"""
Stockage documentaire SDOP — Lot 2.

Un document = deux fichiers dans SDOP_DOC_DIR :
  <doc_id>.pdf    les octets source, tels que déposés
  <doc_id>.json   métadonnées (tlp, version_hash, émetteur, horodatage)

Pas de base de données : à ~10 documents/jour, un sidecar JSON suffit et garde
le système auditable à la main (`cat`). PostgreSQL n'arrive qu'avec la couche
commentaires/visa (ARCHITECTURE.md).

`doc_id` est un UUID4 hexadécimal **opaque** : ni le nom du fichier d'origine,
ni aucun chemin n'est jamais exposé ni accepté côté client (§6.1). Tout doc_id
reçu est validé contre DOC_ID_RE avant de toucher au système de fichiers — un
doc_id ne peut donc jamais contenir de séparateur de chemin.
"""
import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone

import db
import sealing

DOC_DIR = os.environ.get("SDOP_DOC_DIR", "/documents")

# Taille maximale d'un dépôt (défense en profondeur : Flask refuse déjà au-delà
# de MAX_CONTENT_LENGTH, ceci couvre les appels directs au module).
MAX_BYTES = int(os.environ.get("SDOP_MAX_DOC_BYTES", str(64 * 1024 * 1024)))

# Longueur maximale du nom d'origine conservé. Ce n'est PAS une préférence
# d'affichage : ce nom part dans une entrée de ledger, et `ledger._last_hash()`
# ne relit que les 4096 derniers octets du segment. Une entrée plus longue que
# cette fenêtre rend tout ajout ultérieur impossible — donc, la journalisation
# étant fail-closed, rend le service entier indisponible (503). Un émetteur
# habilité pourrait déclencher ce déni de service d'un simple nom de fichier
# long. La borne ferme ce vecteur ici ; le défaut du ledger lui-même est
# SEC-006 et se corrige dans ledger/, pas dans ce module.
MAX_NAME_LEN = 180

DOC_ID_RE = re.compile(r"\A[0-9a-f]{32}\Z")

#: Durée de visibilité par défaut (exigence EX-5).
DEFAULT_TTL_DAYS = int(os.environ.get("SDOP_DOC_TTL_DAYS", "45"))
MAX_TTL_DAYS = int(os.environ.get("SDOP_DOC_MAX_TTL_DAYS", "365"))

PDF_MAGIC = b"%PDF-"


class RejectedDocument(Exception):
    """Dépôt refusé (format, taille) — message destiné à l'émetteur."""


class SealedDocument(Exception):
    """Document scellé : plus aucun accès par le service (EX-5, EX-7)."""


class CorruptedDocument(Exception):
    """Les octets relus ne correspondent plus à l'empreinte de publication.

    Ce n'est pas une erreur de lecture : c'est la preuve que le contenu servi ne
    serait pas celui qui a été journalisé au dépôt. L'appelant doit refuser de
    servir et journaliser l'incohérence (SEC-015).
    """


def new_doc_id() -> str:
    return uuid.uuid4().hex


def is_doc_id(value: str) -> bool:
    return bool(value) and bool(DOC_ID_RE.match(value))


def _paths(doc_id: str, doc_dir: str = None) -> tuple[str, str]:
    if not is_doc_id(doc_id):
        raise ValueError("doc_id invalide")
    base = os.path.join(doc_dir or DOC_DIR, doc_id)
    return base + ".pdf", base + ".json"


def validate(pdf_bytes: bytes) -> None:
    """Contrôles de forme d'un dépôt, sans rien écrire. Lève RejectedDocument.

    Séparé de `put()` pour que l'appelant puisse refuser un document AVANT de
    le rendre persistant : un refus ne doit laisser aucune trace consultable
    (SEC-017).
    """
    if not pdf_bytes:
        raise RejectedDocument("fichier vide")
    if len(pdf_bytes) > MAX_BYTES:
        raise RejectedDocument(f"fichier trop volumineux (> {MAX_BYTES} octets)")
    if not pdf_bytes.startswith(PDF_MAGIC):
        raise RejectedDocument("seuls les PDF sont acceptés (en-tête %PDF- absent)")


def discard_files(doc_id: str, doc_dir: str = None) -> None:
    """Retire les fichiers d'un dépôt dont l'enregistrement a été annulé.

    Indispensable : `get_meta()` réimporte un sidecar orphelin. Laisser le
    fichier après l'annulation de la transaction ressusciterait le document à
    la première lecture (SEC-017, SEC-024).
    """
    for chemin in _paths(doc_id, doc_dir):
        for c in (chemin, chemin + ".tmp"):
            try:
                os.remove(c)
            except FileNotFoundError:
                pass


def put(pdf_bytes: bytes, *, tlp: str, original_name: str, actor: str,
        recipients: list[tuple[str, str]] | None = None,
        ttl_days: int | None = None, doc_dir: str = None) -> dict:
    """Ingère un PDF, renvoie ses métadonnées (dont le doc_id attribué).

    `recipients` est une liste de couples (sujet, nature) — nature valant
    `compte` ou `adresse`. Un document sans destinataire n'est lisible par
    personne d'autre que son émetteur : c'est volontaire, la diffusion est un
    geste explicite.
    """
    validate(pdf_bytes)

    directory = doc_dir or DOC_DIR
    os.makedirs(directory, exist_ok=True)
    doc_id = new_doc_id()
    pdf_path, meta_path = _paths(doc_id, directory)

    jours = DEFAULT_TTL_DAYS if ttl_days is None else min(ttl_days, MAX_TTL_DAYS)
    maintenant = datetime.now(timezone.utc)
    meta = {
        "doc_id": doc_id,
        "tlp": tlp,
        # Nom d'origine conservé pour l'affichage seulement : il ne sert JAMAIS
        # à construire un chemin (le chemin dérive du doc_id). Tronqué : voir
        # MAX_NAME_LEN.
        "original_name": os.path.basename(
            original_name or "document.pdf")[:MAX_NAME_LEN],
        "version_hash": hashlib.sha256(pdf_bytes).hexdigest(),
        "bytes": len(pdf_bytes),
        "published_by": actor,
        "published_at": maintenant.isoformat(),
        "expires_at": (maintenant + timedelta(days=jours)).isoformat(),
        "state": "actif",
    }

    # Publication atomique : les deux fichiers sont écrits à côté puis
    # renommés. Sans cela, une coupure entre les deux écritures laisse un PDF
    # sans métadonnées — donc un document que get_bytes() ne peut plus
    # authentifier, et qui bloquerait sa propre lecture (SEC-015).
    # L'empreinte est calculée sur le CLAIR (meta ci-dessus) : c'est lui qui
    # sera rendu, et c'est lui que le ledger atteste. Le chiffrement au repos
    # n'intervient qu'au moment d'écrire sur le disque.
    try:
        _ecrire_atomique(pdf_path, sealing.encrypt_at_rest(pdf_bytes))
        _ecrire_atomique(meta_path, json.dumps(
            meta, ensure_ascii=False, indent=2, sort_keys=True).encode())

        cx = db.connect()
        cx.execute(
            "INSERT INTO documents (doc_id, tlp, original_name, version_hash, bytes,"
            " published_by, published_at, expires_at, state)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (meta["doc_id"], meta["tlp"], meta["original_name"],
             meta["version_hash"], meta["bytes"], meta["published_by"],
             meta["published_at"], meta["expires_at"], meta["state"]))
        for sujet, nature in (recipients or []):
            cx.execute(
                "INSERT OR IGNORE INTO recipients (doc_id, subject, kind, added_by,"
                " added_at) VALUES (?,?,?,?,?)",
                (doc_id, sujet.strip().lower(), nature, actor, meta["published_at"]))
    except BaseException:
        # Fichiers écrits mais enregistrement échoué : sans ce retrait, le
        # sidecar orphelin serait réimporté par get_meta() (SEC-017).
        discard_files(doc_id, directory)
        raise
    return meta


def recipients_of(doc_id: str) -> list[dict]:
    rows = db.connect().execute(
        "SELECT subject, kind, added_by, added_at FROM recipients"
        " WHERE doc_id=? ORDER BY subject", (doc_id,)).fetchall()
    return [dict(r) for r in rows]


def set_recipients(doc_id: str, recipients: list[tuple[str, str]], actor: str) -> None:
    cx = db.connect()
    quand = datetime.now(timezone.utc).isoformat()
    cx.execute("DELETE FROM recipients WHERE doc_id=?", (doc_id,))
    for sujet, nature in recipients:
        cx.execute(
            "INSERT OR IGNORE INTO recipients (doc_id, subject, kind, added_by,"
            " added_at) VALUES (?,?,?,?,?)",
            (doc_id, sujet.strip().lower(), nature, actor, quand))


def is_expired(meta: dict, now=None) -> bool:
    """Échéance dépassée, indépendamment du balayage.

    L'état en base est posé par le balayage périodique ; la date, elle, fait foi
    tout de suite. Sans cette comparaison, un document resterait lisible entre
    son échéance et le passage suivant du balayage.
    """
    echeance = meta.get("expires_at")
    if not echeance:
        return False
    return (now or datetime.now(timezone.utc)) >= datetime.fromisoformat(echeance)


def expired_documents() -> list[dict]:
    """Documents échus non encore scellés — candidats au scellement.

    « retire » inclus : un document retiré (accès coupé) finit lui aussi scellé
    à son échéance, ou tout de suite par « sceller maintenant ».
    """
    maintenant = datetime.now(timezone.utc).isoformat()
    rows = db.connect().execute(
        "SELECT * FROM documents WHERE state IN ('actif','retire') AND expires_at <= ?"
        " ORDER BY expires_at", (maintenant,)).fetchall()
    return [dict(r) for r in rows]


def expiring_soon(days: int = 7) -> list[dict]:
    """Documents dont l'échéance approche — pour l'alerte à l'émetteur (J-7)."""
    maintenant = datetime.now(timezone.utc)
    limite = (maintenant + timedelta(days=days)).isoformat()
    rows = db.connect().execute(
        "SELECT * FROM documents WHERE state='actif' AND expires_at > ?"
        " AND expires_at <= ? ORDER BY expires_at",
        (maintenant.isoformat(), limite)).fetchall()
    return [dict(r) for r in rows]


def set_state(doc_id: str, state: str) -> None:
    db.connect().execute("UPDATE documents SET state=? WHERE doc_id=?",
                         (state, doc_id))


def extend(doc_id: str, jours: int) -> str:
    """Repousse l'échéance. Refuse au-delà du plafond, et après coup.

    Prolonger un document déjà échu reviendrait à ressusciter un accès que les
    destinataires ont vu disparaître — la prolongation se décide avant (EX-5).
    """
    meta = get_meta(doc_id)
    if meta is None:
        raise RejectedDocument("document inconnu")
    if meta.get("state") != "actif" or is_expired(meta):
        raise RejectedDocument("document déjà échu : prolongation impossible")
    base = datetime.fromisoformat(meta["published_at"])
    nouvelle = datetime.fromisoformat(meta["expires_at"]) + timedelta(days=jours)
    plafond = base + timedelta(days=MAX_TTL_DAYS)
    if nouvelle > plafond:
        raise RejectedDocument(
            f"au-delà du plafond de {MAX_TTL_DAYS} jours après publication")
    db.connect().execute("UPDATE documents SET expires_at=? WHERE doc_id=?",
                         (nouvelle.isoformat(), doc_id))
    return nouvelle.isoformat()


def expire_now(doc_id: str) -> str:
    """Avance l'échéance à l'instant présent (« sceller maintenant »).

    Le document devient invisible pour tous immédiatement (is_expired fait foi
    sans attendre le balayage), puis le balayage suivant le scelle : la route
    HTTP ne détruit rien elle-même, le scellement reste une tâche serveur.
    """
    meta = get_meta(doc_id)
    if meta is None:
        raise RejectedDocument("document inconnu")
    if meta.get("state") not in ("actif", "retire"):
        raise RejectedDocument(f"document déjà {meta.get('state')}")
    maintenant = datetime.now(timezone.utc).isoformat()
    db.connect().execute("UPDATE documents SET expires_at=? WHERE doc_id=?",
                         (maintenant, doc_id))
    return maintenant


def seal_document(doc_id: str, pub_a, pub_b, doc_dir: str = None) -> dict:
    """Scelle les octets sur disque et marque le document. Irréversible ici.

    Le service perd tout moyen de rouvrir : c'est l'objet même du scellement.
    Seule la réunion des deux clés privées, hors ligne, y parvient.
    """
    pdf_path, _ = _paths(doc_id, doc_dir)
    with open(pdf_path, "rb") as f:
        brut = f.read()
    if sealing.is_sealed(brut):
        raise RejectedDocument("document déjà scellé")
    clair = sealing.decrypt_at_rest(brut)
    _ecrire_atomique(pdf_path, sealing.seal(clair, pub_a, pub_b))
    set_state(doc_id, "scelle")
    return {"doc_id": doc_id, "bytes": len(clair),
            "sha256": hashlib.sha256(clair).hexdigest()}


def containment_enabled() -> bool:
    """Confinement : plus aucun document n'est servi, à personne.

    Le dernier cran du kill switch (EX-4). Il ne supprime rien et ne scelle
    rien : il coupe la diffusion, le temps de comprendre. La publication reste
    possible — on peut avoir besoin de déposer des éléments pendant un incident
    sans vouloir qu'ils sortent.
    """
    row = db.connect().execute(
        "SELECT value FROM settings WHERE key='containment'").fetchone()
    return bool(row and row["value"] == "1")


def set_containment(actif: bool, actor: str) -> None:
    db.connect().execute(
        "INSERT INTO settings (key, value, changed_by, changed_at)"
        " VALUES ('containment',?,?,?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value,"
        " changed_by=excluded.changed_by, changed_at=excluded.changed_at",
        ("1" if actif else "0", actor, datetime.now(timezone.utc).isoformat()))


def is_recipient(doc_id: str, subject: str, kind: str | None = None) -> bool:
    requete = "SELECT 1 FROM recipients WHERE doc_id=? AND subject=?"
    params = [doc_id, (subject or "").strip().lower()]
    if kind is not None:
        requete += " AND kind=?"
        params.append(kind)
    return db.connect().execute(requete, params).fetchone() is not None


def _ecrire_atomique(chemin: str, contenu: bytes) -> None:
    tmp = f"{chemin}.tmp"
    with open(tmp, "wb") as f:
        f.write(contenu)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, chemin)


def get_meta(doc_id: str, doc_dir: str = None) -> dict | None:
    """Métadonnées du document. Base d'abord, sidecar en repli.

    Le repli existe pour les documents déposés avant l'arrivée de la base : ils
    sont réimportés à la première lecture plutôt que d'exiger une migration
    manuelle. Un dépôt n'est jamais perdu parce que le format a changé.
    """
    if not is_doc_id(doc_id):
        return None
    row = db.connect().execute(
        "SELECT * FROM documents WHERE doc_id=?", (doc_id,)).fetchone()
    if row is not None:
        return dict(row)

    _, meta_path = _paths(doc_id, doc_dir)
    if not os.path.exists(meta_path):
        return None
    with open(meta_path) as f:
        meta = json.load(f)
    return _importer_sidecar(meta)


def _importer_sidecar(meta: dict) -> dict:
    """Reprend un document d'avant la base, avec une échéance par défaut."""
    meta.setdefault("state", "actif")
    if "expires_at" not in meta:
        depot = datetime.fromisoformat(meta["published_at"])
        meta["expires_at"] = (depot + timedelta(days=DEFAULT_TTL_DAYS)).isoformat()
    db.connect().execute(
        "INSERT OR IGNORE INTO documents (doc_id, tlp, original_name,"
        " version_hash, bytes, published_by, published_at, expires_at, state)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (meta["doc_id"], meta["tlp"], meta["original_name"],
         meta["version_hash"], meta["bytes"], meta["published_by"],
         meta["published_at"], meta["expires_at"], meta["state"]))
    return meta


def reference_hash(doc_id: str) -> str | None:
    """Empreinte de publication, lue au LEDGER — pas dans la base.

    L'audit demande que la référence de comparaison soit protégée
    indépendamment de ce qu'elle vérifie (SEC-015). La base est modifiable comme
    le fichier qu'elle décrit : un acteur qui remplace l'un peut corriger
    l'autre. Le ledger, lui, est chaîné et ancré par un digest signé — une
    réécriture s'y voit. C'est donc lui qui fait foi.
    """
    import ledger
    chemin = ledger._segment_path(ledger.LEDGER_DIR)
    if not os.path.exists(chemin):
        return None
    try:
        for entree in ledger.read(chemin):
            if (entree.get("event") == "document_publish"
                    and entree.get("doc_id") == doc_id):
                return entree.get("version_hash")
    except ledger.LedgerError:
        return None
    return None


def get_bytes(doc_id: str, doc_dir: str = None, *, verify: bool = True) -> bytes | None:
    """Octets du document, vérifiés contre l'empreinte de publication.

    Le hash était calculé une fois au dépôt, puis plus jamais : les octets
    étaient relus et servis tels quels, pendant que le journal continuait
    d'annoncer l'empreinte historique du sidecar. Une corruption, une
    restauration désynchronisée ou un remplacement du fichier passait donc
    inaperçue, et le journal attestait une version qui n'était pas celle qui
    avait été servie (SEC-015).

    `verify=False` n'existe que pour les opérations qui doivent lire un document
    dont on sait déjà l'empreinte fausse — une investigation, par exemple.
    """
    if not is_doc_id(doc_id):
        return None
    pdf_path, _ = _paths(doc_id, doc_dir)
    if not os.path.exists(pdf_path):
        return None
    with open(pdf_path, "rb") as f:
        brut = f.read()

    if sealing.is_sealed(brut):
        # Document scellé : il faut les deux clés des détenteurs, qui ne sont
        # pas sur cette machine. Le refus est définitif côté service.
        raise SealedDocument(f"{doc_id} : document scellé")
    try:
        data = sealing.decrypt_at_rest(brut)
    except sealing.SealingError as exc:
        raise CorruptedDocument(f"{doc_id} : {exc}") from exc

    if not verify:
        return data

    meta = get_meta(doc_id, doc_dir)
    if meta is None:
        # Octets sans métadonnées : on ne sait pas ce qu'on tient.
        raise CorruptedDocument(f"{doc_id} : métadonnées absentes")
    # Référence au ledger en priorité : il est chaîné et ancré, la base ne
    # l'est pas (SEC-015).
    attendu = reference_hash(doc_id) or meta.get("version_hash")
    obtenu = hashlib.sha256(data).hexdigest()
    if attendu != obtenu:
        raise CorruptedDocument(
            f"{doc_id} : empreinte attendue {attendu[:12]}, "
            f"octets relus {obtenu[:12]}")
    return data


def list_docs(doc_dir: str = None) -> list[dict]:
    """Documents connus de la base, du plus récent au plus ancien.

    Les sidecars antérieurs à la base sont réimportés au passage, pour qu'un
    document déposé avant la migration ne disparaisse pas des listes.
    """
    directory = doc_dir or DOC_DIR
    if os.path.isdir(directory):
        for name in os.listdir(directory):
            if name.endswith(".json") and is_doc_id(name[: -len(".json")]):
                get_meta(name[: -len(".json")], directory)
    rows = db.connect().execute(
        "SELECT * FROM documents ORDER BY published_at DESC").fetchall()
    return [dict(r) for r in rows]
