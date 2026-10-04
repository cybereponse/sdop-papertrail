"""
Liens nominatifs et second facteur — accès sans compte (EX-3).

Certains destinataires n'auront pas de compte : victimes en réponse à incident,
tiers ponctuels. Ils reçoivent un lien **nominatif**, servi par un vhost séparé
sans mTLS. C'est une exception assumée à la doctrine « mTLS sur tous les
vhosts », strictement bornée :

- `TLP:RED` n'est **jamais** accessible par lien — il exige un compte ;
- un lien seul ne suffit jamais : il faut un second facteur.

Deux modes de second facteur
-----------------------------
**Mode A — correspondant récurrent.** TOTP enrôlé une fois par personne, pas par
document. Ensuite chaque diffusion est automatique.

**Mode B — réponse à incident.** Une victime en crise ne peut pas enrôler une
application d'authentification avant de lire le rapport qui doit l'aider.
L'analyste dicte un code au téléphone pendant l'appel de prise en charge.

Le mode B n'est pas un repli dégradé : en réponse à incident, la boîte mail de la
victime est souvent compromise. Le lien seul serait alors lu par l'attaquant ;
c'est le code hors bande qui l'arrête.

Ce que le mode B n'atteint pas
-------------------------------
Son attribution repose sur le fait que l'analyste a appelé la bonne personne.
C'est plus faible qu'un TOTP lié à un appareil. Les deux modes ne se valent pas,
et la documentation le dit plutôt que de les présenter comme équivalents.
"""
import base64
import hashlib
import hmac
import os
import re
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import db
import sealing

#: Alphabet sans ambiguïté : ni O/0, ni I/1/l. Un code se dicte au téléphone.
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_LEN = 8                      # 40 bits — voir MAX_ATTEMPTS
MAX_ATTEMPTS = 5

TTL_TOTP_HOURS = int(os.environ.get("SDOP_LINK_TTL_TOTP", "72"))
TTL_CODE_HOURS = int(os.environ.get("SDOP_LINK_TTL_CODE", "96"))
SESSION_MINUTES = int(os.environ.get("SDOP_LINK_SESSION_MINUTES", "2880"))   # 48 h (décision du 2026-10-03)

#: Niveaux jamais diffusables par lien.
TLP_INTERDITS = {"TLP:RED"}


class LinkError(Exception):
    """Émission ou usage de lien refusé — message destiné à l'appelant."""


class AlreadyEnrolled(LinkError):
    """Enrôlement refusé : le correspondant a déjà un second facteur."""


def _hash(valeur: str) -> str:
    return hashlib.sha256(valeur.encode()).hexdigest()


def _now():
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# TOTP (RFC 6238) — implémenté ici pour ne pas ajouter de dépendance
# --------------------------------------------------------------------------

def generate_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def totp_now(secret_b32: str, at: int | None = None, pas: int = 30) -> str:
    cle = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    compteur = int((at if at is not None else time.time()) // pas)
    empreinte = hmac.new(cle, struct.pack("!Q", compteur), hashlib.sha1).digest()
    decalage = empreinte[-1] & 0x0F
    code = struct.unpack("!I", empreinte[decalage:decalage + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


def totp_step(secret_b32: str, code: str, fenetre: int = 1) -> int | None:
    """Pas de temps auquel `code` correspond, ou None.

    Accepte une dérive d'horloge d'un pas de part et d'autre. Rendre le pas, et
    pas seulement « valide », permet de refuser le rejeu d'un code déjà
    consommé (SEC-021) : sans mémoire du dernier pas, un code intercepté reste
    utilisable pendant toute sa fenêtre, sur n'importe quel lien du même
    correspondant.
    """
    code = (code or "").strip()
    maintenant = time.time()
    for ecart in range(-fenetre, fenetre + 1):
        instant = maintenant + ecart * 30
        if hmac.compare_digest(totp_now(secret_b32, instant), code):
            return int(instant // 30)
    return None


def verify_totp(secret_b32: str, code: str, fenetre: int = 1) -> bool:
    return totp_step(secret_b32, code, fenetre) is not None


# --------------------------------------------------------------------------
# Secrets TOTP au repos (SEC-025)
# --------------------------------------------------------------------------
#
# Un secret TOTP en clair dans SQLite se lit dans n'importe quelle copie de la
# base. Il est chiffré (AES-256-GCM) avec une clé DÉRIVÉE de la clé de service
# des documents : il hérite exactement de leur protection — une copie du
# volume documentaire sans la clé ne livre ni les PDF ni les facteurs. Les
# données associées lient le chiffré à SON correspondant : déplacer la valeur
# d'une ligne à une autre la rend illisible.
#
# Limite, la même que pour les documents : qui détient la clé de service (une
# sauvegarde COMPLÈTE de la VM, .env compris) déchiffre aussi les secrets. Ce
# n'est pas un chiffrement contre la sauvegarde, c'est un chiffrement contre la
# copie de la base seule.

_PREFIXE_CHIFFRE = "enc1:"


def _cle_totp() -> bytes | None:
    if not sealing.AT_REST_ENABLED:
        return None
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"sdop-totp-secret-v1").derive(sealing._service_key())


def _sceller_secret(sujet: str, secret: str) -> str:
    cle = _cle_totp()
    if cle is None:
        return secret
    nonce = os.urandom(12)
    chiffre = AESGCM(cle).encrypt(nonce, secret.encode(), sujet.encode())
    return _PREFIXE_CHIFFRE + base64.b64encode(nonce + chiffre).decode()


def _ouvrir_secret(sujet: str, stocke: str | None) -> str | None:
    if not stocke or not stocke.startswith(_PREFIXE_CHIFFRE):
        return stocke                     # en clair : base d'avant SEC-025
    cle = _cle_totp()
    if cle is None:
        raise sealing.SealingError(
            "secret TOTP chiffré mais SDOP_CONTENT_KEY absente")
    brut = base64.b64decode(stocke[len(_PREFIXE_CHIFFRE):])
    try:
        return AESGCM(cle).decrypt(brut[:12], brut[12:], sujet.encode()).decode()
    except Exception as exc:              # InvalidTag : clé changée ou ligne déplacée
        raise sealing.SealingError(f"secret TOTP de {sujet} illisible") from exc


def encrypt_plaintext_secrets() -> int:
    """Chiffre les secrets encore en clair. Idempotent ; appelé au démarrage."""
    if _cle_totp() is None:
        return 0
    with db.transaction() as cx:
        lignes = cx.execute(
            "SELECT subject, totp_secret FROM correspondents"
            " WHERE totp_secret IS NOT NULL AND totp_secret NOT LIKE ?",
            (_PREFIXE_CHIFFRE + "%",)).fetchall()
        for ligne in lignes:
            cx.execute("UPDATE correspondents SET totp_secret=? WHERE subject=?",
                       (_sceller_secret(ligne["subject"], ligne["totp_secret"]),
                        ligne["subject"]))
    return len(lignes)


# --------------------------------------------------------------------------
# Sujets
# --------------------------------------------------------------------------

#: Longueur maximale d'une adresse (RFC 5321) — borne aussi l'entrée de journal.
MAX_SUBJECT_LEN = 254
_ADRESSE_RE = re.compile(r"\A[^@\s]+@[^@\s]+\Z")


def normalize_subject(subject: str | None) -> str:
    return (subject or "").strip().lower()


def require_address(subject: str) -> str:
    """Un lien ou un enrôlement ne vise qu'une ADRESSE, jamais un compte.

    Les comptes du socle et les correspondants sont deux espaces d'identité
    distincts. Un lien adressé à un nom de compte ferait porter au détenteur du
    lien l'identité — et les destinataires — de ce compte (SEC-018).
    """
    sujet = normalize_subject(subject)
    if not sujet:
        raise LinkError("destinataire requis")
    if len(sujet) > MAX_SUBJECT_LEN or not _ADRESSE_RE.match(sujet):
        raise LinkError("le destinataire d'un lien doit être une adresse "
                        "électronique — un compte du socle consulte par son compte")
    return sujet


# --------------------------------------------------------------------------
# Correspondants
# --------------------------------------------------------------------------

def enroll(subject: str, created_by: str) -> str:
    """Enrôle un correspondant en TOTP et renvoie son secret, une seule fois.

    Un correspondant DÉJÀ enrôlé est refusé : remplacer son secret ici, sans
    autre droit que celui de publier, permettait à tout émetteur de prendre le
    second facteur de n'importe quel correspondant (SEC-019). La
    réinitialisation est une opération distincte (`reset_enrollment`).
    """
    sujet = require_address(subject)
    secret = generate_totp_secret()
    maintenant = _now().isoformat()
    cur = db.connect().execute(
        "INSERT INTO correspondents (subject, totp_secret, enrolled_at,"
        " created_by, created_at) VALUES (?,?,?,?,?)"
        " ON CONFLICT(subject) DO UPDATE SET totp_secret=excluded.totp_secret,"
        " enrolled_at=excluded.enrolled_at, totp_last_step=NULL"
        " WHERE correspondents.totp_secret IS NULL",
        (sujet, _sceller_secret(sujet, secret), maintenant, created_by, maintenant))
    if cur.rowcount != 1:
        raise AlreadyEnrolled(
            f"{sujet} est déjà enrôlé — la réinitialisation de son second "
            "facteur est réservée aux administrateurs")
    return secret


def reset_enrollment(subject: str) -> dict:
    """Remplace le secret d'un correspondant déjà enrôlé. Administrateurs seuls.

    Un facteur réinitialisé est un facteur dont on ne sait plus qui le détient :
    toutes les sessions et tous les liens encore actifs de ce correspondant
    sont coupés dans la même transaction. Les diffusions à maintenir sont à
    réémettre.
    """
    sujet = require_address(subject)
    with db.transaction() as cx:
        avant = cx.execute("SELECT * FROM correspondents WHERE subject=?",
                           (sujet,)).fetchone()
        if avant is None or not avant["totp_secret"]:
            raise LinkError(f"{sujet} n'est pas enrôlé")
        secret = generate_totp_secret()
        cx.execute("UPDATE correspondents SET totp_secret=?, enrolled_at=?,"
                   " totp_last_step=NULL WHERE subject=?",
                   (_sceller_secret(sujet, secret), _now().isoformat(), sujet))
        coupees = revoke_all_for(sujet)
    return {"subject": sujet, "totp_secret": secret,
            "enrolled_by": avant["created_by"], "sessions_coupees": coupees}


#: Libellé affiché dans l'application d'authentification du correspondant.
EMETTEUR_TOTP = "SDOP cybeRéponse"


def otpauth_uri(subject: str, secret: str) -> str:
    """URI `otpauth://` (format Key Uri) lue par les applications TOTP."""
    from urllib.parse import quote
    # Deux-points LITTÉRAL entre émetteur et compte : la forme encodée (%3A)
    # est permise par le format, mais toutes les applications ne la séparent
    # pas (pyotp, constaté au test de bout en bout du 2026-10-04).
    libelle = f"{quote(EMETTEUR_TOTP)}:{quote(normalize_subject(subject))}"
    return (f"otpauth://totp/{libelle}?secret={secret}"
            f"&issuer={quote(EMETTEUR_TOTP)}&algorithm=SHA1&digits=6&period=30")


def correspondent(subject: str) -> dict | None:
    """Correspondant, secret TOTP DÉCHIFFRÉ — ne jamais journaliser le résultat."""
    row = db.connect().execute(
        "SELECT * FROM correspondents WHERE subject=?",
        (normalize_subject(subject),)).fetchone()
    if row is None:
        return None
    corr = dict(row)
    corr["totp_secret"] = _ouvrir_secret(corr["subject"], corr["totp_secret"])
    return corr


# --------------------------------------------------------------------------
# Émission
# --------------------------------------------------------------------------

def issue(doc, subject: str, issued_by: str, mode: str = "code",
          ttl_hours: int | None = None) -> dict:
    """Émet un lien nominatif. Renvoie le jeton et, en mode `code`, le code.

    Le code n'est renvoyé qu'ICI, une seule fois, pour être affiché à l'émetteur
    qui le dictera. Il n'est jamais stocké en clair ni envoyé par courriel : le
    faire partir par le canal du lien supprimerait le second facteur.
    """
    sujet = require_address(subject)
    if doc["tlp"] in TLP_INTERDITS:
        raise LinkError(f"{doc['tlp']} n'est jamais accessible par lien — "
                        "un compte est exigé")
    if mode not in ("code", "totp"):
        raise LinkError("mode inconnu")
    if mode == "totp" and not correspondent(sujet):
        raise LinkError(f"{sujet} n'est pas enrôlé en TOTP — "
                        "utiliser le mode code, ou l'enrôler d'abord")

    defaut = TTL_TOTP_HOURS if mode == "totp" else TTL_CODE_HOURS
    heures = min(ttl_hours or defaut, defaut)

    jeton = secrets.token_urlsafe(32)
    code = "".join(secrets.choice(ALPHABET) for _ in range(CODE_LEN)) \
        if mode == "code" else None

    db.connect().execute(
        "INSERT INTO links (token_hash, doc_id, subject, mode, code_hash,"
        " expires_at, issued_by, issued_at) VALUES (?,?,?,?,?,?,?,?)",
        (_hash(jeton), doc["doc_id"], sujet, mode,
         _hash(code) if code else None,
         (_now() + timedelta(hours=heures)).isoformat(), issued_by,
         _now().isoformat()))
    return {"token": jeton, "code": code, "mode": mode,
            "expires_in_hours": heures, "subject": sujet}


def get(token: str) -> dict | None:
    row = db.connect().execute(
        "SELECT * FROM links WHERE token_hash=?", (_hash(token),)).fetchone()
    return dict(row) if row else None


def revoke(token_hash: str, actor: str) -> None:
    with db.transaction() as cx:
        cx.execute("UPDATE links SET state='revoque' WHERE token_hash=?", (token_hash,))
        cx.execute("UPDATE link_sessions SET revoked=1 WHERE token_hash=?", (token_hash,))


def close_session(session_token: str) -> None:
    """Révoque UNE session de lien, à la demande de son porteur."""
    db.connect().execute("UPDATE link_sessions SET revoked=1 WHERE session_hash=?",
                         (_hash(session_token or ""),))


def revoke_for_document(doc_id: str, subject: str) -> int:
    """Coupe les liens et sessions d'un correspondant sur CE document seulement.

    Le droit de révoquer découle d'un droit sur le document (son émetteur) : il
    ne peut pas porter au-delà. Couper ce correspondant partout, documents
    d'autres émetteurs compris, est `revoke_all_for`, réservé aux
    administrateurs (SEC-022).
    """
    sujet = normalize_subject(subject)
    with db.transaction() as cx:
        cur = cx.execute(
            "UPDATE link_sessions SET revoked=1"
            " WHERE doc_id=? AND subject=? AND revoked=0", (doc_id, sujet))
        cx.execute(
            "UPDATE links SET state='revoque' WHERE doc_id=? AND subject=?"
            " AND state IN ('actif','utilise')", (doc_id, sujet))
    return cur.rowcount


def revoke_all_for(subject: str) -> int:
    """Coupe tous les accès d'un correspondant — kill switch par personne."""
    sujet = normalize_subject(subject)
    with db.transaction() as cx:
        cur = cx.execute(
            "UPDATE link_sessions SET revoked=1 WHERE subject=? AND revoked=0",
            (sujet,))
        cx.execute(
            "UPDATE links SET state='revoque' WHERE subject=?"
            " AND state IN ('actif','utilise')", (sujet,))
    return cur.rowcount


# --------------------------------------------------------------------------
# Consommation
# --------------------------------------------------------------------------

_MOTIFS_ETAT = {"utilise": "lien déjà utilisé",
                "verrouille": "lien verrouillé après trop d'essais",
                "revoque": "lien révoqué"}


def redeem(token: str, facteur: str, on_open=None) -> dict:
    """Valide lien + second facteur, ouvre une session. Lève LinkError sinon.

    Le verrouillage porte sur le LIEN, pas sur l'adresse IP : verrouiller l'IP
    se contourne en changeant de réseau, verrouiller le lien ferme la porte.

    Tout se joue dans UNE transaction à verrou d'écriture (SEC-021) : lecture
    de l'état, contrôle, compteur d'essais, consommation et création de la
    session. Deux requêtes concurrentes sur le même lien sont sérialisées — la
    seconde voit le lien déjà consommé, ou le compteur déjà incrémenté.

    `on_open(ouverture)` est appelé avant la validation de la transaction : s'il
    lève (journal indisponible), rien n'est consommé et aucune session n'existe.
    Un essai manqué, lui, est TOUJOURS compté, même si l'appelant échoue
    ensuite : c'est la borne contre la force brute.
    """
    if db.connect().in_transaction:
        raise RuntimeError("redeem() gère sa propre transaction")
    echec = None
    with db.transaction() as cx:
        row = cx.execute("SELECT * FROM links WHERE token_hash=?",
                         (_hash(token or ""),)).fetchone()
        if row is None:
            raise LinkError("lien inconnu")
        lien = dict(row)
        if lien["state"] != "actif":
            raise LinkError(_MOTIFS_ETAT.get(lien["state"], "lien inutilisable"))
        if _now() >= datetime.fromisoformat(lien["expires_at"]):
            raise LinkError("lien expiré")

        pas = None
        rejeu = False
        if lien["mode"] == "code":
            valide = bool(lien["code_hash"]) and hmac.compare_digest(
                lien["code_hash"], _hash((facteur or "").strip().upper()))
        else:
            corr = cx.execute("SELECT * FROM correspondents WHERE subject=?",
                              (lien["subject"],)).fetchone()
            secret = _ouvrir_secret(corr["subject"], corr["totp_secret"]) \
                if corr else None
            pas = totp_step(secret, facteur) if secret else None
            valide = pas is not None
            rejeu = valide and corr["totp_last_step"] is not None \
                and pas <= corr["totp_last_step"]
            if rejeu:
                # Code juste, mais déjà présenté : rejeu. Compté comme un essai.
                valide = False

        if not valide:
            essais = lien["attempts"] + 1
            etat = "verrouille" if essais >= MAX_ATTEMPTS else "actif"
            cx.execute("UPDATE links SET attempts=?, state=? WHERE token_hash=?"
                       " AND state='actif'", (essais, etat, lien["token_hash"]))
            if etat == "verrouille":
                echec = LinkError("verrouillé après trop d'essais")
            elif rejeu:
                echec = LinkError("code déjà utilisé — attendez le code suivant de "
                                  f"l'application ({MAX_ATTEMPTS - essais} essai(s) restant(s))")
            else:
                echec = LinkError(f"second facteur invalide ({MAX_ATTEMPTS - essais} "
                                  "essai(s) restant(s))")
        else:
            cur = cx.execute(
                "UPDATE links SET state='utilise', used_at=? WHERE token_hash=?"
                " AND state='actif'", (_now().isoformat(), lien["token_hash"]))
            if cur.rowcount != 1:
                raise LinkError("lien déjà utilisé")
            if pas is not None:
                cx.execute("UPDATE correspondents SET totp_last_step=?"
                           " WHERE subject=?", (pas, lien["subject"]))
            session = secrets.token_urlsafe(32)
            cx.execute(
                "INSERT INTO link_sessions (session_hash, token_hash, doc_id, subject,"
                " expires_at, created_at) VALUES (?,?,?,?,?,?)",
                (_hash(session), lien["token_hash"], lien["doc_id"], lien["subject"],
                 (_now() + timedelta(minutes=SESSION_MINUTES)).isoformat(),
                 _now().isoformat()))
            ouverture = {"session": session, "doc_id": lien["doc_id"],
                         "subject": lien["subject"], "mode": lien["mode"]}
            if on_open is not None:
                on_open(ouverture)
    if echec is not None:
        raise echec
    return ouverture


def session(session_token: str) -> dict | None:
    """Session valide, ou None. Révocation et expiration vérifiées ici.

    L'état du lien parent est relu aussi : une session ne survit pas à la
    révocation de son lien, quel que soit l'ordre des écritures (SEC-021).
    """
    row = db.connect().execute(
        "SELECT s.*, l.state AS link_state FROM link_sessions s"
        " JOIN links l ON l.token_hash = s.token_hash"
        " WHERE s.session_hash=?",
        (_hash(session_token or ""),)).fetchone()
    if row is None:
        return None
    s = dict(row)
    if s["revoked"] or s["link_state"] == "revoque" \
            or _now() >= datetime.fromisoformat(s["expires_at"]):
        return None
    return s
