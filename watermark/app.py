"""
Service Watermark SDOP — Lot 2 (ARCHITECTURE.md).

Ce service n'est pas un coffre-fort : il **attribue**. Il résout un doc_id
opaque, autorise côté serveur contre les groupes de confiance, journalise au
ledger AVANT de servir, puis diffuse un rendu filigrané nominatif.

Trois propriétés tenues ici, dans cet ordre de priorité :

1. L'identité ne vient jamais du client (`identity.trusted_identity()`).
2. Rien n'est servi qui ne soit journalisé : si le ledger refuse l'écriture,
   la requête échoue (503). Un accès non journalisable est un accès non
   attribuable, donc interdit — c'est la raison d'être du produit.
3. Le client ne reçoit que des pixels : aucune couche texte, aucun PDF source
   (§6.2, décision verrouillée).
"""
import hashlib
import io
import os
import uuid
from urllib.parse import urlsplit

from flask import (Flask, Response, abort, jsonify, make_response, redirect,
                   render_template, request, send_file, url_for)

import authz
import db
import identity
import ledger
import links
import mailer
import manifest
import pades
import qr
import render
import sealing
import siem
import signing
import store

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = store.MAX_BYTES

#: Démo autonome (demo/compose.yml) : l'identité vient d'un faux outpost qui
#: « connecte » tout le monde. Chaque page HTML de l'application doit le dire.
DEMO_MODE = os.environ.get("SDOP_DEMO") == "1"


@app.context_processor
def _mode_demo():
    return {"demo_mode": DEMO_MODE}


# Secrets TOTP restés en clair d'avant SEC-025 : chiffrés au démarrage. Un
# échec n'empêche pas de servir — la lecture sait encore traiter le clair —
# mais il doit se voir.
try:
    _chiffres = links.encrypt_plaintext_secrets()
    if _chiffres:
        app.logger.warning("SEC-025 : %d secret(s) TOTP chiffré(s) au démarrage",
                           _chiffres)
except Exception as _exc:  # noqa: BLE001
    app.logger.error("SEC-025 : chiffrement des secrets TOTP impossible : %s", _exc)


# --------------------------------------------------------------------------
# Journalisation — fail-closed
# --------------------------------------------------------------------------

def journal(**entry) -> str:
    """Écrit au ledger ou fait échouer la requête (503).

    Le ledger est la preuve. Servir un document sans pouvoir inscrire qui l'a
    vu reviendrait à annuler la seule garantie que SDOP apporte réellement.
    """
    try:
        empreinte = ledger.append(entry)
    except ledger.EntryTooLarge as exc:
        # Une entrée trop longue vient d'une saisie (motif, destinataires) : ce
        # n'est pas une panne du journal. L'appelant écrit dans une transaction
        # que cet abort annule — rien n'a donc été modifié (SEC-024).
        app.logger.warning("entrée de journal refusée : %s", exc)
        siem.emit(entry | {"event": "ledger_entry_refused"}, ledger_error=str(exc))
        abort(400, description="saisie trop volumineuse pour le journal — "
                               "rien n'a été modifié")
    except (OSError, ledger.LedgerError) as exc:
        # OSError : disque plein, volume en lecture seule, journal absent.
        # LedgerError : entrée refusée (champ réservé, entrée hors borne) ou
        # segment inexploitable (écriture interrompue). Dans les deux cas le
        # geste n'est pas journalisable, donc il n'a pas lieu.
        app.logger.error("ledger indisponible : %s: %s",
                         type(exc).__name__, exc)
        # La détection doit voir passer CET événement-là, justement parce que la
        # requête est refusée : un ledger en panne est un incident, pas un
        # silence.
        siem.emit(entry | {"event": "ledger_unavailable"},
                  ledger_error=f"{type(exc).__name__}: {exc}")
        abort(503, description="journal indisponible — accès refusé")
    siem.emit(entry, ledger_hash=empreinte)
    return empreinte


#: Borne d'un motif saisi. Validée AVANT toute écriture : un motif hors borne
#: ne doit pas pouvoir faire échouer le journal après coup (SEC-024).
MAX_MOTIF = 1000


def _motif(requis: bool = False) -> str:
    motif = (request.form.get("motif") or "").strip()
    if requis and not motif:
        abort(400, description="motif requis")
    if len(motif) > MAX_MOTIF:
        abort(400, description=f"motif trop long (maximum {MAX_MOTIF} caractères)")
    return motif


# --------------------------------------------------------------------------
# En-têtes de réponse
# --------------------------------------------------------------------------

CSP = (
    "default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)


@app.after_request
def harden(resp: Response) -> Response:
    resp.headers.setdefault("Content-Security-Policy", CSP)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    # Rien n'est conservable par un cache, réponse par réponse : rendus
    # filigranés (horodatage et VIEW id propres à chaque consultation, §6.2),
    # mais aussi pages de diffusion (code + lien = les deux justificatifs),
    # secret d'enrôlement, visionneuse et erreurs (SEC-023). Une règle unique
    # plutôt qu'une liste : une page sensible ajoutée demain est couverte.
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.teardown_request
def fermer_transaction(_exc):
    # Aucune requête ne doit laisser la connexion de son fil en transaction :
    # le worker garderait le verrou d'écriture pour toutes les suivantes.
    if db.rollback_if_open():
        app.logger.error("transaction restée ouverte en fin de requête — annulée")


# --------------------------------------------------------------------------
# Provenance des requêtes qui modifient (SEC-020)
# --------------------------------------------------------------------------

_METHODES_SURES = frozenset({"GET", "HEAD", "OPTIONS"})


def _meme_hote(url: str) -> bool:
    """`url` désigne-t-elle l'hôte qui reçoit la requête ?

    Comparaison sur le NOM d'hôte, port ignoré : nginx transmet `Host: $host`,
    sans port, alors que le navigateur annonce l'origine publique avec son port
    (:8443). Un autre service du même nom sur un autre port n'est pas exclu
    par ce contrôle — il l'est par Sec-Fetch-Site, qui le classe `same-site`.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("https", request.scheme):
        return False
    attendu = urlsplit("//" + request.host).hostname
    return bool(parts.hostname) and parts.hostname == attendu


@app.before_request
def provenance():
    """Refuse une modification demandée depuis une autre origine (SEC-020).

    SameSite=Lax ne sépare pas deux origines HTTPS d'un même site : une
    application voisine sous le même domaine parent, compromise, pouvait faire
    soumettre un formulaire à SDOP par le navigateur d'un analyste connecté.

    Deux signaux du navigateur, que ni une page ni un script ne peuvent forger :
    - `Sec-Fetch-Site` : seul « same-origin » (ou « none », geste direct de
      l'utilisateur) est accepté — « same-site » est précisément le voisin ;
    - `Origin` : s'il désigne un hôte, ce doit être celui-ci.

    ⚠ `Origin: null` n'est PAS un signe d'attaque ici. Nos pages portent
    `Referrer-Policy: no-referrer`, et la spécification Fetch impose alors au
    navigateur d'envoyer `Origin: null` sur un POST, MÊME vers sa propre
    origine. Refuser « null » aurait refusé tous les formulaires de
    l'application. Quand `Sec-Fetch-Site` est présent (Chrome 76+, Firefox 90+,
    Safari 16.4+), c'est lui qui tranche. Sans lui (navigateur ancien), « null »
    n'est toléré que sur la saisie du second facteur d'un lien : une victime
    peut lire son rapport sur un vieux téléphone, et le pire qu'y gagnerait un
    attaquant est d'ouvrir une session avec SES propres justificatifs.

    Une requête sans aucun de ces en-têtes ne vient pas d'un navigateur
    (client en ligne de commande, harnais) : la falsification de requête
    inter-sites passe par un navigateur, qui pose toujours l'un ou l'autre sur
    un POST d'une autre origine.
    """
    if request.method in _METHODES_SURES:
        return None
    site = request.headers.get("Sec-Fetch-Site")
    origine = request.headers.get("Origin")
    motif = None
    if site is not None:
        if site not in ("same-origin", "none"):
            motif = f"Sec-Fetch-Site={site}"
        elif origine not in (None, "null") and not _meme_hote(origine):
            motif = "Origin étrangère"
    elif origine == "null":
        if request.endpoint != "valider_lien":
            motif = "Origin null sans Sec-Fetch-Site"
    elif origine is not None:
        if not _meme_hote(origine):
            motif = "Origin étrangère"
    else:
        referent = request.headers.get("Referer")
        if referent and not _meme_hote(referent):
            motif = "Referer étranger"
    if motif is None:
        return None
    # Pas d'entrée au ledger : rien n'est servi, et la route est publique sur
    # le vhost externe — un tiers pourrait y faire grossir le journal. Le SIEM
    # et les journaux du service voient passer la tentative.
    app.logger.warning("provenance refusée : %s %s (%s)",
                       request.method, request.path, motif)
    siem.emit({"event": "request_origin_refused", "path": request.path,
               "method": request.method, "motif": motif,
               "origin": (origine or "")[:200],
               "ip": (request.headers.get("X-Forwarded-For", "") or "")
               .split(",")[0].strip()})
    abort(403, description="provenance de la requête refusée")


# --------------------------------------------------------------------------
# Santé
# --------------------------------------------------------------------------

@app.get("/health")
def health():
    return jsonify(
        status="ok",
        service="sdop-watermark",
        lot=2,
        trust_mode=identity.TRUST_MODE,
        render_dpi=render.DPI,
        signing_key_id=manifest.KEY_ID,
        # Une clé éphémère signe des manifestes cohérents entre eux, mais qui
        # ne prouvent rien au-delà de la vie du processus. Ça doit se voir.
        signing_key_ephemeral=manifest.EPHEMERAL_KEY,
        # Un chiffrement qu'on croit actif sans qu'il le soit serait pire que
        # pas de chiffrement : la sonde le dit.
        at_rest_encryption=sealing.AT_REST_ENABLED,
        # Secrets TOTP des correspondants chiffrés en base (SEC-025) : même clé
        # de service que les documents, donc même condition.
        totp_secrets_encrypted=sealing.AT_REST_ENABLED,
        doc_ttl_days=store.DEFAULT_TTL_DAYS,
        siem_export=siem.ENABLED,
        containment=store.containment_enabled(),
        # Sceau PAdES des exports (facultatif) : actif, exigé ou non, et jusqu'à
        # quand. Un certificat expiré fait sortir les exports non scellés — ou
        # les suspend si SDOP_PADES_REQUIRED=1 : la date doit se lire avant.
        pades_seal=pades.disponible(),
        pades_required=pades.REQUIRED,
        pades_cert_sha256=pades.cert_sha256(),
        pades_not_after=pades.not_after(),
    )


@app.get("/api/pubkey")
def pubkey():
    """Clé publique de signature des manifestes — publique par nature.

    Un tiers en a besoin pour vérifier hors ligne une preuve d'artefact. La
    donner ici ne suffit pas à lui faire confiance : il doit l'obtenir par un
    canal qu'il juge fiable, et comparer.
    """
    return jsonify(key_id=manifest.KEY_ID, algorithm="Ed25519",
                   public_key=manifest.public_key_b64(),
                   generator=manifest.GENERATOR)


# --------------------------------------------------------------------------
# Publication
# --------------------------------------------------------------------------

@app.get("/")
def index():
    me = identity.trusted_identity()
    readable = authz.readable_levels(me.groups)
    # Double condition : habilité au niveau ET destinataire. La liste ne doit
    # pas révéler l'existence d'un document qu'on n'a pas le droit de lire.
    # L'échéance fait foi sans attendre le balayage : l'état en base peut
    # encore dire « actif » alors que la date est passée.
    docs = [d for d in store.list_docs()
            if d["tlp"] in readable
            and d.get("state", "actif") == "actif"
            and not store.is_expired(d)
            and authz.is_recipient(d, me.user)]
    return render_template(
        "index.html",
        me=me,
        docs=docs,
        publishable=authz.publishable_levels(me.groups),
        readable=readable,
        ttl_defaut=store.DEFAULT_TTL_DAYS,
        mail_actif=mailer.configured(),
        trust_mode=identity.TRUST_MODE,
    )


@app.post("/api/publish")
def publish():
    me = identity.trusted_identity()

    tlp = authz.normalize_tlp(request.form.get("tlp"))
    if tlp is None:
        abort(400, description="niveau TLP inconnu")
    if not authz.can_publish(tlp, me.groups):
        journal(event="publish_denied", actor=me.user, tlp=tlp, ip=me.ip)
        abort(403, description=f"publication {tlp} non autorisée")

    upload = request.files.get("document")
    if upload is None or not upload.filename:
        abort(400, description="aucun fichier transmis")

    destinataires = _lire_destinataires(request.form.get("destinataires", ""))
    ttl = request.form.get("duree_jours", type=int)
    contenu = upload.read()

    # Tous les refus AVANT la moindre écriture (SEC-017) : un PDF mal formé, que
    # le moteur ne sait pas ouvrir, ou dont la rasterisation coûterait plus que
    # ce que le service peut absorber. Un document refusé n'existe nulle part —
    # ni en base, ni sur disque, ni dans l'index de l'émetteur.
    try:
        store.validate(contenu)
        pages = render.check_budget(contenu)["pages"]
    except store.RejectedDocument as exc:
        abort(400, description=str(exc))
    except render.DocumentTooCostly as exc:
        abort(400, description=f"document refusé : {exc}")
    except render.RenderError as exc:
        abort(400, description=f"PDF illisible par le moteur de rendu : {exc}")

    # Dépôt et journal dans la même transaction : si le journal refuse, le
    # document n'est pas publié — base annulée, fichiers retirés (SEC-024).
    meta = None
    try:
        with db.transaction():
            meta = store.put(contenu, tlp=tlp,
                             original_name=upload.filename, actor=me.user,
                             recipients=destinataires, ttl_days=ttl)
            journal(
                event="document_publish", actor=me.user, doc_id=meta["doc_id"],
                tlp=tlp, version_hash=meta["version_hash"], pages=pages,
                original_name=meta["original_name"], ip=me.ip, cert_cn=me.cert_cn,
                expires_at=meta["expires_at"],
                recipients=[s for s, _ in destinataires],
            )
    except store.RejectedDocument as exc:
        abort(400, description=str(exc))
    except BaseException:
        if meta is not None:
            store.discard_files(meta["doc_id"])
        raise

    if _veut_json():
        return jsonify(meta | {"pages": pages}), 201

    # Formulaire : « envoyer un lien à chaque adresse » — publication et diffusion
    # en un geste. Le code de chaque lien n'est affiché qu'ici, une fois.
    adresses = [s for s, kind in destinataires if kind == "adresse"]
    if request.form.get("envoyer_lien") and adresses:
        doc = store.get_meta(meta["doc_id"])
        resultats, erreurs = [], []
        for sujet in adresses:
            try:
                resultats.append(_diffuser(doc, sujet, me, envoyer=True))
            except links.LinkError as exc:
                erreurs.append(f"{sujet} : {exc}")
        return render_template("diffusion.html", me=me, doc=doc, resultats=resultats,
                               erreurs=erreurs, trust_mode=identity.TRUST_MODE)
    return redirect(url_for("viewer", doc_id=meta["doc_id"]), code=303)


def _lire_destinataires(brut: str) -> list[tuple[str, str]]:
    """Analyse la saisie de diffusion : un destinataire par ligne ou par virgule.

    Une entrée contenant « @ » est traitée comme une adresse (donc joignable par
    lien), les autres comme des comptes du socle. La distinction compte : un
    document TLP:RED ne peut pas être diffusé à une adresse (EX-3).
    """
    sujets = [x.strip().lower()
              for x in brut.replace(",", "\n").replace(";", "\n").splitlines()
              if x.strip()]
    vus, sortie = set(), []
    for sujet in sujets:
        if sujet in vus:
            continue
        vus.add(sujet)
        sortie.append((sujet, "adresse" if "@" in sujet else "compte"))
    return sortie


# --------------------------------------------------------------------------
# Consultation
# --------------------------------------------------------------------------

def _source_verifiee(doc_id: str, me: identity.Identity, doc: dict) -> bytes:
    """Octets du document, ou refus si leur empreinte a bougé.

    Servir des octets dont l'empreinte ne correspond plus à celle journalisée au
    dépôt reviendrait à attester une version qui n'est pas celle qui est
    montrée. On refuse, et l'incohérence est journalisée : c'est un incident
    d'intégrité, pas une erreur de lecture (SEC-015).
    """
    try:
        return store.get_bytes(doc_id)
    except store.SealedDocument:
        # Défense en profondeur : l'autorisation refuse déjà un document non
        # actif. Si on arrive ici, l'état en base et les octets divergent.
        journal(event="sealed_access_attempt", actor=me.user, doc_id=doc_id,
                tlp=doc.get("tlp"), ip=me.ip)
        abort(404)
    except store.CorruptedDocument as exc:
        journal(event="integrity_failed", actor=me.user, doc_id=doc_id,
                tlp=doc.get("tlp"), version_hash=doc.get("version_hash"),
                detail=str(exc), ip=me.ip)
        app.logger.error("intégrité : %s", exc)
        abort(503, description="intégrité du document non vérifiable — accès refusé")


def _identite_courante() -> identity.Identity:
    """Identité de la requête : porteur de lien, sinon identité du proxy."""
    moi, _ = _identite_de_lien()
    return moi if moi is not None else identity.trusted_identity()


def _authorized_doc(doc_id: str, me: identity.Identity) -> dict:
    if me.doc_scope is not None and me.doc_scope != doc_id:
        # Porteur de lien : sa session vaut pour UN document. Un autre document
        # de même niveau, adressé à la même personne, exige son propre lien et
        # son propre second facteur (SEC-018).
        journal(event="access_denied", actor=me.user, doc_id=doc_id, ip=me.ip,
                motif="hors de la portée de la session de lien")
        abort(404)
    # Un porteur de lien n'est destinataire qu'en tant qu'ADRESSE : il n'hérite
    # ni des documents d'un compte homonyme, ni du statut d'émetteur.
    doc = authz.resolve_and_authorize(
        doc_id, me.groups, subject=me.user,
        recipient_kind="adresse" if me.doc_scope is not None else None)
    if doc is None:
        # 404 et 403 sont confondus : pas d'énumération des doc_id (authz.py).
        journal(event="access_denied", actor=me.user, doc_id=doc_id, ip=me.ip)
        abort(404)
    return doc


@app.get("/api/doc/<doc_id>")
def doc_meta(doc_id):
    me = _identite_courante()
    doc = _authorized_doc(doc_id, me)
    return jsonify(doc)


@app.get("/viewer/<doc_id>")
def viewer(doc_id):
    me = _identite_courante()
    doc = _authorized_doc(doc_id, me)

    source = _source_verifiee(doc_id, me, doc)
    try:
        pages = render.page_count(source)
    except render.RenderError:
        abort(500, description="PDF illisible")

    # UUID complet : cet identifiant est la clé qui relie un exemplaire retrouvé
    # ailleurs (capture, PDF exfiltré) à une ligne du journal. Il doit être
    # unique sans ambiguïté possible, pas seulement court à lire.
    view_id = str(uuid.uuid4())
    journal(
        event="document_access", actor=me.user, doc_id=doc_id, tlp=doc["tlp"],
        version_hash=doc["version_hash"], pages=pages, view_id=view_id,
        ip=me.ip, cert_cn=me.cert_cn, mode="viewer",
    )

    tiles = []
    for page in range(pages):
        expires, sig = signing.sign(doc_id, page, view_id, me.user)
        tiles.append(url_for("tile", doc_id=doc_id, page=page,
                             view=view_id, exp=expires, sig=sig))

    # Porteur de lien : pas de lien « Retour » (l'index n'existe pas sur le
    # vhost ext, il répondrait 404), et PAS la liste des destinataires : un
    # rapport adressé à plusieurs victimes révélerait à chacune qui sont les
    # autres (décision du 2026-10-04). La liste n'est même pas transmise au
    # gabarit — elle ne peut donc pas fuir par une erreur d'affichage.
    porteur = me.doc_scope is not None
    return render_template("viewer.html", doc=doc, me=me, tiles=tiles,
                           view_id=view_id, ttl=signing.TTL,
                           destinataires=[] if porteur else store.recipients_of(doc_id),
                           porteur_lien=porteur,
                           mail_actif=mailer.configured(),
                           peut_gerer=(doc["published_by"] == me.user
                                       or authz.is_admin(me.groups)))


@app.get("/api/view/<doc_id>/page/<int:page>.png")
def tile(doc_id, page):
    me = _identite_courante()
    view_id = request.args.get("view", "")
    if not signing.verify(doc_id, page, view_id,
                          me.user, request.args.get("exp"),
                          request.args.get("sig")):
        # Journalisé : une URL simplement périmée (onglet laissé ouvert) et une
        # tentative de forçage sont indiscernables côté serveur, et la seconde
        # ne doit pas passer inaperçue. Le volume reste borné — une consultation
        # n'émet qu'une URL par page, et la visionneuse se recharge pour en
        # obtenir de nouvelles.
        journal(event="tile_denied", actor=me.user, doc_id=doc_id, page=page,
                view_id=view_id or "-", ip=me.ip)
        abort(403, description="URL de tuile invalide ou expirée")

    doc = _authorized_doc(doc_id, me)
    try:
        png = render.render_page_png(
            _source_verifiee(doc_id, me, doc), page, username=me.user,
            tlp=doc["tlp"], view_id=view_id)
    except IndexError:
        abort(404)
    except render.DocumentTooCostly as exc:
        abort(500, description=f"rendu refusé : {exc}")
    except render.RenderError:
        abort(500, description="PDF illisible")

    # Empreinte des pixels réellement servis. Les tuiles ne sont pas signées
    # individuellement — elles ne sont pas conservables hors du service et le
    # volume gonflerait le journal — mais ce qui a été montré est enregistré.
    journal(event="tile_served", actor=me.user, doc_id=doc_id, page=page,
            view_id=view_id, tlp=doc["tlp"],
            artifact_sha256=hashlib.sha256(png).hexdigest(), ip=me.ip)

    return send_file(io.BytesIO(png), mimetype="image/png")


@app.get("/api/export/<doc_id>.pdf")
def export(doc_id):
    """PDF filigrané, rendu image (aucune couche texte) — §6.2.

    Journalisé comme un export, distinct d'une consultation : un export sort du
    périmètre de la visionneuse (il est conservable hors SDOP), le ledger doit
    pouvoir le distinguer lors d'une investigation.

    Le porteur de lien exporte aussi (vhost ext, `location ^/api/export/`) :
    même résolution d'identité que la visionneuse. Avec trusted_identity()
    seule, le destinataire voyait le document mais l'export répondait 401
    (constaté en exploitation).
    """
    me = _identite_courante()
    doc = _authorized_doc(doc_id, me)

    # Sceau exigé mais indisponible (absent, expiré) : refus AVANT tout rendu
    # et toute journalisation — un export non scellé ne sort pas en production,
    # et un refus ne laisse pas de faux export au journal.
    if pades.REQUIRED and not pades.disponible():
        abort(503, description="sceau PAdES indisponible : export suspendu")

    view_id = str(uuid.uuid4())
    source = _source_verifiee(doc_id, me, doc)

    try:
        pdf = render.render_pdf(source, username=me.user, tlp=doc["tlp"],
                               view_id=view_id)
    except render.DocumentTooCostly as exc:
        abort(500, description=f"rendu refusé : {exc}")
    except render.RenderError:
        abort(500, description="PDF illisible")

    # Sceau PAdES (pades.py) : après le rendu, avant le manifeste — l'empreinte
    # journalisée doit être celle des octets scellés, ceux que reçoit le client.
    scelle_par = None
    if pades.disponible():
        try:
            pdf = pades.seal(pdf, view_id=view_id)
        except Exception:  # noqa: BLE001 — aucun export non scellé ne sort
            app.logger.exception("sceau PAdES impossible (export %s)", view_id)
            abort(500, description="sceau PAdES impossible")
        scelle_par = pades.cert_sha256()

    # Le manifeste décrit les octets RÉELLEMENT produits : il est donc construit
    # après le rendu, et le geste n'est journalisé qu'ensuite. L'ordre compte —
    # journaliser avant de rendre enregistrerait une demande, pas un artefact.
    man = manifest.build(doc=doc, view_id=view_id, actor=me.user, kind="export",
                         artifact=pdf,
                         source_sha256=hashlib.sha256(source).hexdigest(),
                         pades_cert_sha256=scelle_par)
    journal(
        event="document_export", actor=me.user, doc_id=doc_id, tlp=doc["tlp"],
        version_hash=doc["version_hash"], view_id=view_id, ip=me.ip,
        cert_cn=me.cert_cn, manifest=man, signature=manifest.sign(man),
    )

    slug = doc["tlp"].replace("TLP:", "").replace("+", "-").lower()
    # Le nom du fichier porte l'identifiant de consultation : un exemplaire
    # retrouvé hors SDOP se rattache au journal sans même l'ouvrir.
    return send_file(
        io.BytesIO(pdf), mimetype="application/pdf", as_attachment=True,
        download_name=f"sdop-{slug}-{view_id}.pdf")


@app.get("/api/evidence/<view_id>")
def evidence(view_id):
    """Manifeste signé d'une diffusion — de quoi vérifier un exemplaire retrouvé.

    Rend le manifeste et sa signature détachée. Un tiers vérifie hors ligne avec
    la clé publique (/api/pubkey) : il recalcule l'empreinte des octets qu'il
    détient et la compare à `artifact_sha256`.

    Ce que cela prouve : ces octets sont ceux que le serveur a produits, pour ce
    compte, à cette date. Ce que cela ne prouve pas : qui a ensuite divulgué la
    copie. Un exemplaire émis vers un compte ne désigne pas automatiquement
    l'auteur d'une fuite — poste compromis, transfert légitime, copie obtenue
    par un tiers.
    """
    me = identity.trusted_identity()
    for entree in _entrees_journal():
        if entree.get("view_id") != view_id or "manifest" not in entree:
            continue
        doc = authz.resolve_and_authorize(entree["doc_id"], me.groups,
                                          subject=me.user)
        if doc is None:
            abort(404)
        return jsonify(manifest=entree["manifest"],
                       signature=entree["signature"],
                       key_id=entree["manifest"].get("key_id"),
                       public_key=manifest.public_key_b64())
    abort(404)


def _entrees_journal() -> list[dict]:
    """Entrées du segment courant. Lecture seule, jamais d'écriture ici."""
    chemin = ledger._segment_path(ledger.LEDGER_DIR)
    if not os.path.exists(chemin):
        return []
    try:
        return ledger.read(chemin)
    except ledger.LedgerError:
        return []


@app.post("/api/confinement")
def confinement():
    """Coupe ou rétablit toute diffusion — le dernier cran du kill switch.

    Réservé aux administrateurs. Ne supprime rien, ne scelle rien : coupe la
    diffusion le temps de comprendre. La publication reste possible — on peut
    avoir besoin de déposer des éléments pendant un incident sans vouloir
    qu'ils sortent.
    """
    me = identity.trusted_identity()
    if not authz.is_admin(me.groups):
        journal(event="containment_denied", actor=me.user, ip=me.ip)
        abort(403, description="réservé aux administrateurs")

    actif = (request.form.get("actif", "1") == "1")
    motif = _motif()
    with db.transaction():
        store.set_containment(actif, me.user)
        journal(event="containment_enabled" if actif else "containment_lifted",
                actor=me.user, motif=motif, ip=me.ip)
    return jsonify(containment=actif)


# --------------------------------------------------------------------------
# Accès sans compte : liens nominatifs (EX-3)
# --------------------------------------------------------------------------

COOKIE = "sdop_lien"


def _identite_de_lien() -> tuple[identity.Identity, dict] | tuple[None, None]:
    """Identité d'un porteur de lien, résolue CÔTÉ SERVEUR.

    Le client ne présente qu'un jeton opaque : c'est SDOP qui le résout en
    identité, exactement comme le proxy résout une session Authentik. La règle
    « l'identité ne vient jamais du client » tient — un jeton n'est pas une
    identité déclarée, c'est une référence que le serveur seul sait traduire.

    Le porteur reçoit le groupe lecteur du niveau de SON document : il traverse
    ainsi l'autorisation normale (double condition) sans exception taillée pour
    lui.
    """
    jeton = request.cookies.get(COOKIE)
    if not jeton:
        return None, None
    sess = links.session(jeton)
    if sess is None:
        return None, None
    doc = store.get_meta(sess["doc_id"])
    if doc is None:
        return None, None
    moi = identity.Identity(
        user=sess["subject"], groups=[authz.reader_group(doc["tlp"])],
        ip=(request.headers.get("X-Forwarded-For", "") or "").split(",")[0].strip()
           or (request.remote_addr or ""),
        cert_cn="", email=sess["subject"], doc_scope=sess["doc_id"])
    return moi, sess


def _diffuser(doc: dict, sujet: str, me: identity.Identity, mode: str = "code",
              ttl_hours: int | None = None, envoyer: bool = False) -> dict:
    """Émet un lien pour `sujet` et, sur demande, l'envoie par courriel.

    Le code n'est rendu qu'ici, pour être affiché UNE fois à l'émetteur ; il ne
    part jamais dans le courriel (mailer.py). Lève links.LinkError (journalisé)
    si le lien est refusé. Un échec d'envoi ne lève pas : le lien existe, l'analyste
    le transmet lui-même, et l'échec est journalisé.
    """
    try:
        # Lien, destinataire et journal : tout ou rien (SEC-024). Le courriel
        # part APRÈS la validation — jamais un lien qui n'existerait pas.
        with db.transaction():
            sujet = links.require_address(sujet)
            if store.is_recipient(doc["doc_id"], sujet, kind="compte"):
                raise links.LinkError(f"{sujet} est un compte du socle : il consulte "
                                      "par son compte, pas par lien")
            lien = links.issue(doc, sujet, issued_by=me.user, mode=mode,
                               ttl_hours=ttl_hours)
            # Le destinataire devient destinataire du document : la double
            # condition s'applique à lui comme aux comptes.
            actuels = [(r["subject"], r["kind"])
                       for r in store.recipients_of(doc["doc_id"])]
            if sujet not in {s for s, _ in actuels}:
                store.set_recipients(doc["doc_id"], actuels + [(sujet, "adresse")],
                                     me.user)
            journal(event="link_issued", actor=me.user, doc_id=doc["doc_id"],
                    subject=sujet, mode=lien["mode"],
                    expires_in_hours=lien["expires_in_hours"], ip=me.ip)
    except links.LinkError as exc:
        journal(event="link_denied", actor=me.user, doc_id=doc["doc_id"],
                subject=sujet[:links.MAX_SUBJECT_LEN], motif=str(exc), ip=me.ip)
        raise

    chemin = url_for("ouvrir_lien", token=lien["token"], _external=False)
    resultat = {"destinataire": sujet, "url": chemin, "code": lien["code"],
                "mode": lien["mode"], "expires_in_hours": lien["expires_in_hours"],
                "lien_public": mailer.public_link(chemin) if mailer.PUBLIC_URL else "",
                "courriel": "non demandé"}
    if envoyer:
        if "@" not in sujet:
            resultat["courriel"] = "non envoyé : le destinataire n'est pas une adresse"
        elif not mailer.configured():
            resultat["courriel"] = "non envoyé : courriel non configuré sur ce serveur"
        else:
            try:
                msgid = mailer.send(mailer.build(
                    sujet, resultat["lien_public"], doc["tlp"],
                    lien["expires_in_hours"], reply_to=me.email))
                resultat["courriel"] = "envoyé"
                journal(event="link_mailed", actor=me.user, doc_id=doc["doc_id"],
                        subject=sujet, message_id=msgid, ip=me.ip)
            except mailer.MailError as exc:
                resultat["courriel"] = f"échec : {exc}"
                journal(event="link_mail_failed", actor=me.user, doc_id=doc["doc_id"],
                        subject=sujet, motif=str(exc), ip=me.ip)
    return resultat


def _veut_json() -> bool:
    return request.accept_mimetypes.best == "application/json"


@app.post("/api/lien/<doc_id>")
def emettre_lien(doc_id):
    """Émet un lien nominatif. Le code n'est montré qu'ici, une seule fois."""
    me = identity.trusted_identity()
    doc = _authorized_doc(doc_id, me)
    if doc["published_by"] != me.user:
        abort(403, description="seul l'émetteur peut diffuser par lien")

    sujet = (request.form.get("destinataire") or "").strip().lower()
    try:
        r = _diffuser(doc, sujet, me, mode=request.form.get("mode", "code"),
                      ttl_hours=request.form.get("heures", type=int),
                      envoyer=bool(request.form.get("envoyer")))
    except links.LinkError as exc:
        abort(400, description=str(exc))

    if _veut_json():
        return jsonify(url=r["url"], code=r["code"], mode=r["mode"],
                       expires_in_hours=r["expires_in_hours"],
                       courriel=r["courriel"],
                       rappel="Le code se dicte de vive voix. Ne jamais l'envoyer "
                              "par le même canal que le lien.")
    return render_template("diffusion.html", me=me, doc=doc, resultats=[r],
                           erreurs=[], trust_mode=identity.TRUST_MODE)


@app.post("/api/enroler")
def enroler():
    """Enrôle un correspondant en TOTP — une fois par personne, pas par document."""
    me = identity.trusted_identity()
    if not authz.publishable_levels(me.groups):
        abort(403, description="réservé aux émetteurs")
    sujet = links.normalize_subject(request.form.get("destinataire"))
    try:
        with db.transaction():
            secret = links.enroll(sujet, created_by=me.user)
            journal(event="correspondent_enrolled", actor=me.user, subject=sujet,
                    ip=me.ip)
    except links.AlreadyEnrolled as exc:
        # Un second enrôlement remplaçait le secret existant : tout émetteur
        # pouvait ainsi prendre le facteur de n'importe quel correspondant
        # (SEC-019). Refusé, et le refus est une trace à surveiller.
        journal(event="enrollment_denied", actor=me.user, subject=sujet,
                motif="déjà enrôlé", ip=me.ip)
        abort(409, description=str(exc))
    except links.LinkError as exc:
        abort(400, description=str(exc))
    return _rendre_enrolement(me, sujet, secret)


def _rendre_enrolement(me, sujet: str, secret: str):
    """Secret d'enrôlement : JSON pour l'API, page (secret + QR) pour le formulaire.

    Le secret n'est montré qu'ici, une seule fois, jamais journalisé ; la page
    est `no-store` comme toute réponse (SEC-023).
    """
    if _veut_json():
        return jsonify(subject=sujet, totp_secret=secret,
                       rappel="Secret à transmettre de vive voix, une seule fois.")
    groupes = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return render_template("enrolement.html", me=me, sujet=sujet, secret=groupes,
                           qr=qr.svg(links.otpauth_uri(sujet, secret)),
                           trust_mode=identity.TRUST_MODE)


@app.post("/api/correspondant/reinitialiser")
def reinitialiser_correspondant():
    """Réinitialise le second facteur d'un correspondant — administrateurs seuls.

    Récupération après perte ou compromission de l'appareil. Distincte de
    l'enrôlement (SEC-019) : elle exige un administrateur et un motif, coupe
    toutes les sessions et tous les liens actifs du correspondant, et trace
    l'opérateur ET l'émetteur d'origine. L'identité de la personne qui reçoit le
    nouveau secret se vérifie hors bande, par rappel à un numéro connu : le code
    ne peut pas le faire à sa place.
    """
    me = identity.trusted_identity()
    sujet = links.normalize_subject(request.form.get("destinataire"))
    if not authz.is_admin(me.groups):
        journal(event="enrollment_reset_denied", actor=me.user, subject=sujet,
                ip=me.ip)
        abort(403, description="réservé aux administrateurs")
    motif = _motif(requis=True)
    try:
        with db.transaction():
            r = links.reset_enrollment(sujet)
            journal(event="correspondent_reset", actor=me.user, subject=r["subject"],
                    enrolled_by=r["enrolled_by"],
                    sessions_coupees=r["sessions_coupees"], motif=motif, ip=me.ip)
    except links.LinkError as exc:
        abort(400, description=str(exc))
    return jsonify(subject=r["subject"], totp_secret=r["totp_secret"],
                   sessions_revoquees=r["sessions_coupees"],
                   rappel="Identité vérifiée hors bande ; secret transmis de vive "
                          "voix, une seule fois. Les liens actifs sont à réémettre.")


@app.post("/api/correspondant/revoquer")
def revoquer_correspondant():
    """Coupe TOUS les accès d'un correspondant, tous documents — administrateurs.

    La révocation par document (`/api/lien/<doc_id>/revoquer`) ne porte que sur
    ce document : un émetteur ne coupe pas l'accès aux diffusions des autres
    (SEC-022). Le kill switch par personne est un geste d'administration.
    """
    me = identity.trusted_identity()
    sujet = links.normalize_subject(request.form.get("destinataire"))
    if not authz.is_admin(me.groups):
        journal(event="link_revoke_all_denied", actor=me.user, subject=sujet,
                ip=me.ip)
        abort(403, description="réservé aux administrateurs")
    if not sujet:
        abort(400, description="destinataire requis")
    motif = _motif()
    with db.transaction():
        coupees = links.revoke_all_for(sujet)
        journal(event="link_revoked_all", actor=me.user, subject=sujet,
                sessions_coupees=coupees, motif=motif, ip=me.ip)
    return jsonify(subject=sujet, sessions_revoquees=coupees, portee="tous documents")


@app.post("/lien/quitter")
def quitter_lien():
    """Ferme la session de lien du porteur — bouton « Quitter ».

    La session est révoquée côté serveur, pas seulement oubliée par le
    navigateur : un cookie copié ailleurs ne vaut plus rien non plus. Route
    statique : Flask la préfère à `/lien/<token>`, et aucun jeton (43
    caractères aléatoires) ne vaut « quitter ». Le vhost externe l'ouvre déjà
    (`location ~ ^/lien/[A-Za-z0-9_-]+$`).
    """
    jeton = request.cookies.get(COOKIE)
    sess = links.session(jeton) if jeton else None
    if sess is not None:
        ip = (request.headers.get("X-Forwarded-For", "") or "").split(",")[0].strip()
        with db.transaction():
            links.close_session(jeton)
            journal(event="link_session_closed", actor=sess["subject"],
                    doc_id=sess["doc_id"], ip=ip)
    resp = make_response(render_template("quitte.html", trust_mode=identity.TRUST_MODE))
    resp.delete_cookie(COOKIE, secure=True, httponly=True, samesite="Lax")
    return resp


@app.get("/lien/<token>")
def ouvrir_lien(token):
    return render_template("lien.html", token=token, erreur=None,
                           trust_mode=identity.TRUST_MODE)


@app.post("/lien/<token>")
def valider_lien(token):
    """Valide le second facteur et ouvre une session courte."""
    facteur = request.form.get("facteur", "")
    lien = links.get(token)
    ip = (request.headers.get("X-Forwarded-For", "") or "").split(",")[0].strip()

    def journaliser_ouverture(ouverture):
        # Dans la transaction de consommation : si le journal refuse, le lien
        # n'est pas consommé et aucune session n'existe (SEC-024).
        journal(event="link_used", actor=ouverture["subject"],
                doc_id=ouverture["doc_id"], mode=ouverture["mode"], ip=ip)

    try:
        ouverture = links.redeem(token, facteur, on_open=journaliser_ouverture)
    except links.LinkError as exc:
        if lien:
            journal(event="link_failed", actor=lien["subject"],
                    doc_id=lien["doc_id"], motif=str(exc),
                    ip=(request.headers.get("X-Forwarded-For", "") or "").split(",")[0].strip())
        return render_template("lien.html", token=token, erreur=str(exc),
                               trust_mode=identity.TRUST_MODE), 403

    resp = make_response(redirect(url_for("viewer", doc_id=ouverture["doc_id"]),
                                  code=303))
    resp.set_cookie(COOKIE, ouverture["session"], httponly=True, secure=True,
                    samesite="Lax", max_age=links.SESSION_MINUTES * 60)
    return resp


@app.post("/api/lien/<doc_id>/revoquer")
def revoquer_liens(doc_id):
    """Coupe les liens et sessions d'un correspondant sur CE document.

    La portée suit le droit : l'émetteur de ce document coupe l'accès à ce
    document, pas aux diffusions des autres émetteurs (SEC-022). Couper une
    personne partout : `/api/correspondant/revoquer`, administrateurs.
    """
    me = identity.trusted_identity()
    doc = _authorized_doc(doc_id, me)
    if doc["published_by"] != me.user and not authz.is_admin(me.groups):
        abort(403, description="réservé à l'émetteur ou à un administrateur")
    sujet = links.normalize_subject(request.form.get("destinataire"))
    if not sujet:
        abort(400, description="destinataire requis")
    with db.transaction():
        coupees = links.revoke_for_document(doc_id, sujet)
        journal(event="link_revoked", actor=me.user, doc_id=doc_id, subject=sujet,
                sessions_coupees=coupees, ip=me.ip)
    return jsonify(subject=sujet, sessions_revoquees=coupees, portee="ce document")


# --------------------------------------------------------------------------
# Cycle de vie du document
# --------------------------------------------------------------------------

@app.post("/api/prolonger/<doc_id>")
def prolonger(doc_id):
    """Repousse l'échéance — avant qu'elle ne tombe, et par l'émetteur seul.

    Après l'échéance, la prolongation est refusée : les destinataires ont vu
    l'accès disparaître, le rouvrir sans nouvelle décision de diffusion
    reviendrait à republier en silence (EX-5).
    """
    me = identity.trusted_identity()
    doc = _authorized_doc(doc_id, me)
    if doc["published_by"] != me.user:
        journal(event="extend_denied", actor=me.user, doc_id=doc_id, ip=me.ip)
        abort(403, description="seul l'émetteur peut prolonger")

    jours = request.form.get("jours", type=int) \
        or (request.get_json(silent=True) or {}).get("jours")
    if not isinstance(jours, int) or isinstance(jours, bool) or jours < 1:
        abort(400, description="durée invalide")
    try:
        with db.transaction():
            nouvelle = store.extend(doc_id, jours)
            journal(event="document_extended", actor=me.user, doc_id=doc_id,
                    tlp=doc["tlp"], jours=jours, expires_at=nouvelle, ip=me.ip)
    except store.RejectedDocument as exc:
        abort(400, description=str(exc))
    if request.accept_mimetypes.best == "application/json":
        return jsonify(doc_id=doc_id, expires_at=nouvelle)
    return redirect(url_for("viewer", doc_id=doc_id), code=303)


@app.post("/api/sceller/<doc_id>")
def sceller_maintenant(doc_id):
    """« Sceller maintenant » : échéance avancée à l'instant, scellement au
    prochain balayage (scripts/sdop-sceller.py, tâche serveur horaire).

    Délibérément PAS de scellement ici : une route capable de rendre un
    document définitivement illisible serait une cible (voir sdop-sceller.py).
    """
    me = identity.trusted_identity()
    # Pas _authorized_doc : un document RETIRÉ n'est plus lisible par personne,
    # mais son émetteur doit encore pouvoir le sceller. Pour tout autre : 404,
    # comme partout, sans trahir l'existence du document.
    doc = store.get_meta(doc_id) if store.DOC_ID_RE.match(doc_id) else None
    if doc is None or (doc["published_by"] != me.user and not authz.is_admin(me.groups)):
        journal(event="seal_request_denied", actor=me.user, doc_id=doc_id, ip=me.ip)
        abort(404)
    motif = _motif()
    try:
        with db.transaction():
            quand = store.expire_now(doc_id)
            journal(event="seal_requested", actor=me.user, doc_id=doc_id,
                    tlp=doc["tlp"], expires_at=quand, motif=motif, ip=me.ip)
    except store.RejectedDocument as exc:
        abort(400, description=str(exc))
    if _veut_json():
        return jsonify(doc_id=doc_id, expires_at=quand, state="a_sceller")
    return redirect(url_for("index"), code=303)


@app.post("/api/retirer/<doc_id>")
def retirer(doc_id):
    """Retrait immédiat de la diffusion — le kill switch au niveau document.

    Les octets restent (le scellement est une opération distincte, hors ligne) ;
    c'est l'accès qui cesse, pour tous et tout de suite.
    """
    me = identity.trusted_identity()
    doc = _authorized_doc(doc_id, me)
    if doc["published_by"] != me.user and not authz.is_admin(me.groups):
        journal(event="withdraw_denied", actor=me.user, doc_id=doc_id, ip=me.ip)
        abort(403, description="seuls l'émetteur ou un administrateur peuvent retirer")

    motif = _motif()
    with db.transaction():
        store.set_state(doc_id, "retire")
        journal(event="document_withdrawn", actor=me.user, doc_id=doc_id,
                tlp=doc["tlp"], motif=motif, ip=me.ip)
    if request.accept_mimetypes.best == "application/json":
        return jsonify(doc_id=doc_id, state="retire")
    return redirect(url_for("index"), code=303)


# --------------------------------------------------------------------------
# Erreurs — toujours en JSON sous /api/, jamais de trace au client
# --------------------------------------------------------------------------

@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(409)
@app.errorhandler(413)
@app.errorhandler(500)
@app.errorhandler(503)
def error(exc):
    code = getattr(exc, "code", 500)
    msg = getattr(exc, "description", "erreur")
    if request.path.startswith("/api/"):
        return jsonify(error=msg, status=code), code
    return Response(f"SDOP — {code} : {msg}\n", status=code,
                    mimetype="text/plain")


if __name__ == "__main__":
    app.run(host=os.environ.get("SDOP_BIND", "0.0.0.0"),
            port=int(os.environ.get("SDOP_PORT", "5000")), debug=False)
