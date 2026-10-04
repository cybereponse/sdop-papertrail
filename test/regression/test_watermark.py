"""
Palier 1 — régression du service watermark (Lot 2, ARCHITECTURE.md).

Aucun conteneur : l'app Flask est chargée directement et exercée via
`test_client()`. Les en-têtes de confiance sont simulés, comme pour le
placeholder — ce que nginx garantit (impossibilité pour un client de les
fournir) est validé au Palier 2, pas ici.

Ce fichier teste les propriétés qui font le produit, pas les détails de rendu :
1. rien n'est servi sans identité de confiance ;
2. l'habilitation TLP est évaluée côté serveur, et un doc_id non autorisé est
   indistinguable d'un doc_id inexistant ;
3. rien n'est servi qui ne soit journalisé (fail-closed si le ledger tombe) ;
4. le client ne reçoit jamais de couche texte.
"""
import glob
import hashlib
import importlib.util
import io
import json
import os
import sys

import pytest
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# Le service est chargé par chemin : `watermark/app.py` ne doit pas entrer en
# collision avec `placeholder/app.py` dans sys.path (voir conftest.py).
sys.path.insert(0, os.path.join(ROOT, "watermark"))
sys.path.insert(0, os.path.join(ROOT, "ledger"))
_spec = importlib.util.spec_from_file_location(
    "sdop_watermark_app", os.path.join(ROOT, "watermark", "app.py"))
wm = importlib.util.module_from_spec(_spec)
# Enregistré dans sys.modules AVANT exécution : Flask résout son dossier de
# templates via sys.modules[import_name].__file__ — sans cela, les gabarits
# seraient cherchés depuis le répertoire courant et introuvables.
sys.modules[_spec.name] = wm
_spec.loader.exec_module(wm)

import ledger  # noqa: E402
import links  # noqa: E402
import render  # noqa: E402
import store  # noqa: E402

EMETTEUR_RED = {
    "X-Authentik-Username": "emetteur.red",
    "X-Authentik-Groups": "tlp-red-emetteurs",
    "X-Client-Cert-CN": "emetteur.red",
    "X-Forwarded-For": "10.0.0.1",
}
LECTEUR_RED = {
    "X-Authentik-Username": "lecteur.red",
    "X-Authentik-Groups": "tlp-red-lecteurs",
    "X-Client-Cert-CN": "lecteur.red",
    "X-Forwarded-For": "10.0.0.2",
}
EMETTEUR_AMBER = {
    "X-Authentik-Username": "emetteur.amber",
    "X-Authentik-Groups": "tlp-amber-emetteurs",
    "X-Client-Cert-CN": "emetteur.amber",
    "X-Forwarded-For": "10.0.0.4",
}
LECTEUR_AMBER = {
    "X-Authentik-Username": "lecteur.amber",
    "X-Authentik-Groups": "tlp-amber-lecteurs",
    "X-Client-Cert-CN": "lecteur.amber",
    "X-Forwarded-For": "10.0.0.3",
}


def _pdf(pages=1, text="Document de test SDOP") -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    for i in range(pages):
        c.setFont("Helvetica", 12)
        c.drawString(72, 700, f"{text} — page {i + 1}")
        c.showPage()
    c.save()
    return buf.getvalue()


@pytest.fixture
def client():
    wm.app.config["TESTING"] = True
    with wm.app.test_client() as c:
        yield c


@pytest.fixture
def doc_id(client):
    """Document diffusé explicitement à LECTEUR_RED.

    La diffusion est un geste : un document sans destinataire n'est lisible que
    par son émetteur (EX-1). Les tests doivent donc la poser.
    """
    resp = client.post("/api/publish", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:RED", "document": (io.BytesIO(_pdf(2)), "note.pdf"),
        "destinataires": "lecteur.red"})
    assert resp.status_code == 201, resp.get_data(as_text=True)
    return resp.get_json()["doc_id"]


def _journal_events():
    events = []
    for path in glob.glob(os.path.join(os.environ["SDOP_LEDGER_DIR"], "*.jsonl")):
        with open(path) as f:
            events += [json.loads(line) for line in f if line.strip()]
    return events


# --- 1. Rien sans identité de confiance -----------------------------------

def test_health_sans_identite(client):
    """Seule la sonde de santé est ouverte — elle ne révèle aucun document."""
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "ok"
    assert body["trust_mode"] == "proxy"


@pytest.mark.parametrize("url", ["/", "/api/doc/" + "0" * 32,
                                 "/viewer/" + "0" * 32,
                                 "/api/export/" + "0" * 32 + ".pdf"])
def test_401_sans_entete_identite(client, url):
    """Pas d'en-tête d'identité = requête non passée par le proxy = refus."""
    assert client.get(url).status_code == 401


# --- 2. Habilitation évaluée côté serveur ---------------------------------

def test_publication_refusee_sans_groupe_emetteur(client):
    resp = client.post("/api/publish", headers=LECTEUR_RED | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:RED", "document": (io.BytesIO(_pdf()), "x.pdf")})
    assert resp.status_code == 403
    assert any(e["event"] == "publish_denied" and e["actor"] == "lecteur.red"
               for e in _journal_events())


def test_publication_refusee_niveau_non_habilite(client):
    """Émetteur RED ne publie pas en AMBER : aucune hiérarchie implicite."""
    resp = client.post("/api/publish", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:AMBER", "document": (io.BytesIO(_pdf()), "x.pdf")})
    assert resp.status_code == 403


def test_tlp_inconnu_refuse(client):
    resp = client.post("/api/publish", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:GREEN", "document": (io.BytesIO(_pdf()), "x.pdf")})
    assert resp.status_code == 400


def test_nom_de_fichier_long_ne_casse_pas_le_journal(client):
    """Un nom de fichier long ne doit pas rendre le journal inutilisable.

    `ledger._last_hash()` ne relit que les 4096 derniers octets du segment :
    une entrée plus longue casse DÉFINITIVEMENT tout ajout ultérieur. La
    journalisation étant fail-closed, le service entier tomberait en 503 —
    déni de service déclenchable par un émetteur habilité. Le nom est donc
    borné au dépôt (store.MAX_NAME_LEN).
    """
    nom = "A" * 5000 + ".pdf"
    resp = client.post("/api/publish", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:RED", "document": (io.BytesIO(_pdf()), nom),
        "destinataires": "lecteur.red"})
    assert resp.status_code == 201
    assert len(resp.get_json()["original_name"]) <= store.MAX_NAME_LEN

    # Le journal reste utilisable : un geste postérieur doit encore s'inscrire.
    doc_id = resp.get_json()["doc_id"]
    assert client.get(f"/api/doc/{doc_id}", headers=LECTEUR_RED).status_code == 200
    avant = len(_journal_events())
    client.get(f"/viewer/{doc_id}", headers=LECTEUR_RED)
    assert len(_journal_events()) > avant, "le journal n'accepte plus d'entrée"


def _pdf_geant(pages=1, largeur=595, hauteur=842) -> bytes:
    """PDF de géométrie choisie — compressé, donc petit en octets."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(largeur, hauteur))
    for _ in range(pages):
        c.showPage()
    c.save()
    return buf.getvalue()


def test_document_trop_de_pages_refuse(client, monkeypatch):
    """La taille du fichier ne borne pas le coût du rendu (SEC-017).

    Un PDF compressé de quelques kilo-octets peut contenir des milliers de
    pages. Le plafond mémoire du conteneur ne protège pas le service : il le
    fait tuer, ce qui est l'indisponibilité qu'on veut éviter.
    """
    monkeypatch.setattr(render, "MAX_PAGES", 10)
    resp = client.post("/api/publish", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:RED", "document": (io.BytesIO(_pdf_geant(50)), "gros.pdf")})
    assert resp.status_code == 400
    assert "50 pages" in resp.get_json()["error"]


def test_page_demesuree_refusee(client):
    """Une seule page peut suffire : 5 m de côté à 150 dpi dépasse le budget."""
    enorme = _pdf_geant(1, largeur=14400, hauteur=14400)   # 200 pouces
    resp = client.post("/api/publish", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:RED", "document": (io.BytesIO(enorme), "enorme.pdf")})
    assert resp.status_code == 400
    assert "trop grande" in resp.get_json()["error"]


def test_budget_cumule_refuse(client, monkeypatch):
    """C'est l'export qui accumule en mémoire : le cumul est borné aussi."""
    monkeypatch.setattr(render, "MAX_TOTAL_PIXELS", 5_000_000)
    resp = client.post("/api/publish", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:RED", "document": (io.BytesIO(_pdf_geant(20)), "cumul.pdf")})
    assert resp.status_code == 400
    assert "cumulés" in resp.get_json()["error"]


def test_document_raisonnable_accepte(client):
    """Le garde-fou ne doit pas refuser un rapport ordinaire."""
    resp = client.post("/api/publish", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:RED", "document": (io.BytesIO(_pdf(30)), "rapport.pdf")})
    assert resp.status_code == 201


def test_non_pdf_refuse(client):
    resp = client.post("/api/publish", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:RED", "document": (io.BytesIO(b"MZ pas un pdf"), "x.pdf")})
    assert resp.status_code == 400


def test_habilite_mais_non_destinataire_refuse(client):
    """Le groupe TLP est un plafond, pas une permission (EX-1).

    Avant la V1, appartenir au groupe du niveau donnait accès à TOUS les
    documents de ce niveau : un rapport adressé à une collectivité était lisible
    par toutes les autres.
    """
    resp = client.post("/api/publish", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:RED", "document": (io.BytesIO(_pdf()), "prive.pdf"),
        "destinataires": "quelqu-un-dautre"})
    autre = resp.get_json()["doc_id"]

    # LECTEUR_RED est habilité RED, mais n'est pas destinataire de ce document.
    assert client.get(f"/api/doc/{autre}", headers=LECTEUR_RED).status_code == 404
    assert client.get(f"/viewer/{autre}", headers=LECTEUR_RED).status_code == 404
    assert autre not in client.get("/", headers=LECTEUR_RED).get_data(as_text=True)


def test_destinataire_mais_non_habilite_refuse(client):
    """Et réciproquement : être désigné ne dispense pas de l'habilitation."""
    resp = client.post("/api/publish", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:RED", "document": (io.BytesIO(_pdf()), "rouge.pdf"),
        "destinataires": "lecteur.amber"})
    rouge = resp.get_json()["doc_id"]

    # LECTEUR_AMBER est bien destinataire, mais n'est pas habilité RED.
    assert client.get(f"/api/doc/{rouge}", headers=LECTEUR_AMBER).status_code == 404


def test_emetteur_voit_ce_qu_il_a_publie(client):
    """Sans se désigner lui-même : il doit pouvoir vérifier sa diffusion."""
    resp = client.post("/api/publish", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:RED", "document": (io.BytesIO(_pdf()), "mien.pdf"),
        "destinataires": "lecteur.red"})
    mien = resp.get_json()["doc_id"]
    assert client.get(f"/api/doc/{mien}", headers=EMETTEUR_RED).status_code == 200


def test_destinataires_journalises_a_la_publication(client):
    resp = client.post("/api/publish", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:RED", "document": (io.BytesIO(_pdf()), "diff.pdf"),
        "destinataires": "lecteur.red, autre.red\ntiers@exemple.invalid"})
    doc = resp.get_json()["doc_id"]
    pub = [e for e in _journal_events()
           if e["event"] == "document_publish" and e["doc_id"] == doc][0]
    assert set(pub["recipients"]) == {"lecteur.red", "autre.red",
                                      "tiers@exemple.invalid"}
    assert pub["expires_at"]


def test_lecteur_du_bon_niveau_accede(client, doc_id):
    resp = client.get(f"/api/doc/{doc_id}", headers=LECTEUR_RED)
    assert resp.status_code == 200
    assert resp.get_json()["tlp"] == "TLP:RED"


def test_lecteur_autre_niveau_ne_distingue_pas_404_de_403(client, doc_id):
    """Un non-habilité ne doit pas pouvoir énumérer les doc_id existants."""
    existant = client.get(f"/api/doc/{doc_id}", headers=LECTEUR_AMBER)
    inexistant = client.get(f"/api/doc/{'0' * 32}", headers=LECTEUR_AMBER)
    assert existant.status_code == inexistant.status_code == 404
    assert any(e["event"] == "access_denied" and e["actor"] == "lecteur.amber"
               for e in _journal_events())


def test_doc_id_non_conforme_rejete(client):
    """Aucun doc_id ne touche le système de fichiers sans validation stricte."""
    assert store.is_doc_id("../../etc/passwd") is False
    assert store.is_doc_id("0" * 32) is True
    resp = client.get("/api/doc/..%2f..%2fetc%2fpasswd", headers=LECTEUR_RED)
    assert resp.status_code == 404


def test_index_ne_liste_que_le_lisible(client, doc_id):
    html = client.get("/", headers=LECTEUR_AMBER).get_data(as_text=True)
    assert doc_id not in html
    html_red = client.get("/", headers=LECTEUR_RED).get_data(as_text=True)
    assert doc_id in html_red


def test_source_alteree_refusee_et_journalisee(client, doc_id):
    """Des octets qui ne correspondent plus à leur empreinte ne sont pas servis.

    Le hash était calculé une fois au dépôt, puis plus jamais vérifié : un
    fichier remplacé sans son sidecar aurait été rendu pendant que le journal
    annonçait l'empreinte d'origine (SEC-015). Le service doit refuser, et dire
    pourquoi au journal.
    """
    chemin, _ = store._paths(doc_id, os.environ["SDOP_DOC_DIR"])
    original = open(chemin, "rb").read()
    try:
        with open(chemin, "wb") as f:
            f.write(_pdf(1, text="Contenu substitue"))

        assert client.get(f"/viewer/{doc_id}", headers=LECTEUR_RED).status_code == 503
        assert client.get(f"/api/export/{doc_id}.pdf",
                          headers=LECTEUR_RED).status_code == 503
        assert any(e["event"] == "integrity_failed" and e["doc_id"] == doc_id
                   for e in _journal_events())

        with pytest.raises(store.CorruptedDocument):
            store.get_bytes(doc_id)
    finally:
        with open(chemin, "wb") as f:
            f.write(original)

    # Une fois les octets d'origine rétablis, le service repart.
    assert client.get(f"/viewer/{doc_id}", headers=LECTEUR_RED).status_code == 200


def test_publication_atomique(client, doc_id):
    """Un PDF ne doit jamais exister sans son sidecar."""
    pdf, meta = store._paths(doc_id, os.environ["SDOP_DOC_DIR"])
    assert os.path.exists(pdf) and os.path.exists(meta)
    restes = [n for n in os.listdir(os.environ["SDOP_DOC_DIR"]) if n.endswith(".tmp")]
    assert not restes, f"fichiers temporaires laissés : {restes}"


# --- 3. Tuiles : signature liée à l'utilisateur ----------------------------

def _tiles(client, doc_id, headers):
    html = client.get(f"/viewer/{doc_id}", headers=headers).get_data(as_text=True)
    import re
    # Les tuiles seules (img.page) : le gabarit porte aussi le logo en data:.
    return re.findall(r'<img class="page" src="([^"]+)"', html.replace("&amp;", "&"))


def test_tuile_servie_en_png(client, doc_id):
    url = _tiles(client, doc_id, LECTEUR_RED)[0]
    resp = client.get(url, headers=LECTEUR_RED)
    assert resp.status_code == 200
    assert resp.mimetype == "image/png"
    assert resp.data.startswith(b"\x89PNG")
    assert "no-store" in resp.headers["Cache-Control"]


def test_tuile_sans_signature_refusee(client, doc_id):
    resp = client.get(f"/api/view/{doc_id}/page/0.png", headers=LECTEUR_RED)
    assert resp.status_code == 403
    assert any(e["event"] == "tile_denied" and e["actor"] == "lecteur.red"
               for e in _journal_events())


def test_tuile_signee_pour_un_autre_utilisateur_refusee(client, doc_id):
    """Une URL de tuile recopiée vers un autre compte ne vaut rien."""
    url = _tiles(client, doc_id, LECTEUR_RED)[0]
    autre = dict(LECTEUR_RED, **{"X-Authentik-Username": "autre.red"})
    assert client.get(url, headers=autre).status_code == 403


def test_tuile_expiree_refusee(client, doc_id):
    import signing
    expires, sig = signing.sign(doc_id, 0, "VIEWTEST", "lecteur.red", ttl=-1)
    resp = client.get(f"/api/view/{doc_id}/page/0.png"
                      f"?view=VIEWTEST&exp={expires}&sig={sig}",
                      headers=LECTEUR_RED)
    assert resp.status_code == 403


# --- 4. Aucune couche texte servie ----------------------------------------

def test_export_pdf_sans_couche_texte(client, doc_id):
    """Décision verrouillée §6.2 : le client ne reçoit que des pixels.

    Y compris le filigrane lui-même — sinon il serait détachable par un simple
    éditeur PDF, et l'attribution ne tiendrait plus.
    """
    import pymupdf
    resp = client.get(f"/api/export/{doc_id}.pdf", headers=LECTEUR_RED)
    assert resp.status_code == 200
    assert resp.mimetype == "application/pdf"
    with pymupdf.open(stream=resp.data, filetype="pdf") as doc:
        assert doc.page_count == 2
        for page in doc:
            assert page.get_text().strip() == ""
            assert len(page.get_images()) == 1


def test_export_journalise_distinctement(client, doc_id):
    client.get(f"/api/export/{doc_id}.pdf", headers=LECTEUR_RED)
    events = _journal_events()
    exports = [e for e in events if e["event"] == "document_export"]
    assert exports, "aucun document_export au journal"
    assert exports[-1]["actor"] == "lecteur.red"
    assert exports[-1]["version_hash"]


def test_rendu_depend_de_l_identite(client, doc_id):
    """Deux lecteurs ne reçoivent pas le même rendu : le filigrane attribue."""
    source = store.get_bytes(doc_id)
    a = render.render_page_png(source, 0, username="lecteur.red",
                               tlp="TLP:RED", view_id="aaaaaaaa-0000-4000-8000-000000000001",
                               timestamp="2026-01-01 00:00 UTC")
    b = render.render_page_png(source, 0, username="autre.red",
                               tlp="TLP:RED", view_id="aaaaaaaa-0000-4000-8000-000000000002",
                               timestamp="2026-01-01 00:00 UTC")
    assert a != b


def _rendus(doc_id):
    """(rendu nu, rendu marqué) de la page 1, mêmes dimensions."""
    import pymupdf
    source = store.get_bytes(doc_id)
    marque = render.render_page_png(source, 0, username="lecteur.red",
                                    tlp="TLP:RED", view_id="t-0001",
                                    timestamp="2026-01-01 00:00 UTC")
    with pymupdf.open(stream=source, filetype="pdf") as doc:
        nu = doc[0].get_pixmap(dpi=render.DPI, alpha=False)
    marque_pix = pymupdf.Pixmap(io.BytesIO(marque))
    assert (marque_pix.width, marque_pix.height) == (nu.width, nu.height)
    return nu, marque_pix


def _zone_modifiee(nu, marque, x0, y0, x1, y1) -> float:
    """Proportion de pixels d'une zone que le marquage a touchés."""
    total = touches = 0
    for y in range(int(y0), int(y1), 3):
        for x in range(int(x0), int(x1), 3):
            total += 1
            if marque.pixel(x, y) != nu.pixel(x, y):
                touches += 1
    return touches / max(total, 1)


def _rendu_pour(doc_id, username):
    """Rendu de la page 1 pour un compte donné — tout le reste identique."""
    import pymupdf
    png = render.render_page_png(
        store.get_bytes(doc_id), 0, username=username, tlp="TLP:RED",
        view_id="aaaaaaaa-0000-4000-8000-000000000001",
        timestamp="2026-01-01 00:00 UTC")
    return pymupdf.Pixmap(io.BytesIO(png))


ZONES = {
    "en-tête": (0.00, 0.000, 1.00, 0.030),
    "pied": (0.00, 0.970, 1.00, 1.000),
    "marge gauche": (0.00, 0.250, 0.03, 0.750),
    "marge droite": (0.97, 0.250, 1.00, 0.750),
    "centre": (0.25, 0.400, 0.75, 0.600),
}


def _zone_differe(a, b, bornes) -> bool:
    """Vrai si deux rendus diffèrent quelque part dans la zone."""
    x0, y0, x1, y1 = bornes
    for y in range(int(a.height * y0), int(a.height * y1), 2):
        for x in range(int(a.width * x0), int(a.width * x1), 2):
            if a.pixel(x, y) != b.pixel(x, y):
                return True
    return False


def test_chaque_ancrage_porte_l_identite(client, doc_id):
    """Chaque ancrage doit porter le COMPTE, pas seulement le niveau TLP.

    L'ancien test vérifiait que des pixels avaient changé dans cinq zones. Il
    passait alors que l'en-tête ne contenait que l'étiquette TLP et que le mode
    dense ne répétait que le niveau : des pixels « marqués » qui n'attribuaient
    rien (SEC-016).

    Celui-ci rend deux fois la même page, en ne changeant QUE le compte. Toute
    zone qui ne diffère pas ne porte pas l'identité — un extrait recadré sur
    cette zone sortirait anonyme.
    """
    a = _rendu_pour(doc_id, "lecteur.red")
    b = _rendu_pour(doc_id, "autre.lecteur")
    assert (a.width, a.height) == (b.width, b.height)

    muettes = [nom for nom, bornes in ZONES.items() if not _zone_differe(a, b, bornes)]
    assert not muettes, f"zones sans identité : {', '.join(muettes)}"


def test_mode_dense_porte_aussi_l_identite(client, doc_id, monkeypatch):
    """Le mode dense doit densifier l'ATTRIBUTION, pas répéter le niveau TLP.

    C'est le mode vendu comme réponse au recadrage : s'il ne répète que
    « TLP:RED », il ne tient pas cette promesse.
    """
    monkeypatch.setattr(render, "DENSITY", "dense")
    a = _rendu_pour(doc_id, "lecteur.red")
    b = _rendu_pour(doc_id, "autre.lecteur")

    # Bande intermédiaire, hors de tous les ancrages du mode discret.
    assert _zone_differe(a, b, (0.35, 0.70, 0.65, 0.88)), \
        "le mode dense ne porte pas l'identité hors des ancrages"


@pytest.mark.parametrize("tlp,attendu", [
    ("TLP:RED", (255, 43, 43)),            # #FF2B2B
    ("TLP:AMBER", (255, 192, 0)),          # #FFC000
    ("TLP:AMBER+STRICT", (255, 192, 0)),   # #FFC000
])
def test_etiquette_tlp_aux_couleurs_officielles(client, doc_id, tlp, attendu):
    """L'étiquette porte la couleur TLP officielle (FIRST, TLP 2.0).

    Ces couleurs sont définies pour un fond sombre — le jaune AMBER #FFC000
    disparaîtrait sur du blanc. L'étiquette est donc rendue comme le standard
    le prévoit : texte en couleur officielle sur pastille noire. Le test
    cherche cette couleur dans la bande d'en-tête.
    """
    import pymupdf
    png = render.render_page_png(store.get_bytes(doc_id), 0,
                                 username="lecteur.red", tlp=tlp,
                                 view_id="t-0001",
                                 timestamp="2026-01-01 00:00 UTC")
    pix = pymupdf.Pixmap(io.BytesIO(png))
    bande = int(pix.height * 0.03)
    trouve = any(
        all(abs(got - exp) <= 12 for got, exp in zip(pix.pixel(x, y), attendu))
        for y in range(0, bande)
        for x in range(int(pix.width * 0.5), pix.width)
    )
    assert trouve, f"couleur officielle {attendu} absente de l'étiquette {tlp}"


def test_marquage_reste_lisible_dans_le_corps_de_page(client, doc_id):
    """Le corps reste un rapport lisible, pas un brouillon filigrané.

    La marque centrale existe (test précédent) mais doit rester marginale :
    moins de 8 % des pixels du corps touchés, et aucun écart brutal — c'est
    ce qui sépare une mention pâle d'une tapisserie.
    """
    nu, marque = _rendus(doc_id)
    w, h = nu.width, nu.height

    corps = _zone_modifiee(nu, marque, w * 0.10, h * 0.10, w * 0.90, h * 0.90)
    assert corps < 0.08, f"corps de page trop recouvert : {corps:.1%}"

    ecart_max = 0
    for y in range(int(h * 0.10), int(h * 0.90), 5):
        for x in range(int(w * 0.10), int(w * 0.90), 5):
            a, b = nu.pixel(x, y), marque.pixel(x, y)
            ecart_max = max(ecart_max, max(abs(p - q) for p, q in zip(a, b)))
    assert ecart_max < 80, f"marquage trop opaque : écart max {ecart_max}/255"


# --- Preuve de l'artefact (SEC-014) ---------------------------------------

def test_export_journalise_un_manifeste_signe(client, doc_id):
    """Le ledger doit porter l'empreinte des octets SERVIS, pas de la source.

    Avant, seul le `version_hash` du dépôt était journalisé : face à un
    exemplaire retrouvé on pouvait corréler une consultation, pas vérifier que
    ces octets-là étaient ceux du serveur (SEC-014).
    """
    import manifest as mf

    resp = client.get(f"/api/export/{doc_id}.pdf", headers=LECTEUR_RED)
    assert resp.status_code == 200

    exports = [e for e in _journal_events() if e["event"] == "document_export"]
    entree = exports[-1]
    man, sig = entree["manifest"], entree["signature"]

    # L'empreinte journalisée est bien celle du PDF reçu.
    assert man["artifact_sha256"] == hashlib.sha256(resp.data).hexdigest()
    assert man["artifact_bytes"] == len(resp.data)
    assert man["kind"] == "export"
    assert man["actor"] == "lecteur.red"
    assert man["key_id"] == mf.KEY_ID
    assert mf.verify(man, sig) is True


def test_manifeste_altere_invalide_la_signature(client, doc_id):
    """Une preuve qui ne peut pas échouer ne prouve rien."""
    import manifest as mf
    client.get(f"/api/export/{doc_id}.pdf", headers=LECTEUR_RED)
    entree = [e for e in _journal_events() if e["event"] == "document_export"][-1]

    for champ, valeur in (("actor", "quelqu-un-dautre"),
                          ("artifact_sha256", "0" * 64),
                          ("tlp", "TLP:AMBER")):
        falsifie = dict(entree["manifest"], **{champ: valeur})
        assert mf.verify(falsifie, entree["signature"]) is False, champ


def test_preuve_verifiable_par_un_tiers(client, doc_id):
    """Un tiers vérifie hors ligne, avec la seule clé publique."""
    import manifest as mf

    export = client.get(f"/api/export/{doc_id}.pdf", headers=LECTEUR_RED)
    view_id = [e for e in _journal_events()
               if e["event"] == "document_export"][-1]["view_id"]

    preuve = client.get(f"/api/evidence/{view_id}", headers=LECTEUR_RED).get_json()
    pub = client.get("/api/pubkey").get_json()["public_key"]

    # Le tiers ne dispose que du fichier, du manifeste, de la signature et de
    # la clé publique — aucun accès au service.
    assert mf.verify(preuve["manifest"], preuve["signature"], pub) is True
    assert preuve["manifest"]["artifact_sha256"] == \
        hashlib.sha256(export.data).hexdigest()


def test_preuve_inaccessible_a_un_non_habilite(client, doc_id):
    client.get(f"/api/export/{doc_id}.pdf", headers=LECTEUR_RED)
    view_id = [e for e in _journal_events()
               if e["event"] == "document_export"][-1]["view_id"]
    assert client.get(f"/api/evidence/{view_id}",
                      headers=LECTEUR_AMBER).status_code == 404


def test_tuile_journalise_son_empreinte(client, doc_id):
    """Les tuiles ne sont pas signées, mais ce qui est montré est enregistré."""
    url = _tiles(client, doc_id, LECTEUR_RED)[0]
    resp = client.get(url, headers=LECTEUR_RED)
    servies = [e for e in _journal_events() if e["event"] == "tile_served"]
    assert servies[-1]["artifact_sha256"] == hashlib.sha256(resp.data).hexdigest()


# --- 5. Journalisation fail-closed ----------------------------------------

def test_journal_indisponible_bloque_la_diffusion(client, doc_id, monkeypatch):
    """Un accès non journalisable est un accès non attribuable, donc refusé."""
    def refuse(*_args, **_kwargs):
        raise OSError("journal en lecture seule")

    monkeypatch.setattr(wm.ledger, "append", refuse)
    assert client.get(f"/viewer/{doc_id}", headers=LECTEUR_RED).status_code == 503
    assert client.get(f"/api/export/{doc_id}.pdf",
                      headers=LECTEUR_RED).status_code == 503


def test_chaine_du_journal_intacte():
    """La chaîne de hachage reste valide après tous les tests ci-dessus."""
    segments = glob.glob(os.path.join(os.environ["SDOP_LEDGER_DIR"], "*.jsonl"))
    assert segments, "aucun segment de journal écrit"
    for path in segments:
        assert ledger.verify(path) is True


# --- 6. En-têtes de durcissement ------------------------------------------

def test_entetes_de_durcissement(client, doc_id):
    resp = client.get("/", headers=LECTEUR_RED)
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]


# --- Lot C : cycle de vie, chiffrement au repos, scellement ----------------

def _echoir(doc_id, jours=1):
    """Place l'échéance dans le passé, sans toucher au reste."""
    import db
    from datetime import datetime, timedelta, timezone
    db.connect().execute(
        "UPDATE documents SET expires_at=? WHERE doc_id=?",
        ((datetime.now(timezone.utc) - timedelta(days=jours)).isoformat(), doc_id))


def test_document_echu_invisible_de_tous(client, doc_id):
    """À l'échéance, l'accès cesse pour TOUS — émetteur compris (EX-5).

    Un document qui reste lisible par son auteur n'est pas retiré, et son
    scellement n'aurait pas de sens puisqu'il faudrait garder la clé en ligne.
    """
    assert client.get(f"/api/doc/{doc_id}", headers=LECTEUR_RED).status_code == 200
    _echoir(doc_id)
    for qui, entetes in (("destinataire", LECTEUR_RED), ("émetteur", EMETTEUR_RED)):
        assert client.get(f"/api/doc/{doc_id}", headers=entetes).status_code == 404, qui
        assert client.get(f"/viewer/{doc_id}", headers=entetes).status_code == 404, qui
    assert doc_id not in client.get("/", headers=EMETTEUR_RED).get_data(as_text=True)


def test_echeance_fait_foi_avant_le_balayage(client, doc_id):
    """La date refuse l'accès tout de suite, sans attendre le passage du balayage."""
    _echoir(doc_id)
    assert store.get_meta(doc_id)["state"] == "actif"   # pas encore balayé
    assert client.get(f"/viewer/{doc_id}", headers=LECTEUR_RED).status_code == 404


def test_prolongation_par_emetteur_avant_echeance(client, doc_id):
    avant = store.get_meta(doc_id)["expires_at"]
    resp = client.post(f"/api/prolonger/{doc_id}", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={"jours": 30})
    assert resp.status_code == 200
    assert resp.get_json()["expires_at"] > avant
    assert any(e["event"] == "document_extended" and e["doc_id"] == doc_id
               for e in _journal_events())


def test_prolongation_refusee_apres_echeance(client, doc_id):
    """Rouvrir après coup reviendrait à republier en silence."""
    _echoir(doc_id)
    resp = client.post(f"/api/prolonger/{doc_id}", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={"jours": 30})
    assert resp.status_code == 404      # le document n'est plus accessible


def test_prolongation_refusee_a_un_destinataire(client, doc_id):
    resp = client.post(f"/api/prolonger/{doc_id}", headers=LECTEUR_RED | {
        "Accept": "application/json"}, data={"jours": 30})
    assert resp.status_code == 403
    assert any(e["event"] == "extend_denied" for e in _journal_events())


def test_retrait_coupe_immediatement(client, doc_id):
    """Kill switch au niveau document : l'accès cesse pour tous, tout de suite."""
    assert client.get(f"/viewer/{doc_id}", headers=LECTEUR_RED).status_code == 200
    resp = client.post(f"/api/retirer/{doc_id}", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={"motif": "diffusion erronée"})
    assert resp.status_code == 200
    assert client.get(f"/viewer/{doc_id}", headers=LECTEUR_RED).status_code == 404
    assert client.get(f"/api/doc/{doc_id}", headers=EMETTEUR_RED).status_code == 404
    assert any(e["event"] == "document_withdrawn" and e["doc_id"] == doc_id
               for e in _journal_events())


def test_chiffrement_au_repos(client, monkeypatch):
    """Les octets sur disque ne doivent pas être lisibles tels quels (EX-8)."""
    import base64
    import sealing
    monkeypatch.setattr(sealing, "AT_REST_ENABLED", True)
    monkeypatch.setattr(sealing, "_SERVICE_KEY_B64",
                        base64.b64encode(os.urandom(32)).decode())

    marqueur = "TEXTE-TEMOIN-AU-REPOS"
    resp = client.post("/api/publish", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:RED", "document": (io.BytesIO(_pdf(1, text=marqueur)), "r.pdf"),
        "destinataires": "lecteur.red"})
    doc = resp.get_json()["doc_id"]

    chemin, _ = store._paths(doc, os.environ["SDOP_DOC_DIR"])
    sur_disque = open(chemin, "rb").read()
    assert sealing.is_encrypted(sur_disque)
    assert marqueur.encode() not in sur_disque
    assert not sur_disque.startswith(b"%PDF")

    # Et le service lit toujours, empreinte conforme.
    assert hashlib.sha256(store.get_bytes(doc)).hexdigest() == \
        resp.get_json()["version_hash"]


def test_scellement_deux_sur_deux(client, doc_id):
    """Ni l'un ni l'autre détenteur ne peut ouvrir seul (EX-7)."""
    import sealing
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    a, b, tiers = (X25519PrivateKey.generate() for _ in range(3))
    clair = store.get_bytes(doc_id)

    _echoir(doc_id)
    store.seal_document(doc_id, a.public_key(), b.public_key(),
                        os.environ["SDOP_DOC_DIR"])

    # Le service a perdu tout moyen de rouvrir.
    with pytest.raises(store.SealedDocument):
        store.get_bytes(doc_id)
    assert store.get_meta(doc_id)["state"] == "scelle"
    assert client.get(f"/viewer/{doc_id}", headers=LECTEUR_RED).status_code == 404

    chemin, _ = store._paths(doc_id, os.environ["SDOP_DOC_DIR"])
    scelle = open(chemin, "rb").read()
    assert sealing.is_sealed(scelle)

    # Une seule part, ou une clé tierce : refus.
    for nom, ka, kb in (("A seule", a, None), ("B seule", None, b),
                        ("A + tiers", a, tiers), ("tiers + B", tiers, b)):
        with pytest.raises(sealing.SealingError):
            sealing.unseal(scelle, ka, kb)

    # Les deux réunies : l'original, au bit près.
    assert sealing.unseal(scelle, a, b) == clair


def test_balayage_ne_ramasse_que_les_echus(client, doc_id):
    assert doc_id not in [d["doc_id"] for d in store.expired_documents()]
    _echoir(doc_id)
    assert doc_id in [d["doc_id"] for d in store.expired_documents()]
    assert doc_id not in [d["doc_id"] for d in store.expiring_soon(7)]


# --- Lot D : accès sans compte (EX-3) --------------------------------------

@pytest.fixture
def doc_amber(client):
    """Document AMBER diffusé — les liens sont interdits en RED."""
    resp = client.post("/api/publish", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:AMBER", "document": (io.BytesIO(_pdf(1)), "note-amber.pdf"),
        "destinataires": "lecteur.amber"})
    assert resp.status_code == 201, resp.get_data(as_text=True)
    return resp.get_json()["doc_id"]


def test_lien_interdit_en_tlp_red(client, doc_id):
    """TLP:RED exige un compte — jamais de lien (EX-3)."""
    resp = client.post(f"/api/lien/{doc_id}", headers=EMETTEUR_RED | {
        "Accept": "application/json"},
        data={"destinataire": "victime@exemple.invalid", "mode": "code"})
    assert resp.status_code == 400
    assert "jamais accessible par lien" in resp.get_json()["error"]
    assert any(e["event"] == "link_denied" for e in _journal_events())


def test_lien_code_ouvre_puis_ne_vaut_plus(client, doc_amber):
    """Le code ouvre une session, puis le lien est consommé."""
    emis = client.post(f"/api/lien/{doc_amber}", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"},
        data={"destinataire": "victime@exemple.invalid"}).get_json()
    assert emis["mode"] == "code"
    assert len(emis["code"]) == links.CODE_LEN
    assert emis["expires_in_hours"] == links.TTL_CODE_HOURS   # 96 h
    jeton = emis["url"].rsplit("/", 1)[-1]

    # Sans code : refus.
    assert client.post(f"/lien/{jeton}", data={"facteur": ""}).status_code == 403

    # Avec le code : session ouverte, document lisible sans aucun en-tête
    # d'identité — c'est tout l'objet du lien.
    ouverture = client.post(f"/lien/{jeton}", data={"facteur": emis["code"]})
    assert ouverture.status_code == 303
    assert client.get(f"/viewer/{doc_amber}").status_code == 200

    # Rejoué : le lien est consommé.
    client.delete_cookie("sdop_lien")
    rejeu = client.post(f"/lien/{jeton}", data={"facteur": emis["code"]})
    assert rejeu.status_code == 403
    assert "déjà utilisé" in rejeu.get_data(as_text=True)


def test_lien_verrouille_apres_cinq_essais(client, doc_amber):
    """Le verrouillage porte sur le LIEN, pas sur l'adresse IP."""
    emis = client.post(f"/api/lien/{doc_amber}", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"},
        data={"destinataire": "cible@exemple.invalid"}).get_json()
    jeton = emis["url"].rsplit("/", 1)[-1]

    for _ in range(links.MAX_ATTEMPTS):
        assert client.post(f"/lien/{jeton}",
                           data={"facteur": "MAUVAIS1"}).status_code == 403

    # Même le bon code ne passe plus.
    final = client.post(f"/lien/{jeton}", data={"facteur": emis["code"]})
    assert final.status_code == 403
    assert "verrouillé" in final.get_data(as_text=True)
    assert any(e["event"] == "link_failed" for e in _journal_events())


def test_lien_totp_exige_un_enrolement(client, doc_amber):
    emis = client.post(f"/api/lien/{doc_amber}", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"},
        data={"destinataire": "jamais.vu@exemple.invalid", "mode": "totp"})
    assert emis.status_code == 400
    assert "n'est pas enrôlé" in emis.get_json()["error"]


def test_lien_totp_apres_enrolement(client, doc_amber):
    """Mode A : un enrôlement par personne, puis chaque diffusion est automatique."""
    sujet = "correspondant@exemple.invalid"
    secret = client.post("/api/enroler", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"},
        data={"destinataire": sujet}).get_json()["totp_secret"]

    emis = client.post(f"/api/lien/{doc_amber}", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"},
        data={"destinataire": sujet, "mode": "totp"}).get_json()
    assert emis["code"] is None          # rien à dicter : le facteur est l'appli
    assert emis["expires_in_hours"] == links.TTL_TOTP_HOURS   # 72 h
    jeton = emis["url"].rsplit("/", 1)[-1]

    assert client.post(f"/lien/{jeton}",
                       data={"facteur": "000000"}).status_code == 403
    assert client.post(f"/lien/{jeton}",
                       data={"facteur": links.totp_now(secret)}).status_code == 303


def test_session_de_lien_revocable(client, doc_amber):
    """Kill switch : la révocation coupe à la requête suivante (EX-4)."""
    sujet = "a.couper@exemple.invalid"
    emis = client.post(f"/api/lien/{doc_amber}", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"}, data={"destinataire": sujet}).get_json()
    jeton = emis["url"].rsplit("/", 1)[-1]
    client.post(f"/lien/{jeton}", data={"facteur": emis["code"]})
    assert client.get(f"/viewer/{doc_amber}").status_code == 200

    client.post(f"/api/lien/{doc_amber}/revoquer", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"}, data={"destinataire": sujet})

    # Le cookie est toujours dans le navigateur ; la session, elle, ne vaut plus.
    assert client.get(f"/viewer/{doc_amber}").status_code == 401
    assert any(e["event"] == "link_revoked" for e in _journal_events())


def test_porteur_de_lien_ne_voit_que_son_document(client, doc_amber):
    """La session ouvre UN document, pas le niveau TLP."""
    autre = client.post("/api/publish", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:AMBER", "document": (io.BytesIO(_pdf(1)), "autre.pdf"),
        "destinataires": "quelqun.dautre"}).get_json()["doc_id"]

    emis = client.post(f"/api/lien/{doc_amber}", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"},
        data={"destinataire": "porteur@exemple.invalid"}).get_json()
    jeton = emis["url"].rsplit("/", 1)[-1]
    client.post(f"/lien/{jeton}", data={"facteur": emis["code"]})

    assert client.get(f"/viewer/{doc_amber}").status_code == 200
    assert client.get(f"/viewer/{autre}").status_code == 404


def test_porteur_de_lien_exporte_son_document(client, doc_amber):
    """L'export suit la session de lien comme la visionneuse — et ne l'étend pas."""
    autre = client.post("/api/publish", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:AMBER", "document": (io.BytesIO(_pdf(1)), "autre.pdf"),
        "destinataires": "quelqun.dautre"}).get_json()["doc_id"]

    emis = client.post(f"/api/lien/{doc_amber}", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"},
        data={"destinataire": "exporteur@exemple.invalid"}).get_json()
    jeton = emis["url"].rsplit("/", 1)[-1]
    client.post(f"/lien/{jeton}", data={"facteur": emis["code"]})

    page = client.get(f"/viewer/{doc_amber}").get_data(as_text=True)
    assert "Lien adressé à" in page and "exporteur@exemple.invalid" in page
    assert "Identité de confiance" not in page
    assert page.count(f"/api/export/{doc_amber}.pdf") == 2   # en haut et en bas

    r = client.get(f"/api/export/{doc_amber}.pdf")
    assert r.status_code == 200
    assert r.mimetype == "application/pdf"
    assert client.get(f"/api/export/{autre}.pdf").status_code == 404


def test_code_dicte_a_quarante_bits(client):
    """8 caractères sur un alphabet de 32 : 40 bits, dictables au téléphone."""
    assert links.CODE_LEN == 8
    assert len(links.ALPHABET) == 32
    for ambigu in "O0I1l":
        assert ambigu not in links.ALPHABET


# --- Lot E : kill switch et traçabilité (EX-4, EX-6) -----------------------

ADMIN = {
    "X-Authentik-Username": "admin.plateforme",
    "X-Authentik-Groups": "platform-admins",
    "X-Client-Cert-CN": "admin.plateforme",
    "X-Forwarded-For": "10.0.0.9",
}


def test_confinement_coupe_toute_diffusion(client, doc_id):
    """Dernier cran du kill switch : plus rien n'est servi, à personne."""
    assert client.get(f"/viewer/{doc_id}", headers=LECTEUR_RED).status_code == 200

    resp = client.post("/api/confinement", headers=ADMIN | {
        "Accept": "application/json"}, data={"actif": "1", "motif": "incident"})
    assert resp.status_code == 200

    for entetes in (LECTEUR_RED, EMETTEUR_RED, ADMIN):
        assert client.get(f"/viewer/{doc_id}", headers=entetes).status_code == 404
        assert client.get(f"/api/doc/{doc_id}", headers=entetes).status_code == 404

    # La publication reste possible : déposer pendant un incident sans diffuser.
    depot = client.post("/api/publish", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={
        "tlp": "TLP:RED", "document": (io.BytesIO(_pdf()), "pendant.pdf"),
        "destinataires": "lecteur.red"})
    assert depot.status_code == 201

    # Levée : tout revient.
    client.post("/api/confinement", headers=ADMIN | {"Accept": "application/json"},
                data={"actif": "0"})
    assert client.get(f"/viewer/{doc_id}", headers=LECTEUR_RED).status_code == 200
    evenements = {e["event"] for e in _journal_events()}
    assert {"containment_enabled", "containment_lifted"} <= evenements


def test_confinement_reserve_aux_administrateurs(client):
    resp = client.post("/api/confinement", headers=EMETTEUR_RED | {
        "Accept": "application/json"}, data={"actif": "1"})
    assert resp.status_code == 403
    assert any(e["event"] == "containment_denied" for e in _journal_events())
    assert store.containment_enabled() is False


def test_administrateur_ne_lit_pas_les_documents(client, doc_id):
    """platform-admins administre et ne lit pas (EX-2).

    Un administrateur n'a pas à consulter un TLP:RED pour gérer le service.
    """
    assert client.get(f"/api/doc/{doc_id}", headers=ADMIN).status_code == 404
    assert client.get(f"/viewer/{doc_id}", headers=ADMIN).status_code == 404


def test_siem_recoit_les_evenements(client, doc_id, tmp_path, monkeypatch):
    """Chaque geste part aussi vers le SIEM, avec une sévérité exploitable."""
    import siem
    chemin = tmp_path / "sdop-events.jsonl"
    monkeypatch.setattr(siem, "PATH", str(chemin))
    monkeypatch.setattr(siem, "ENABLED", True)

    client.get(f"/viewer/{doc_id}", headers=LECTEUR_RED)
    client.get(f"/api/doc/{doc_id}", headers=LECTEUR_AMBER)      # refus

    lignes = [json.loads(l) for l in chemin.read_text().splitlines() if l.strip()]
    par_evenement = {e["event"]: e for e in lignes}
    assert "document_access" in par_evenement
    assert par_evenement["document_access"]["severity"] == "info"
    assert par_evenement["document_access"]["ledger_hash"]
    assert par_evenement["access_denied"]["severity"] == "warning"
    assert all(e["product"] == "sdop" and e["@timestamp"] for e in lignes)


def test_siem_indisponible_ne_degrade_pas_le_service(client, doc_id, monkeypatch):
    """Un collecteur en panne ne doit jamais faire tomber SDOP.

    Sinon il suffirait de faire tomber le collecteur pour faire tomber le
    service : le SIEM deviendrait un levier de déni de service.
    """
    import siem
    monkeypatch.setattr(siem, "PATH", "/chemin/qui/n/existe/pas/events.jsonl")
    monkeypatch.setattr(siem, "ENABLED", True)
    assert client.get(f"/viewer/{doc_id}", headers=LECTEUR_RED).status_code == 200


def test_panne_de_ledger_remonte_au_siem(client, doc_id, tmp_path, monkeypatch):
    """Le ledger refuse, la requête échoue — et la détection le voit passer."""
    import siem
    chemin = tmp_path / "events.jsonl"
    monkeypatch.setattr(siem, "PATH", str(chemin))
    monkeypatch.setattr(siem, "ENABLED", True)
    monkeypatch.setattr(wm.ledger, "append",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("disque plein")))

    assert client.get(f"/viewer/{doc_id}", headers=LECTEUR_RED).status_code == 503
    lignes = [json.loads(l) for l in chemin.read_text().splitlines() if l.strip()]
    panne = [e for e in lignes if e["event"] == "ledger_unavailable"]
    assert panne and panne[0]["severity"] == "critical"
    assert "disque plein" in panne[0]["ledger_error"]


# --- Diffusion par courriel (2026-10-03) ----------------------------------

import re  # noqa: E402
import mailer  # noqa: E402


@pytest.fixture
def boite(monkeypatch):
    """Serveur SMTP simulé : capture les messages au lieu de les envoyer."""
    envoyes = []
    monkeypatch.setattr(mailer, "HOST", "mail.exemple.invalid")
    monkeypatch.setattr(mailer, "FROM", "npr@exemple.invalid")
    monkeypatch.setattr(mailer, "PUBLIC_URL", "https://sdop.exemple.invalid:8443")
    monkeypatch.setattr(mailer, "send", lambda msg: envoyes.append(msg) or "<id@test>")
    return envoyes


def test_publier_et_envoyer_le_lien(client, boite):
    """Un geste : publication AMBER, lien par adresse, courriel sans le code."""
    r = client.post("/api/publish", headers=EMETTEUR_AMBER, data={
        "tlp": "TLP:AMBER", "document": (io.BytesIO(_pdf(1)), "rapport.pdf"),
        "destinataires": "victime@exemple.invalid\ncompte.interne",
        "envoyer_lien": "1"})
    assert r.status_code == 200
    page = r.get_data(as_text=True)
    assert "Code à dicter" in page and "envoyé" in page

    assert len(boite) == 1                      # l'adresse seule, pas le compte
    msg = boite[0]
    corps = msg.get_content()
    assert msg["To"] == "victime@exemple.invalid"
    assert "https://sdop.exemple.invalid:8443/lien/" in corps
    code = re.search(r'class="code-lien">([A-Z0-9]+)<', page).group(1)
    assert code not in corps and code not in msg["Subject"]   # jamais le code
    assert "rapport.pdf" not in corps                          # ni le nom du fichier

    evts = [e["event"] for e in _journal_events()]
    assert "link_issued" in evts and "link_mailed" in evts


def test_echec_d_envoi_journalise_et_lien_conserve(client, boite, monkeypatch):
    def refus(msg):
        raise mailer.MailError("envoi refusé : test")
    monkeypatch.setattr(mailer, "send", refus)
    r = client.post("/api/publish", headers=EMETTEUR_AMBER, data={
        "tlp": "TLP:AMBER", "document": (io.BytesIO(_pdf(1)), "r.pdf"),
        "destinataires": "victime@exemple.invalid", "envoyer_lien": "1"})
    page = r.get_data(as_text=True)
    assert "échec" in page and "Code à dicter" in page   # le lien reste utilisable
    assert "link_mail_failed" in [e["event"] for e in _journal_events()]


def test_rouge_jamais_par_lien_meme_par_le_formulaire(client, boite):
    r = client.post("/api/publish", headers=EMETTEUR_RED, data={
        "tlp": "TLP:RED", "document": (io.BytesIO(_pdf(1)), "r.pdf"),
        "destinataires": "victime@exemple.invalid", "envoyer_lien": "1"})
    page = r.get_data(as_text=True)
    assert "Refusé" in page and "Code à dicter" not in page
    assert boite == []


def test_courriel_non_configure_le_dit(client, monkeypatch):
    monkeypatch.setattr(mailer, "HOST", "")
    r = client.post("/api/publish", headers=EMETTEUR_AMBER, data={
        "tlp": "TLP:AMBER", "document": (io.BytesIO(_pdf(1)), "r.pdf"),
        "destinataires": "victime@exemple.invalid", "envoyer_lien": "1"})
    assert "non configuré" in r.get_data(as_text=True)


def test_envoi_refuse_sans_ca(monkeypatch):
    """Jamais de STARTTLS sans vérification du certificat du serveur."""
    monkeypatch.setattr(mailer, "HOST", "mail.exemple.invalid")
    monkeypatch.setattr(mailer, "FROM", "npr@exemple.invalid")
    monkeypatch.setattr(mailer, "PUBLIC_URL", "https://x")
    monkeypatch.setattr(mailer, "CAFILE", "")
    with pytest.raises(mailer.MailError):
        mailer.send(mailer.build("a@exemple.invalid", "https://x/lien/t", "TLP:AMBER", 96))


def test_ca_introuvable_donne_un_echec_d_envoi_pas_une_500(client, monkeypatch):
    """Régression du 2026-10-03 : CA du serveur SMTP non montée → 500, code perdu."""
    monkeypatch.setattr(mailer, "HOST", "mail.exemple.invalid")
    monkeypatch.setattr(mailer, "FROM", "npr@exemple.invalid")
    monkeypatch.setattr(mailer, "PUBLIC_URL", "https://sdop.exemple.invalid:8443")
    monkeypatch.setattr(mailer, "CAFILE", "/secrets/introuvable.crt")
    r = client.post("/api/publish", headers=EMETTEUR_AMBER, data={
        "tlp": "TLP:AMBER", "document": (io.BytesIO(_pdf(1)), "r.pdf"),
        "destinataires": "victime@exemple.invalid", "envoyer_lien": "1"})
    page = r.get_data(as_text=True)
    assert r.status_code == 200
    assert "Code à dicter" in page and "échec" in page
    assert "link_mail_failed" in [e["event"] for e in _journal_events()]


# --- Fin de diffusion : retirer, sceller maintenant (2026-10-04) -----------

def test_sceller_maintenant_par_l_emetteur(client, doc_amber):
    r = client.post(f"/api/sceller/{doc_amber}", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"}, data={"motif": "fin de mission"})
    assert r.status_code == 200 and r.get_json()["state"] == "a_sceller"
    # Invisible tout de suite, pour tous (l'échéance fait foi sans balayage)…
    assert client.get(f"/viewer/{doc_amber}", headers=EMETTEUR_AMBER).status_code == 404
    # …et candidat au prochain balayage.
    assert doc_amber in [d["doc_id"] for d in store.expired_documents()]
    assert "seal_requested" in [e["event"] for e in _journal_events()]


def test_sceller_maintenant_refuse_a_un_autre(client, doc_amber):
    autre = {"X-Authentik-Username": "autre.amber", "X-Authentik-Groups":
             "tlp-amber-emetteurs", "X-Client-Cert-CN": "autre.amber",
             "X-Forwarded-For": "10.0.0.9", "Accept": "application/json"}
    assert client.post(f"/api/sceller/{doc_amber}", headers=autre).status_code in (403, 404)
    assert doc_amber not in [d["doc_id"] for d in store.expired_documents()]


def test_retire_puis_scelle_au_balayage(client, doc_amber):
    client.post(f"/api/retirer/{doc_amber}", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"}, data={"motif": "erreur de destinataire"})
    client.post(f"/api/sceller/{doc_amber}", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"})
    assert doc_amber in [d["doc_id"] for d in store.expired_documents()]


def test_boutons_fin_de_diffusion_visibles_de_l_emetteur_seul(client, doc_amber):
    page = client.get(f"/viewer/{doc_amber}", headers=EMETTEUR_AMBER).get_data(as_text=True)
    assert "Sceller maintenant" in page and "Retirer maintenant" in page
    emis = client.post(f"/api/lien/{doc_amber}", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"}, data={"destinataire": "p@exemple.invalid"}).get_json()
    client.post(f"/lien/{emis['url'].rsplit('/', 1)[-1]}", data={"facteur": emis["code"]})
    page = client.get(f"/viewer/{doc_amber}").get_data(as_text=True)
    assert "Sceller maintenant" not in page


def test_descellement_avec_cles_protegees_par_phrase(tmp_path, monkeypatch):
    """Les clés privées des détenteurs sont chiffrées : sdop-desceller les ouvre."""
    import importlib.util as iu
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    import sealing
    spec = iu.spec_from_file_location(
        "desceller", os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "sdop-desceller.py"))
    desc = iu.module_from_spec(spec); spec.loader.exec_module(desc)
    cles = {}
    for nom, phrase in (("a", b"phrase-analystes"), ("b", b"phrase-direction")):
        k = X25519PrivateKey.generate()
        (tmp_path / f"{nom}.pem").write_bytes(k.private_bytes(
            ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.BestAvailableEncryption(phrase)))
        cles[nom] = (k, phrase)
    scelle = sealing.seal(b"%PDF secret", cles["a"][0].public_key(), cles["b"][0].public_key())
    phrases = iter([cles["a"][1].decode(), cles["b"][1].decode()])
    monkeypatch.setattr("getpass.getpass", lambda *_: next(phrases))
    ka = desc.charger_privee(str(tmp_path / "a.pem"))
    kb = desc.charger_privee(str(tmp_path / "b.pem"))
    assert sealing.unseal(scelle, ka, kb) == b"%PDF secret"


def test_porteur_de_lien_ne_voit_pas_les_autres_destinataires(client):
    """Décision du 2026-10-04 : une victime ne doit pas apprendre qui sont les autres."""
    doc = client.post("/api/publish", headers=EMETTEUR_AMBER | {"Accept": "application/json"},
                      data={"tlp": "TLP:AMBER", "document": (io.BytesIO(_pdf(1)), "r.pdf"),
                            "destinataires": "mairie@exemple.invalid\nhopital@exemple.invalid"}
                      ).get_json()["doc_id"]
    # L'émetteur voit la liste.
    page = client.get(f"/viewer/{doc}", headers=EMETTEUR_AMBER).get_data(as_text=True)
    assert "mairie@exemple.invalid" in page and "hopital@exemple.invalid" in page
    # Le porteur de lien de la mairie ne voit pas l'hôpital.
    emis = client.post(f"/api/lien/{doc}", headers=EMETTEUR_AMBER | {"Accept": "application/json"},
                       data={"destinataire": "mairie@exemple.invalid"}).get_json()
    client.post(f"/lien/{emis['url'].rsplit('/', 1)[-1]}", data={"facteur": emis["code"]})
    page = client.get(f"/viewer/{doc}").get_data(as_text=True)
    assert "hopital@exemple.invalid" not in page
    assert "destinataires :" not in page
