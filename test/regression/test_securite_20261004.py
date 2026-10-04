"""
Non-régression des constats SEC-017 à SEC-025 d'un audit de sécurité
(rapport non publié).

Chaque test reproduit le scénario du rapport et exige le comportement corrigé.
Les tests existants ne couvraient pas ces cas précisément parce qu'ils posaient
la question d'à côté (un AUTRE destinataire pour SEC-018, des appels
séquentiels pour SEC-021) : ceux-ci posent la question du rapport.

Même application, mêmes identités simulées et même bac à sable que
test_watermark.py, dont les fixtures sont reprises telles quelles.
"""
import io
import threading

import pytest

from test_watermark import (EMETTEUR_AMBER, LECTEUR_AMBER, _journal_events,  # noqa: F401
                            _pdf, client, wm)

import db  # noqa: E402
import links  # noqa: E402
import store  # noqa: E402

JSON = {"Accept": "application/json"}

AUTRE_EMETTEUR_AMBER = {
    "X-Authentik-Username": "autre.emetteur.amber",
    "X-Authentik-Groups": "tlp-amber-emetteurs",
    "X-Client-Cert-CN": "autre.emetteur.amber",
    "X-Forwarded-For": "10.0.0.5",
}
ADMIN = {
    "X-Authentik-Username": "admin.plateforme",
    "X-Authentik-Groups": "platform-admins",
    "X-Client-Cert-CN": "admin.plateforme",
    "X-Forwarded-For": "10.0.0.9",
}


def _publier(client, destinataires="", emetteur=EMETTEUR_AMBER, nom="d.pdf"):
    r = client.post("/api/publish", headers=emetteur | JSON, data={
        "tlp": "TLP:AMBER", "document": (io.BytesIO(_pdf(1)), nom),
        "destinataires": destinataires})
    assert r.status_code == 201, r.get_data(as_text=True)
    return r.get_json()["doc_id"]


def _lien(client, doc_id, sujet, emetteur=EMETTEUR_AMBER, mode="code"):
    r = client.post(f"/api/lien/{doc_id}", headers=emetteur | JSON,
                    data={"destinataire": sujet, "mode": mode})
    assert r.status_code == 200, r.get_data(as_text=True)
    emis = r.get_json()
    return emis["url"].rsplit("/", 1)[-1], emis["code"]


def _ouvrir(client, jeton, facteur):
    return client.post(f"/lien/{jeton}", data={"facteur": facteur})


def _routes_document(doc_id):
    return [f"/viewer/{doc_id}", f"/api/doc/{doc_id}", f"/api/export/{doc_id}.pdf"]


# --- SEC-018 : une session de lien ne vaut que pour SON document -----------

def test_sec018_session_ne_s_etend_pas_au_document_du_meme_destinataire(client):
    """Même destinataire, même TLP, autre document : refusé sans son propre lien."""
    sujet = "victime.018@exemple.invalid"
    doc_a = _publier(client, sujet, nom="a.pdf")
    doc_b = _publier(client, sujet, nom="b.pdf")
    jeton, code = _lien(client, doc_a, sujet)
    _lien(client, doc_b, sujet)          # B est bien diffusé à cette personne
    assert _ouvrir(client, jeton, code).status_code == 303

    for url in _routes_document(doc_a):
        assert client.get(url).status_code == 200, url
    for url in _routes_document(doc_b):
        assert client.get(url).status_code == 404, url
    refus = [e for e in _journal_events()
             if e["event"] == "access_denied" and e.get("doc_id") == doc_b]
    assert refus and "portée" in refus[-1]["motif"]


def test_sec018_tuile_d_un_autre_document_refusee(client):
    """Les tuiles suivent la même portée que la visionneuse."""
    sujet = "tuile.018@exemple.invalid"
    doc_a = _publier(client, sujet)
    doc_b = _publier(client, sujet)
    jeton, code = _lien(client, doc_a, sujet)
    _ouvrir(client, jeton, code)
    # Une URL de tuile valablement signée pour ce sujet, mais sur B.
    import signing
    exp, sig = signing.sign(doc_b, 0, "v", sujet)
    r = client.get(f"/api/view/{doc_b}/page/0.png?view=v&exp={exp}&sig={sig}")
    assert r.status_code == 404


def test_sec018_retrait_du_document_d_origine_coupe_tout(client):
    """La session ne survit pas au retrait de A, ni ne se reporte sur B."""
    sujet = "retrait.018@exemple.invalid"
    doc_a = _publier(client, sujet)
    doc_b = _publier(client, sujet)
    jeton, code = _lien(client, doc_a, sujet)
    _ouvrir(client, jeton, code)
    client.post(f"/api/retirer/{doc_a}", headers=EMETTEUR_AMBER | JSON,
                data={"motif": "test"})
    for doc in (doc_a, doc_b):
        assert client.get(f"/viewer/{doc}").status_code == 404


def test_sec018_lien_vers_un_nom_de_compte_refuse(client):
    """Un lien porte une adresse ; jamais l'identité d'un compte du socle."""
    doc = _publier(client, "lecteur.amber")
    r = client.post(f"/api/lien/{doc}", headers=EMETTEUR_AMBER | JSON,
                    data={"destinataire": "lecteur.amber"})
    assert r.status_code == 400
    assert "adresse" in r.get_json()["error"]


def test_sec018_adresse_designee_comme_compte_refusee(client):
    """Un compte dont le nom est une adresse reste un compte : pas de lien."""
    doc = _publier(client)
    store.set_recipients(doc, [("compte@interne.invalid", "compte")], "test")
    r = client.post(f"/api/lien/{doc}", headers=EMETTEUR_AMBER | JSON,
                    data={"destinataire": "compte@interne.invalid"})
    assert r.status_code == 400
    assert "compte du socle" in r.get_json()["error"]


def test_sec018_porteur_n_herite_pas_du_statut_d_emetteur(client):
    """Une session dont le sujet porte le nom de l'émetteur ne lit pas ses documents."""
    emetteur = {**EMETTEUR_AMBER, "X-Authentik-Username": "emetteur@interne.invalid"}
    doc = _publier(client, emetteur=emetteur)
    # Lien émis directement par le module : le chemin HTTP n'inscrit pas ce
    # sujet comme destinataire, on vérifie la défense de l'autorisation.
    lien = links.issue(store.get_meta(doc), "emetteur@interne.invalid", "test")
    ouverture = links.redeem(lien["token"], lien["code"])
    client.set_cookie("sdop_lien", ouverture["session"])
    assert client.get(f"/viewer/{doc}").status_code == 404


# --- SEC-019 : pas de remplacement implicite du TOTP ----------------------

def test_sec019_second_enrolement_refuse_et_secret_intact(client):
    sujet = "corr.019@exemple.invalid"
    premier = client.post("/api/enroler", headers=EMETTEUR_AMBER | JSON,
                          data={"destinataire": sujet})
    assert premier.status_code == 200
    secret = premier.get_json()["totp_secret"]

    second = client.post("/api/enroler", headers=AUTRE_EMETTEUR_AMBER | JSON,
                         data={"destinataire": sujet})
    assert second.status_code == 409
    assert "totp_secret" not in second.get_json()
    assert links.correspondent(sujet)["totp_secret"] == secret
    assert any(e["event"] == "enrollment_denied" and e["subject"] == sujet
               for e in _journal_events())


def test_sec019_enrolement_d_un_nom_de_compte_refuse(client):
    r = client.post("/api/enroler", headers=EMETTEUR_AMBER | JSON,
                    data={"destinataire": "lecteur.amber"})
    assert r.status_code == 400


def test_sec019_reinitialisation_reservee_aux_administrateurs(client):
    sujet = "corr.reset.019@exemple.invalid"
    client.post("/api/enroler", headers=EMETTEUR_AMBER | JSON,
                data={"destinataire": sujet})
    avant = links.correspondent(sujet)["totp_secret"]
    for qui in (EMETTEUR_AMBER, AUTRE_EMETTEUR_AMBER):
        r = client.post("/api/correspondant/reinitialiser", headers=qui | JSON,
                        data={"destinataire": sujet, "motif": "perte"})
        assert r.status_code == 403
    assert links.correspondent(sujet)["totp_secret"] == avant


def test_sec019_reinitialisation_coupe_sessions_et_liens(client):
    sujet = "corr.reset2.019@exemple.invalid"
    ancien = client.post("/api/enroler", headers=EMETTEUR_AMBER | JSON,
                         data={"destinataire": sujet}).get_json()["totp_secret"]
    doc = _publier(client)
    jeton_utilise, _ = _lien(client, doc, sujet, mode="totp")
    assert _ouvrir(client, jeton_utilise, links.totp_now(ancien)).status_code == 303
    assert client.get(f"/viewer/{doc}").status_code == 200
    jeton_en_attente, _ = _lien(client, doc, sujet, mode="totp")

    sans_motif = client.post("/api/correspondant/reinitialiser", headers=ADMIN | JSON,
                             data={"destinataire": sujet})
    assert sans_motif.status_code == 400

    r = client.post("/api/correspondant/reinitialiser", headers=ADMIN | JSON,
                    data={"destinataire": sujet, "motif": "téléphone perdu"})
    assert r.status_code == 200
    nouveau = r.get_json()["totp_secret"]
    assert nouveau != ancien and r.get_json()["sessions_revoquees"] == 1

    assert client.get(f"/viewer/{doc}").status_code == 401        # session coupée
    client.delete_cookie("sdop_lien")
    assert _ouvrir(client, jeton_en_attente,
                   links.totp_now(nouveau)).status_code == 403    # lien coupé
    evt = [e for e in _journal_events() if e["event"] == "correspondent_reset"][-1]
    assert evt["actor"] == "admin.plateforme"
    assert evt["enrolled_by"] == "emetteur.amber"
    assert nouveau not in str(evt) and ancien not in str(evt)


# --- SEC-021 : consommation atomique, essais comptés, pas de rejeu --------

def _en_parallele(n, fonction):
    """Lance `fonction` dans n fils démarrés ensemble ; renvoie les résultats.

    Chaque fil a sa propre connexion SQLite (db.connect() est par fil), comme
    deux workers gunicorn ont chacun la leur.
    """
    depart = threading.Barrier(n)
    resultats = [None] * n

    def corps(i):
        depart.wait()
        try:
            resultats[i] = ("ok", fonction())
        except Exception as exc:              # noqa: BLE001
            resultats[i] = ("erreur", exc)
        finally:
            db.reset_for_tests()

    fils = [threading.Thread(target=corps, args=(i,)) for i in range(n)]
    for f in fils:
        f.start()
    for f in fils:
        f.join(30)
    return resultats


def test_sec021_lien_consomme_une_seule_fois_en_concurrence(client):
    doc = _publier(client)
    lien = links.issue(store.get_meta(doc), "course.021@exemple.invalid", "test")
    resultats = _en_parallele(8, lambda: links.redeem(lien["token"], lien["code"]))
    reussis = [r for r in resultats if r[0] == "ok"]
    assert len(reussis) == 1, resultats
    n = db.connect().execute(
        "SELECT COUNT(*) FROM link_sessions WHERE token_hash=?",
        (links._hash(lien["token"]),)).fetchone()[0]
    assert n == 1


def test_sec021_chaque_essai_concurrent_est_compte(client):
    doc = _publier(client)
    lien = links.issue(store.get_meta(doc), "force.021@exemple.invalid", "test")
    _en_parallele(4, lambda: links.redeem(lien["token"], "MAUVAIS1"))
    etat = links.get(lien["token"])
    assert etat["attempts"] == 4 and etat["state"] == "actif"
    _en_parallele(4, lambda: links.redeem(lien["token"], "MAUVAIS1"))
    etat = links.get(lien["token"])
    assert etat["attempts"] == links.MAX_ATTEMPTS and etat["state"] == "verrouille"


def test_sec021_code_totp_non_rejouable_sur_un_autre_lien(client):
    sujet = "rejeu.021@exemple.invalid"
    secret = links.enroll(sujet, "test")
    doc = _publier(client)
    j1, _ = _lien(client, doc, sujet, mode="totp")
    j2, _ = _lien(client, doc, sujet, mode="totp")
    code = links.totp_now(secret)
    assert _ouvrir(client, j1, code).status_code == 303
    client.delete_cookie("sdop_lien")
    assert _ouvrir(client, j2, code).status_code == 403


def test_sec021_session_morte_avec_son_lien(client):
    doc = _publier(client)
    lien = links.issue(store.get_meta(doc), "parent.021@exemple.invalid", "test")
    ouverture = links.redeem(lien["token"], lien["code"])
    assert links.session(ouverture["session"]) is not None
    # Lien révoqué sans que la session ait été marquée (écriture interrompue,
    # ordre inverse) : la session ne vaut plus.
    db.connect().execute("UPDATE links SET state='revoque' WHERE token_hash=?",
                         (links._hash(lien["token"]),))
    assert links.session(ouverture["session"]) is None


def test_sec021_journal_refuse_rien_n_est_consomme(client, monkeypatch):
    """Ouverture non journalisable : pas de session, le lien reste utilisable."""
    doc = _publier(client)
    jeton, code = _lien(client, doc, "journal.021@exemple.invalid")

    def refuse(*_a, **_k):
        raise OSError("journal en lecture seule")
    monkeypatch.setattr(wm.ledger, "append", refuse)
    assert _ouvrir(client, jeton, code).status_code == 503
    monkeypatch.undo()

    assert links.get(jeton)["state"] == "actif"
    assert db.connect().execute(
        "SELECT COUNT(*) FROM link_sessions WHERE token_hash=?",
        (links._hash(jeton),)).fetchone()[0] == 0
    assert _ouvrir(client, jeton, code).status_code == 303


# --- SEC-022 : la révocation documentaire reste dans son document ---------

def test_sec022_revocation_limitee_au_document(client):
    sujet = "deux.docs.022@exemple.invalid"
    doc_a = _publier(client, sujet)
    doc_b = _publier(client, sujet, emetteur=AUTRE_EMETTEUR_AMBER)
    ja, ca = _lien(client, doc_a, sujet)
    jb, cb = _lien(client, doc_b, sujet, emetteur=AUTRE_EMETTEUR_AMBER)
    sa = links.redeem(ja, ca)["session"]
    sb = links.redeem(jb, cb)["session"]

    r = client.post(f"/api/lien/{doc_a}/revoquer", headers=EMETTEUR_AMBER | JSON,
                    data={"destinataire": sujet})
    assert r.status_code == 200 and r.get_json()["sessions_revoquees"] == 1
    assert links.session(sa) is None
    assert links.session(sb) is not None        # l'autre émetteur n'est pas touché
    client.set_cookie("sdop_lien", sb)
    assert client.get(f"/viewer/{doc_b}").status_code == 200


def test_sec022_revocation_globale_reservee_aux_administrateurs(client):
    sujet = "global.022@exemple.invalid"
    doc = _publier(client, sujet)
    j, c = _lien(client, doc, sujet)
    s = links.redeem(j, c)["session"]

    r = client.post("/api/correspondant/revoquer", headers=EMETTEUR_AMBER | JSON,
                    data={"destinataire": sujet})
    assert r.status_code == 403
    assert links.session(s) is not None

    r = client.post("/api/correspondant/revoquer", headers=ADMIN | JSON,
                    data={"destinataire": sujet, "motif": "compromission"})
    assert r.status_code == 200 and r.get_json()["sessions_revoquees"] == 1
    assert links.session(s) is None
    assert any(e["event"] == "link_revoked_all" and e["subject"] == sujet
               for e in _journal_events())


def test_sec022_revocation_sans_destinataire_refusee(client):
    doc = _publier(client)
    r = client.post(f"/api/lien/{doc}/revoquer", headers=EMETTEUR_AMBER | JSON,
                    data={})
    assert r.status_code == 400


# --- Schéma : une base d'avant la correction est mise à niveau ------------

def test_migration_base_existante(tmp_path, monkeypatch):
    """La base de production a été créée sans `totp_last_step`."""
    import sqlite3
    chemin = tmp_path / "ancienne.sqlite"
    cx = sqlite3.connect(chemin)
    cx.execute("CREATE TABLE correspondents (subject TEXT PRIMARY KEY,"
               " totp_secret TEXT, enrolled_at TEXT, created_by TEXT NOT NULL,"
               " created_at TEXT NOT NULL)")
    cx.execute("INSERT INTO correspondents VALUES ('a@b.invalid','X','t','u','t')")
    cx.commit()
    cx.close()

    monkeypatch.setattr(db, "DB_PATH", str(chemin))
    db.reset_for_tests()
    try:
        colonnes = {r[1] for r in db.connect().execute(
            "PRAGMA table_info(correspondents)")}
        assert "totp_last_step" in colonnes
        assert links.correspondent("a@b.invalid")["totp_secret"] == "X"
    finally:
        db.reset_for_tests()


# --- SEC-017 : un dépôt refusé n'existe nulle part -----------------------

import os  # noqa: E402

import render  # noqa: E402
from test_watermark import _pdf_geant  # noqa: E402


def _empreinte_stockage():
    # Documents seulement : la base SQLite vit dans le même dossier, et ses
    # fichiers WAL apparaissent et disparaissent au gré des connexions.
    fichiers = sorted(n for n in os.listdir(store.DOC_DIR)
                      if not n.startswith("sdop.sqlite")) \
        if os.path.isdir(store.DOC_DIR) else []
    lignes = db.connect().execute("SELECT COUNT(*) FROM documents").fetchone()[0]
    return fichiers, lignes


def test_sec017_depot_hors_budget_sans_aucune_trace(client, monkeypatch):
    monkeypatch.setattr(render, "MAX_PAGES", 10)
    avant = _empreinte_stockage()
    r = client.post("/api/publish", headers=EMETTEUR_AMBER | JSON, data={
        "tlp": "TLP:AMBER", "document": (io.BytesIO(_pdf_geant(50)), "gros.pdf")})
    assert r.status_code == 400
    assert _empreinte_stockage() == avant          # ni ligne, ni fichier
    index = client.get("/", headers=EMETTEUR_AMBER).get_data(as_text=True)
    assert "gros.pdf" not in index
    assert not any(e["event"] == "document_publish"
                   and e.get("original_name") == "gros.pdf" for e in _journal_events())


def test_sec017_pdf_illisible_sans_aucune_trace(client):
    avant = _empreinte_stockage()
    r = client.post("/api/publish", headers=EMETTEUR_AMBER | JSON, data={
        "tlp": "TLP:AMBER",
        "document": (io.BytesIO(b"%PDF-1.4 tronque"), "casse.pdf")})
    assert r.status_code == 400
    assert _empreinte_stockage() == avant


def test_sec017_budget_reverifie_au_rendu(client, monkeypatch):
    """Un document admis puis devenu hors budget n'est pas rasterisé."""
    doc = _publier(client)
    monkeypatch.setattr(render, "MAX_PAGE_PIXELS", 10)
    appels = []
    monkeypatch.setattr(render.pymupdf.Page, "get_pixmap",
                        lambda *a, **k: appels.append(1))
    page = client.get(f"/viewer/{doc}", headers=EMETTEUR_AMBER)
    assert page.status_code == 200      # la visionneuse ne rend rien elle-même
    import re as _re
    tuile = _re.search(r'src="(/api/view/[^"]+)"', page.get_data(as_text=True)).group(1)
    assert client.get(tuile.replace("&amp;", "&"),
                      headers=EMETTEUR_AMBER).status_code == 500
    assert client.get(f"/api/export/{doc}.pdf",
                      headers=EMETTEUR_AMBER).status_code == 500
    assert appels == []                 # aucune allocation de rendu


# --- SEC-024 : un refus du journal annule la mutation ---------------------

@pytest.fixture
def journal_en_panne(monkeypatch):
    """Active la panne du journal à la demande : `journal_en_panne()`."""
    def activer():
        def refuse(*_a, **_k):
            raise OSError("journal en lecture seule")
        monkeypatch.setattr(wm.ledger, "append", refuse)
    return activer


def test_sec024_publication_annulee_si_journal_refuse(client, journal_en_panne):
    avant = _empreinte_stockage()
    journal_en_panne()
    r = client.post("/api/publish", headers=EMETTEUR_AMBER | JSON, data={
        "tlp": "TLP:AMBER", "document": (io.BytesIO(_pdf(1)), "x.pdf")})
    assert r.status_code == 503
    assert _empreinte_stockage() == avant
    assert len(store.list_docs()) == avant[1]     # pas de sidecar ressuscité


def test_sec024_retrait_annule(client, journal_en_panne):
    doc = _publier(client)
    journal_en_panne()
    r = client.post(f"/api/retirer/{doc}", headers=EMETTEUR_AMBER | JSON,
                    data={"motif": "x"})
    assert r.status_code == 503
    assert store.get_meta(doc)["state"] == "actif"


def test_sec024_scellement_demande_annule(client, journal_en_panne):
    doc = _publier(client)
    avant = store.get_meta(doc)["expires_at"]
    journal_en_panne()
    assert client.post(f"/api/sceller/{doc}", headers=EMETTEUR_AMBER | JSON,
                       data={"motif": "x"}).status_code == 503
    assert store.get_meta(doc)["expires_at"] == avant


def test_sec024_prolongation_annulee(client, journal_en_panne):
    doc = _publier(client)
    avant = store.get_meta(doc)["expires_at"]
    journal_en_panne()
    assert client.post(f"/api/prolonger/{doc}", headers=EMETTEUR_AMBER | JSON,
                       data={"jours": 3}).status_code == 503
    assert store.get_meta(doc)["expires_at"] == avant


def test_sec024_levee_de_confinement_annulee(client, journal_en_panne, monkeypatch):
    assert client.post("/api/confinement", headers=ADMIN | JSON,
                       data={"actif": "1", "motif": "test"}).status_code == 200
    try:
        journal_en_panne()
        r = client.post("/api/confinement", headers=ADMIN | JSON,
                        data={"actif": "0", "motif": "test"})
        assert r.status_code == 503
        assert store.containment_enabled() is True    # la levée n'a pas eu lieu
    finally:
        monkeypatch.undo()
        store.set_containment(False, "test")


def test_sec024_emission_de_lien_annulee(client, journal_en_panne):
    doc = _publier(client)
    journal_en_panne()
    r = client.post(f"/api/lien/{doc}", headers=EMETTEUR_AMBER | JSON,
                    data={"destinataire": "annule.024@exemple.invalid"})
    assert r.status_code == 503
    assert db.connect().execute("SELECT COUNT(*) FROM links WHERE doc_id=?",
                                (doc,)).fetchone()[0] == 0
    assert store.recipients_of(doc) == []


def test_sec024_enrolement_annule(client, journal_en_panne):
    journal_en_panne()
    r = client.post("/api/enroler", headers=EMETTEUR_AMBER | JSON,
                    data={"destinataire": "annule.enr.024@exemple.invalid"})
    assert r.status_code == 503
    assert links.correspondent("annule.enr.024@exemple.invalid") is None


def test_sec024_revocation_annulee(client, journal_en_panne):
    sujet = "annule.rev.024@exemple.invalid"
    doc = _publier(client, sujet)
    j, c = _lien(client, doc, sujet)
    s = links.redeem(j, c)["session"]
    journal_en_panne()
    assert client.post(f"/api/lien/{doc}/revoquer", headers=EMETTEUR_AMBER | JSON,
                       data={"destinataire": sujet}).status_code == 503
    assert links.session(s) is not None


def test_sec024_reinitialisation_annulee(client, journal_en_panne):
    sujet = "annule.reset.024@exemple.invalid"
    secret = links.enroll(sujet, "test")
    journal_en_panne()
    assert client.post("/api/correspondant/reinitialiser", headers=ADMIN | JSON,
                       data={"destinataire": sujet, "motif": "x"}).status_code == 503
    assert links.correspondent(sujet)["totp_secret"] == secret


def test_sec024_motif_hors_borne_refuse_avant_ecriture(client):
    doc = _publier(client)
    r = client.post(f"/api/retirer/{doc}", headers=EMETTEUR_AMBER | JSON,
                    data={"motif": "x" * (wm.MAX_MOTIF + 1)})
    assert r.status_code == 400
    assert store.get_meta(doc)["state"] == "actif"


def test_sec024_entree_de_journal_trop_longue_annule_la_publication(client):
    """Liste de destinataires dépassant la borne du journal : 400, rien d'écrit."""
    avant = _empreinte_stockage()
    beaucoup = "\n".join(f"{'d' * 200}{i}@exemple.invalid" for i in range(60))
    r = client.post("/api/publish", headers=EMETTEUR_AMBER | JSON, data={
        "tlp": "TLP:AMBER", "document": (io.BytesIO(_pdf(1)), "liste.pdf"),
        "destinataires": beaucoup})
    assert r.status_code == 400
    assert "rien n'a été modifié" in r.get_json()["error"]
    assert _empreinte_stockage() == avant


# --- SEC-020 : provenance des requêtes qui modifient ----------------------

def _routes_post():
    """Toutes les routes POST de l'application, arguments remplis au hasard.

    Énumérées depuis l'application elle-même : une route ajoutée demain est
    vérifiée sans qu'on pense à l'ajouter ici.
    """
    valeurs = {"doc_id": "0" * 32, "token": "jeton-inexistant", "page": 0,
               "view_id": "v"}
    routes = []
    for regle in wm.app.url_map.iter_rules():
        if "POST" not in regle.methods:
            continue
        chemin = regle.rule
        for nom in regle.arguments:
            chemin = chemin.replace(f"<{nom}>", str(valeurs[nom])) \
                           .replace(f"<int:{nom}>", str(valeurs[nom]))
        routes.append(chemin)
    return routes


def test_sec020_il_existe_des_routes_post():
    """Garde-fou du test suivant : il ne doit pas passer à vide."""
    routes = _routes_post()
    assert "/api/publish" in routes and "/lien/jeton-inexistant" in routes
    assert len(routes) >= 11


#: Émetteur ET administrateur : sans le contrôle de provenance, chaque route
#: irait au bout de son traitement — le 403 attendu ne peut venir que de lui.
ADMIN_GROUPES = {"X-Authentik-Groups": "tlp-amber-emetteurs|platform-admins"}


@pytest.mark.parametrize("entetes", [
    {"Origin": "https://voisin.example.org"},
    {"Origin": "https://attaquant.exemple.invalid"},
    {"Origin": "null", "Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site", "Origin": "https://voisin.example.org"},
    {"Sec-Fetch-Site": "same-origin", "Origin": "https://voisin.example.org"},
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},
    {"Referer": "https://voisin.example.org/formulaire"},
], ids=["origine-voisine", "origine-tierce", "null+cross-site", "same-site+origine",
        "same-origin+origine-contradictoire", "cross-site", "same-site",
        "referer-voisin"])
def test_sec020_toute_route_post_refuse_une_autre_origine(client, entetes):
    for chemin in _routes_post():
        r = client.post(chemin, headers=EMETTEUR_AMBER | ADMIN_GROUPES | entetes,
                        data={"motif": "x", "destinataire": "a@b.invalid"})
        assert r.status_code == 403, chemin
        assert "provenance" in r.get_data(as_text=True), chemin


def test_sec020_meme_origine_acceptee_port_public_compris(client):
    """nginx transmet `Host` sans port ; le navigateur annonce :8443."""
    for origine in ("https://localhost", "https://localhost:8443"):
        r = client.post("/api/publish",
                        headers=EMETTEUR_AMBER | JSON | {
                            "Origin": origine, "Sec-Fetch-Site": "same-origin"},
                        data={"tlp": "TLP:AMBER",
                              "document": (io.BytesIO(_pdf(1)), "o.pdf")})
        assert r.status_code == 201, (origine, r.get_data(as_text=True))


def test_sec020_navigateur_reel_avec_no_referrer_accepte(client):
    """Ce qu'envoie VRAIMENT un navigateur sur nos formulaires.

    Nos pages portent `Referrer-Policy: no-referrer` : la spécification Fetch
    fait alors envoyer `Origin: null` sur un POST, même vers sa propre origine.
    Sans ce test, le contrôle de provenance pouvait refuser tous les
    formulaires réels en passant tous les autres tests.
    """
    navigateur = {"Origin": "null", "Sec-Fetch-Site": "same-origin",
                  "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
    r = client.post("/api/publish", headers=EMETTEUR_AMBER | navigateur, data={
        "tlp": "TLP:AMBER", "document": (io.BytesIO(_pdf(1)), "nav.pdf"),
        "destinataires": "nav.020@exemple.invalid"})
    assert r.status_code in (200, 303), r.get_data(as_text=True)
    doc = _publier(client)
    jeton, code = _lien(client, doc, "nav2.020@exemple.invalid")
    assert client.post(f"/lien/{jeton}", data={"facteur": code},
                       headers=navigateur).status_code == 303


def test_sec020_navigateur_ancien_origin_null(client):
    """Sans Sec-Fetch-Site : « null » toléré sur la saisie du facteur seulement."""
    doc = _publier(client)
    jeton, code = _lien(client, doc, "ancien.020@exemple.invalid")
    assert client.post(f"/lien/{jeton}", data={"facteur": code},
                       headers={"Origin": "null"}).status_code == 303
    r = client.post("/api/publish", headers=EMETTEUR_AMBER | {"Origin": "null"},
                    data={"tlp": "TLP:AMBER",
                          "document": (io.BytesIO(_pdf(1)), "x.pdf")})
    assert r.status_code == 403 and "provenance" in r.get_data(as_text=True)


def test_sec020_client_non_navigateur_accepte(client):
    """Sans Origin ni Sec-Fetch-Site : pas un navigateur, pas de CSRF possible."""
    r = client.post("/api/publish", headers=EMETTEUR_AMBER | JSON, data={
        "tlp": "TLP:AMBER", "document": (io.BytesIO(_pdf(1)), "cli.pdf")})
    assert r.status_code == 201


def test_sec020_ouverture_de_lien_imposee_refusee(client):
    """Ouverture de session forcée avec les justificatifs d'un tiers."""
    doc = _publier(client)
    jeton, code = _lien(client, doc, "imposee.020@exemple.invalid")
    r = client.post(f"/lien/{jeton}", data={"facteur": code},
                    headers={"Origin": "https://attaquant.exemple.invalid"})
    assert r.status_code == 403
    assert "sdop_lien" not in r.headers.get("Set-Cookie", "")
    assert links.get(jeton)["state"] == "actif"        # rien de consommé


# --- SEC-023 : aucune réponse conservable par un cache --------------------

def test_sec023_reponses_sensibles_non_stockables(client):
    doc = _publier(client)
    emis = client.post(f"/api/lien/{doc}", headers=EMETTEUR_AMBER,
                       data={"destinataire": "cache.023@exemple.invalid"})
    reponses = {
        "index": client.get("/", headers=EMETTEUR_AMBER),
        "visionneuse": client.get(f"/viewer/{doc}", headers=EMETTEUR_AMBER),
        "diffusion (code + lien)": emis,
        "enrôlement (secret)": client.post(
            "/api/enroler", headers=EMETTEUR_AMBER | JSON,
            data={"destinataire": "cache.enr.023@exemple.invalid"}),
        "métadonnées": client.get(f"/api/doc/{doc}", headers=EMETTEUR_AMBER),
        "page de lien": client.get("/lien/quelconque"),
        "erreur": client.get(f"/viewer/{'f' * 32}", headers=EMETTEUR_AMBER),
    }
    assert emis.status_code == 200
    for nom, r in reponses.items():
        assert "no-store" in r.headers.get("Cache-Control", ""), nom


# --- SEC-025 : secrets TOTP chiffrés en base ------------------------------

@pytest.fixture
def chiffrement(monkeypatch):
    import base64
    import os as _os
    import sealing
    monkeypatch.setattr(sealing, "AT_REST_ENABLED", True)
    monkeypatch.setattr(sealing, "_SERVICE_KEY_B64",
                        base64.b64encode(_os.urandom(32)).decode())


def _brut(sujet):
    return db.connect().execute(
        "SELECT totp_secret FROM correspondents WHERE subject=?",
        (sujet,)).fetchone()[0]


def test_sec025_secret_chiffre_en_base_et_utilisable(client, chiffrement):
    sujet = "chiffre.025@exemple.invalid"
    secret = client.post("/api/enroler", headers=EMETTEUR_AMBER | JSON,
                         data={"destinataire": sujet}).get_json()["totp_secret"]
    brut = _brut(sujet)
    assert brut.startswith("enc1:") and secret not in brut
    doc = _publier(client)
    jeton, _ = _lien(client, doc, sujet, mode="totp")
    assert _ouvrir(client, jeton, links.totp_now(secret)).status_code == 303


def test_sec025_chiffre_lie_a_son_correspondant(client, chiffrement):
    """Recopier le chiffré d'une ligne sur une autre ne donne rien."""
    import sealing
    links.enroll("a.025@exemple.invalid", "test")
    links.enroll("b.025@exemple.invalid", "test")
    db.connect().execute("UPDATE correspondents SET totp_secret=? WHERE subject=?",
                         (_brut("a.025@exemple.invalid"), "b.025@exemple.invalid"))
    with pytest.raises(sealing.SealingError):
        links.correspondent("b.025@exemple.invalid")


def test_sec025_secrets_en_clair_chiffres_au_demarrage(client, chiffrement):
    """Base d'avant la correction : secret en clair, repris tel quel."""
    sujet = "ancien.025@exemple.invalid"
    secret = links.generate_totp_secret()
    db.connect().execute(
        "INSERT INTO correspondents (subject, totp_secret, enrolled_at,"
        " created_by, created_at) VALUES (?,?,?,?,?)",
        (sujet, secret, "t", "test", "t"))
    assert links.correspondent(sujet)["totp_secret"] == secret     # lu en clair
    assert links.encrypt_plaintext_secrets() >= 1
    assert _brut(sujet).startswith("enc1:")
    assert links.correspondent(sujet)["totp_secret"] == secret
    assert links.encrypt_plaintext_secrets() == 0                   # idempotent


def test_sec025_sante_annonce_l_etat(client):
    assert "totp_secrets_encrypted" in client.get("/health").get_json()


# --- Suites de la revue : robustesse des transactions ---------------------

def test_commit_refuse_ne_laisse_pas_la_connexion_en_transaction(client, monkeypatch):
    """Un COMMIT en échec doit annuler, sinon le worker garde le verrou."""
    import sqlite3
    cx = db.connect()

    class Connexion:
        def __getattr__(self, nom):
            return getattr(cx, nom)

        def execute(self, sql, *a):
            if sql == "COMMIT":
                raise sqlite3.OperationalError("disk I/O error (simulé)")
            return cx.execute(sql, *a)

    monkeypatch.setattr(db, "connect", lambda: Connexion())
    with pytest.raises(sqlite3.OperationalError):
        with db.transaction() as c:
            c.execute("INSERT INTO settings (key, value) VALUES ('t_commit', '1')")
    monkeypatch.undo()
    assert not cx.in_transaction
    assert cx.execute("SELECT 1 FROM settings WHERE key='t_commit'").fetchone() is None


def test_depot_dont_l_enregistrement_echoue_ne_laisse_pas_de_fichier(client, monkeypatch):
    avant = _empreinte_stockage()
    import sqlite3

    def casse(*_a, **_k):
        raise sqlite3.OperationalError("database is locked (simulé)")
    cx = db.connect()

    class Connexion:
        def __getattr__(self, nom):
            return getattr(cx, nom)

        def execute(self, sql, *a):
            if sql.startswith("INSERT INTO documents"):
                casse()
            return cx.execute(sql, *a)
    monkeypatch.setattr(db, "connect", lambda: Connexion())
    with pytest.raises(sqlite3.OperationalError):
        store.put(_pdf(1), tlp="TLP:AMBER", original_name="x.pdf", actor="t")
    monkeypatch.undo()
    assert _empreinte_stockage() == avant


def test_rejeu_totp_message_explicite(client):
    sujet = "rejeu.msg@exemple.invalid"
    secret = links.enroll(sujet, "test")
    doc = _publier(client)
    j1, _ = _lien(client, doc, sujet, mode="totp")
    j2, _ = _lien(client, doc, sujet, mode="totp")
    code = links.totp_now(secret)
    _ouvrir(client, j1, code)
    client.delete_cookie("sdop_lien")
    r = _ouvrir(client, j2, code)
    assert r.status_code == 403 and "déjà utilisé" in r.get_data(as_text=True)


def test_prolongation_refuse_un_booleen(client):
    doc = _publier(client)
    r = client.post(f"/api/prolonger/{doc}", headers=EMETTEUR_AMBER | JSON,
                    json={"jours": True})
    assert r.status_code == 400


# --- Déconnexion et enrôlement TOTP outillé (2026-10-04) ------------------

def test_lien_deconnexion_visible_aux_comptes(client):
    page = client.get("/", headers=EMETTEUR_AMBER).get_data(as_text=True)
    assert 'href="/outpost.goauthentik.io/sign_out"' in page
    doc = _publier(client)
    page = client.get(f"/viewer/{doc}", headers=EMETTEUR_AMBER).get_data(as_text=True)
    assert "Se déconnecter" in page


def test_porteur_quitte_sa_session(client):
    sujet = "quitte@exemple.invalid"
    doc = _publier(client, sujet)
    jeton, code = _lien(client, doc, sujet)
    _ouvrir(client, jeton, code)
    page = client.get(f"/viewer/{doc}").get_data(as_text=True)
    assert 'action="/lien/quitter"' in page and "sign_out" not in page
    session = client.get_cookie("sdop_lien").value

    r = client.post("/lien/quitter", headers={"Origin": "null",
                                              "Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 200 and "Session fermée" in r.get_data(as_text=True)
    assert links.session(session) is None              # révoquée côté serveur
    client.set_cookie("sdop_lien", session)            # cookie recopié : sans effet
    assert client.get(f"/viewer/{doc}").status_code == 401
    assert any(e["event"] == "link_session_closed" and e["actor"] == sujet
               for e in _journal_events())


def test_quitter_sans_session_ne_casse_rien(client):
    assert client.post("/lien/quitter").status_code == 200


def test_enrolement_par_formulaire_affiche_secret_et_qr(client):
    sujet = "formulaire.totp@exemple.invalid"
    r = client.post("/api/enroler", headers=EMETTEUR_AMBER,
                    data={"destinataire": sujet})
    assert r.status_code == 200
    page = r.get_data(as_text=True)
    assert "<svg" in page and "ne sera plus jamais affiché" in page
    import re as _re
    groupes = _re.search(r'class="code-lien">([A-Z2-7 ]+)<', page).group(1)
    secret = groupes.replace(" ", "")
    assert links.correspondent(sujet)["totp_secret"] == secret
    assert "no-store" in r.headers["Cache-Control"]
    assert secret not in str(_journal_events())        # jamais journalisé


def test_uri_otpauth_conforme():
    uri = links.otpauth_uri("A@B.invalid", "JBSWY3DPEHPK3PXP")
    assert uri.startswith("otpauth://totp/SDOP%20cybeR%C3%A9ponse:a%40b.invalid?")
    for p in ("secret=JBSWY3DPEHPK3PXP", "issuer=SDOP%20cybeR%C3%A9ponse",
              "algorithm=SHA1", "digits=6", "period=30"):
        assert p in uri


def test_lien_totp_emis_par_le_formulaire_de_la_visionneuse(client):
    sujet = "visionneuse.totp@exemple.invalid"
    secret = links.enroll(sujet, "test")
    doc = _publier(client)
    page = client.get(f"/viewer/{doc}", headers=EMETTEUR_AMBER).get_data(as_text=True)
    assert '<option value="totp">' in page
    r = client.post(f"/api/lien/{doc}", headers=EMETTEUR_AMBER,
                    data={"destinataire": sujet, "mode": "totp"})
    assert r.status_code == 200
    page = r.get_data(as_text=True)
    import re as _re
    assert "Code à dicter" not in page and "None" not in page
    assert "application TOTP du correspondant" in page
    jeton = _re.search(r"/lien/([A-Za-z0-9_-]{20,})", page).group(1)
    assert _ouvrir(client, jeton, links.totp_now(secret)).status_code == 303
