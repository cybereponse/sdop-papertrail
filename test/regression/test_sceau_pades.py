"""
Sceau PAdES des exports (watermark/pades.py).

Le destinataire ne reçoit jamais le PDF source : chaque export est re-rastérisé
avec un filigrane nominatif (§6.2). Une signature posée sur l'original ne
survivrait donc pas ; le sceau se pose sur CHAQUE export, après le rendu et
avant le manifeste, pour que l'empreinte journalisée couvre les octets scellés.

Ce que ces tests exigent :
1. tout export sort scellé — validable, intact, couvrant le fichier entier,
   certifié « aucune modification » — y compris pour un porteur de lien ;
2. le manifeste journalisé décrit les octets scellés et le certificat du sceau ;
3. le sceau ne réintroduit aucune couche texte ;
4. un sceau exigé mais indisponible refuse l'export SANS rien journaliser ;
5. une configuration incohérente refuse de se charger (jamais un sceau
   silencieusement absent).
"""
import hashlib
import io
import os

import pytest

from test_watermark import (EMETTEUR_AMBER, LECTEUR_RED, _journal_events,  # noqa: F401
                            _pdf, client, doc_amber, doc_id, wm)

import pades  # noqa: E402

from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext


def _statut_du_sceau(pdf: bytes):
    lecteur = PdfFileReader(io.BytesIO(pdf))
    assert len(lecteur.embedded_signatures) == 1, "un et un seul sceau attendu"
    signature = lecteur.embedded_signatures[0]
    racine = load_cert_from_pemder(os.environ["SDOP_TEST_PADES_ROOT"])
    return signature, validate_pdf_signature(
        signature, ValidationContext(trust_roots=[racine]))


def test_export_scelle_et_valide(client, doc_id):
    from pyhanko.sign.validation.status import SignatureCoverageLevel

    r = client.get(f"/api/export/{doc_id}.pdf", headers=LECTEUR_RED)
    assert r.status_code == 200
    signature, statut = _statut_du_sceau(r.data)
    assert statut.intact and statut.valid and statut.trusted
    assert statut.coverage == SignatureCoverageLevel.ENTIRE_FILE
    assert signature.sig_object["/SubFilter"] == "/ETSI.CAdES.detached"
    # Certification « aucune modification » : un exemplaire retouché ne peut
    # pas garder un sceau valide.
    assert statut.docmdp_ok is not False
    from pyhanko.sign.fields import MDPPerm
    assert signature.docmdp_level == MDPPerm.NO_CHANGES


def test_raison_du_sceau_porte_l_identifiant_de_consultation(client, doc_id):
    """Un exemplaire retrouvé se rattache au journal par son sceau même."""
    raisons = []
    for _ in range(2):
        r = client.get(f"/api/export/{doc_id}.pdf", headers=LECTEUR_RED)
        view_id = [e for e in _journal_events()
                   if e["event"] == "document_export"][-1]["view_id"]
        signature, _ = _statut_du_sceau(r.data)
        raison = str(signature.sig_object["/Reason"])
        assert raison == f"Exemplaire SDOP {view_id}"
        raisons.append(raison)
    assert raisons[0] != raisons[1], "chaque export a son propre view_id"


def test_manifeste_couvre_les_octets_scelles(client, doc_id):
    r = client.get(f"/api/export/{doc_id}.pdf", headers=LECTEUR_RED)
    man = [e for e in _journal_events()
           if e["event"] == "document_export"][-1]["manifest"]
    assert man["artifact_sha256"] == hashlib.sha256(r.data).hexdigest()
    assert man["generator"] == "sdop-watermark/3"
    signature, _ = _statut_du_sceau(r.data)
    cert_der = signature.signer_cert.dump()
    assert man["pades_cert_sha256"] == hashlib.sha256(cert_der).hexdigest()


def test_sceau_sans_couche_texte(client, doc_id):
    import pymupdf
    r = client.get(f"/api/export/{doc_id}.pdf", headers=LECTEUR_RED)
    with pymupdf.open(stream=r.data, filetype="pdf") as doc:
        for page in doc:
            assert page.get_text().strip() == ""
            assert len(page.get_images()) == 1


def test_porteur_de_lien_recoit_un_export_scelle(client, doc_amber):
    emis = client.post(f"/api/lien/{doc_amber}", headers=EMETTEUR_AMBER | {
        "Accept": "application/json"},
        data={"destinataire": "sceau@exemple.invalid"}).get_json()
    jeton = emis["url"].rsplit("/", 1)[-1]
    client.post(f"/lien/{jeton}", data={"facteur": emis["code"]})
    r = client.get(f"/api/export/{doc_amber}.pdf")
    assert r.status_code == 200
    _, statut = _statut_du_sceau(r.data)
    assert statut.intact and statut.valid and statut.trusted


def test_sceau_facultatif_par_defaut(client):
    """Décision du 2026-10-05 : signer n'est pas obligatoire. Sans
    SDOP_PADES_REQUIRED explicite, l'exigence est désactivée."""
    assert "SDOP_PADES_REQUIRED" not in os.environ
    assert pades.REQUIRED is False
    assert client.get("/health").get_json()["pades_required"] is False


def test_health_expose_le_sceau(client):
    sante = client.get("/health").get_json()
    assert sante["pades_seal"] is True
    assert len(sante["pades_cert_sha256"]) == 64
    assert sante["pades_not_after"]


def test_sceau_exige_mais_absent_refuse_sans_trace(client, doc_id, monkeypatch):
    """Refus AVANT rendu et journal : un export non scellé ne sort pas, et
    un refus ne laisse pas de faux export au journal."""
    monkeypatch.setattr(pades, "REQUIRED", True)
    monkeypatch.setattr(pades, "_SIGNER", None)
    avant = len([e for e in _journal_events() if e["event"] == "document_export"])
    r = client.get(f"/api/export/{doc_id}.pdf", headers=LECTEUR_RED)
    assert r.status_code == 503
    apres = len([e for e in _journal_events() if e["event"] == "document_export"])
    assert apres == avant


def test_sceau_facultatif_absent_exporte_sans_sceau(client, doc_id, monkeypatch):
    """Hors production (démo, dev), l'absence de sceau ne bloque pas — mais le
    manifeste le dit (pas d'empreinte de certificat)."""
    monkeypatch.setattr(pades, "REQUIRED", False)
    monkeypatch.setattr(pades, "_SIGNER", None)
    r = client.get(f"/api/export/{doc_id}.pdf", headers=LECTEUR_RED)
    assert r.status_code == 200
    assert len(PdfFileReader(io.BytesIO(r.data)).embedded_signatures) == 0
    man = [e for e in _journal_events()
           if e["event"] == "document_export"][-1]["manifest"]
    assert man["pades_cert_sha256"] is None


def test_cle_et_certificat_incoherents_refuses(tmp_path):
    from conftest import _pki_de_sceau
    autre_cle, _, _ = _pki_de_sceau(str(tmp_path / "autre"))
    with pytest.raises(pades.ConfigurationSceau):
        pades.charger(autre_cle, os.environ["SDOP_PADES_CERT"])


def test_configuration_partielle_refusee():
    with pytest.raises(pades.ConfigurationSceau):
        pades.charger(os.environ["SDOP_PADES_KEY"], "")
    with pytest.raises(pades.ConfigurationSceau):
        pades.charger("", os.environ["SDOP_PADES_CERT"])


def test_fichier_absent_refuse(tmp_path):
    with pytest.raises(pades.ConfigurationSceau):
        pades.charger(str(tmp_path / "absente.key"), os.environ["SDOP_PADES_CERT"])
