"""
scripts/verifier-sceau.py — l'outil de vérification des exemplaires, hors conteneur.

Ce qu'on exige : un export sorti du service est reconnu OK avec la racine de test ;
sans racine, le verdict n'est pas OK (confiance inconnue) ; un exemplaire retouché
après le sceau n'est plus OK ; un PDF sans signature est dit « non scellé ».
L'outil est exercé tel que l'opérateur le lance (processus séparé, codes de sortie).
"""
import json
import os
import re
import subprocess
import sys

from test_watermark import LECTEUR_RED, _pdf, client, doc_id  # noqa: F401

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUTIL = os.path.join(ROOT, "scripts", "verifier-sceau.py")
# La raison du sceau porte l'identifiant de CONSULTATION (un par export), pas celui du document.
RAISON = re.compile(r"Exemplaire SDOP [0-9a-f-]{36}")


def _lancer(*args, env=None):
    e = {k: v for k, v in os.environ.items() if k != "SDOP_PADES_RACINE"}
    e.update(env or {})
    return subprocess.run([sys.executable, OUTIL, *args], capture_output=True, text=True, env=e)


def _export(client, doc_id, tmp_path):
    r = client.get(f"/api/export/{doc_id}.pdf", headers=LECTEUR_RED)
    assert r.status_code == 200
    f = tmp_path / "exemplaire.pdf"
    f.write_bytes(r.data)
    return f


def test_export_reconnu_ok_avec_la_racine(client, doc_id, tmp_path):
    f = _export(client, doc_id, tmp_path)
    r = _lancer("--racine", os.environ["SDOP_TEST_PADES_ROOT"], str(f))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "VERDICT : OK" in r.stdout
    assert "SceauSDOP" in r.stdout and RAISON.search(r.stdout)


def test_racine_par_variable_d_environnement(client, doc_id, tmp_path):
    f = _export(client, doc_id, tmp_path)
    r = _lancer(str(f), env={"SDOP_PADES_RACINE": os.environ["SDOP_TEST_PADES_ROOT"]})
    assert r.returncode == 0, r.stdout + r.stderr


def test_sans_racine_la_confiance_est_inconnue(client, doc_id, tmp_path):
    f = _export(client, doc_id, tmp_path)
    r = _lancer(str(f))
    assert r.returncode == 1
    assert "confiance     : inconnue" in r.stdout
    assert "VERDICT : NON OK" in r.stdout


def test_exemplaire_retouche_n_est_plus_ok(client, doc_id, tmp_path):
    f = _export(client, doc_id, tmp_path)
    f.write_bytes(f.read_bytes() + b"\n% retouche apres le sceau\n")
    r = _lancer("--racine", os.environ["SDOP_TEST_PADES_ROOT"], str(f))
    assert r.returncode == 1, r.stdout + r.stderr
    assert "VERDICT : NON OK" in r.stdout


def test_pdf_sans_signature_est_dit_non_scelle(tmp_path):
    f = tmp_path / "brut.pdf"
    f.write_bytes(_pdf())
    r = _lancer("--racine", os.environ["SDOP_TEST_PADES_ROOT"], str(f))
    assert r.returncode == 2
    assert "AUCUNE signature" in r.stdout and "VERDICT : NON SCELLÉ" in r.stdout


def test_sortie_json(client, doc_id, tmp_path):
    f = _export(client, doc_id, tmp_path)
    r = _lancer("--json", "--racine", os.environ["SDOP_TEST_PADES_ROOT"], str(f))
    assert r.returncode == 0
    rapport = json.loads(r.stdout)
    assert rapport[0]["sceaux"][0]["ok"] is True
    assert RAISON.fullmatch(rapport[0]["sceaux"][0]["raison"])
