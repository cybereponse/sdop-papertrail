#!/usr/bin/env python3
"""
Démonstration de bout en bout du service watermark, sans serveur ni conteneur.

L'application est exercée par son client de test Flask, en mode de confiance
`proxy` : l'identité est fournie par des en-têtes, exactement comme nginx les
poserait. C'est donc le vrai chemin de code qui est exercé — pas un mode dev.

Produit dans var/demo/ :
  note-test-sdop.pdf        le document source (contenu fictif)
  export-<view>.pdf         l'export filigrané, rendu image, sans couche texte
  page-N.png                les tuiles telles que la visionneuse les sert
  viewer.html               la page de visionneuse rendue
  journal/ledger-AAAA-MM.jsonl   le journal à chaîne de hachage
"""
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "var", "demo")

# Repartir d'un état vierge : une démo qui s'ajoute à la précédente ne montre
# plus ce qu'elle vient de faire.
shutil.rmtree(OUT, ignore_errors=True)
os.makedirs(OUT, exist_ok=True)

os.environ["SDOP_TRUST_MODE"] = "proxy"
os.environ["SDOP_DOC_DIR"] = os.path.join(OUT, "documents")
os.environ["SDOP_LEDGER_DIR"] = os.path.join(OUT, "journal")
os.environ.setdefault("SDOP_RENDER_DPI", "150")
os.environ["SDOP_TILE_SECRET"] = "demo-secret-non-sensible"

sys.path.insert(0, os.path.join(ROOT, "watermark"))
sys.path.insert(0, os.path.join(ROOT, "ledger"))

_spec = importlib.util.spec_from_file_location(
    "sdop_watermark_app", os.path.join(ROOT, "watermark", "app.py"))
wm = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = wm
_spec.loader.exec_module(wm)

import ledger  # noqa: E402

EMETTEUR = {
    "X-Authentik-Username": "jdupont",
    "X-Authentik-Groups": "tlp-red-emetteurs",
    "X-Client-Cert-CN": "jdupont",
    "X-Forwarded-For": "10.20.0.11",
}
LECTEUR = {
    "X-Authentik-Username": "mbernard",
    "X-Authentik-Groups": "tlp-red-lecteurs",
    "X-Client-Cert-CN": "mbernard",
    "X-Forwarded-For": "10.20.0.42",
}
NON_HABILITE = {
    "X-Authentik-Username": "pmartin",
    "X-Authentik-Groups": "tlp-amber-lecteurs",
    "X-Client-Cert-CN": "pmartin",
    "X-Forwarded-For": "10.20.0.77",
}

etapes = []


def etape(libelle, attendu, obtenu):
    ok = attendu == obtenu
    etapes.append((ok, libelle, f"attendu {attendu}, obtenu {obtenu}"))
    return ok


def main():
    source = os.path.join(OUT, "note-test-sdop.pdf")
    subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "make-test-doc.py"),
                    source], check=True, stdout=subprocess.DEVNULL)

    wm.app.config["TESTING"] = True
    c = wm.app.test_client()

    # 1. Publication par un émetteur habilité TLP:RED
    with open(source, "rb") as f:
        resp = c.post("/api/publish", headers=EMETTEUR | {"Accept": "application/json"},
                      data={"tlp": "TLP:RED",
                            "document": (io.BytesIO(f.read()), "note-test-sdop.pdf"),
                            "destinataires": "mbernard"})
    etape("publication TLP:RED par un émetteur habilité", 201, resp.status_code)
    meta = resp.get_json()
    doc_id = meta["doc_id"]

    # 2. Un émetteur AMBER ne publie pas en RED (aucune hiérarchie implicite)
    resp = c.post("/api/publish", headers=NON_HABILITE | {"Accept": "application/json"},
                  data={"tlp": "TLP:RED", "document": (io.BytesIO(b"%PDF-1.4\n"), "x.pdf")})
    etape("publication TLP:RED refusée à un non-émetteur", 403, resp.status_code)

    # 3. Un lecteur non habilité RED ne distingue pas 403 de 404
    etape("document invisible pour un lecteur non habilité", 404,
          c.get(f"/api/doc/{doc_id}", headers=NON_HABILITE).status_code)

    # 3 bis. Habilité au bon niveau, mais pas destinataire : refusé aussi.
    autre_lecteur = dict(LECTEUR, **{"X-Authentik-Username": "slemoine"})
    etape("document invisible pour un habilité non destinataire", 404,
          c.get(f"/api/doc/{doc_id}", headers=autre_lecteur).status_code)

    # 4. Visionneuse pour le lecteur habilité
    resp = c.get(f"/viewer/{doc_id}", headers=LECTEUR)
    etape("visionneuse rendue pour le lecteur habilité", 200, resp.status_code)
    html = resp.get_data(as_text=True)
    with open(os.path.join(OUT, "viewer.html"), "w") as f:
        f.write(html)
    tuiles = re.findall(r'src="([^"]+)"', html.replace("&amp;", "&"))

    # 5. Tuiles PNG : servies uniquement via URL signée, pour CET utilisateur
    etape("tuile sans URL signée refusée", 403,
          c.get(f"/api/view/{doc_id}/page/0.png", headers=LECTEUR).status_code)
    autre = dict(LECTEUR, **{"X-Authentik-Username": "usurpateur"})
    etape("URL de tuile rejouée par un autre compte refusée", 403,
          c.get(tuiles[0], headers=autre).status_code)

    for i, url in enumerate(tuiles):
        r = c.get(url, headers=LECTEUR)
        etape(f"tuile page {i + 1} servie en PNG", 200, r.status_code)
        with open(os.path.join(OUT, f"page-{i + 1}.png"), "wb") as f:
            f.write(r.data)

    # 6. Export filigrané
    resp = c.get(f"/api/export/{doc_id}.pdf", headers=LECTEUR)
    etape("export filigrané servi", 200, resp.status_code)
    export_name = resp.headers["Content-Disposition"].split("filename=")[-1].strip('";')
    export_path = os.path.join(OUT, export_name)
    with open(export_path, "wb") as f:
        f.write(resp.data)

    # 7. L'export ne contient aucune couche texte
    import pymupdf
    with pymupdf.open(export_path) as doc:
        textes = [p.get_text().strip() for p in doc]
    etape("aucune couche texte dans l'export", [""] * len(textes), textes)

    # 8. Journal : chaîne intacte
    segments = [os.path.join(os.environ["SDOP_LEDGER_DIR"], n)
                for n in os.listdir(os.environ["SDOP_LEDGER_DIR"])]
    etape("chaîne de hachage du journal intacte", [True] * len(segments),
          [ledger.verify(s) for s in segments])

    # --- Restitution ------------------------------------------------------
    print()
    print("Document publié")
    print(f"  doc_id        {meta['doc_id']}")
    print(f"  TLP           {meta['tlp']}")
    print(f"  émetteur      {meta['published_by']}")
    print(f"  SHA-256       {meta['version_hash']}")
    print(f"  pages         {meta['pages']}")
    print(f"  destinataires mbernard")
    print(f"  visible jusqu'au {meta['expires_at'][:10]}")
    print()
    print("Contrôles")
    for ok, libelle, detail in etapes:
        print(f"  [{'✓' if ok else '✗'}] {libelle}" + ("" if ok else f" — {detail}"))
    print()
    print("Journal (toutes les entrées, dans l'ordre de la chaîne)")
    for seg in sorted(segments):
        with open(seg) as f:
            for line in f:
                e = json.loads(line)
                print(f"  {e['timestamp'][11:19]}  {e['event']:<17} "
                      f"{e.get('actor','-'):<12} {e.get('view_id', '-')}")
    print()
    print(f"Artefacts : {os.path.relpath(OUT, ROOT)}/")
    for n in sorted(os.listdir(OUT)):
        path = os.path.join(OUT, n)
        if os.path.isfile(path):
            print(f"  {n:<36} {os.path.getsize(path):>9} octets")

    rate = [l for ok, l, _ in etapes if not ok]
    return 1 if rate else 0


if __name__ == "__main__":
    sys.exit(main())
