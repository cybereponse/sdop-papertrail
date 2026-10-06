#!/usr/bin/env python3
"""
Vérifie le sceau PAdES d'un ou plusieurs exports SDOP, hors de tout conteneur.

Aperçu (macOS) n'affiche pas les signatures PDF ; Acrobat Reader le fait mais
n'est pas toujours là. Cet outil dit la même chose qu'Acrobat avec la racine
installée : qui a scellé, pour quel exemplaire, et si le fichier a bougé.

    scripts/verifier-sceau.py --racine <racine.crt> exemplaire.pdf [autre.pdf …]

Ce qui est exigé pour un verdict OK, sceau par sceau :
  - signature cryptographiquement intacte ;
  - chaîne de confiance jusqu'à UNE des racines données (--racine, répétable,
    ou SDOP_PADES_RACINE) — sans racine, le sceau est décrit mais le verdict
    est « confiance inconnue » (code 1) ;
  - signature de CERTIFICATION « aucune modification permise », couvrant le
    fichier entier : un exemplaire retouché après coup n'est pas OK.
Aucune révocation n'est consultée (pas de réseau) : un certificat révoqué
n'est pas détecté ici.

Codes de sortie : 0 tous les sceaux OK · 1 au moins un sceau non OK ·
2 un fichier sans aucune signature · 3 usage ou fichier illisible.
"""
import argparse
import json
import os
import sys

try:
    from pyhanko.keys import load_cert_from_pemder
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.fields import MDPPerm
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko.sign.validation.status import SignatureCoverageLevel
    from pyhanko_certvalidator import ValidationContext
except ImportError:  # pragma: no cover
    sys.stderr.write("pyHanko absent : lancer via scripts/verifier-sceau.sh (venv watermark) "
                     "ou pip install -r watermark/requirements.txt\n")
    sys.exit(3)


def _nom(name) -> str:
    """CN et O d'un nom X.509, lisibles."""
    d = name.native
    parts = [d.get("common_name"), d.get("organization_name")]
    return " · ".join(p for p in parts if p)


def verifier(chemin: str, contexte: ValidationContext, avec_racine: bool) -> dict:
    with open(chemin, "rb") as f:
        lecteur = PdfFileReader(f)
        sceaux = []
        for sig in lecteur.embedded_signatures:
            st = validate_pdf_signature(sig, contexte)
            cert = st.signing_cert
            entier = st.coverage == SignatureCoverageLevel.ENTIRE_FILE
            certifie = sig.docmdp_level == MDPPerm.NO_CHANGES and st.docmdp_ok is not False
            ok = bool(st.intact and st.valid and entier and certifie
                      and (st.trusted if avec_racine else False))
            sceaux.append({
                "champ": sig.field_name,
                "signataire": _nom(cert.subject),
                "emetteur": _nom(cert.issuer),
                "raison": sig.sig_object.get("/Reason"),
                "signe_le": st.signer_reported_dt.isoformat() if st.signer_reported_dt else None,
                "certificat_expire_le": cert.not_valid_after.isoformat(),
                "intact": bool(st.intact and st.valid),
                "fichier_entier": entier,
                "certification_sans_modification": certifie,
                "confiance": (bool(st.trusted) if avec_racine else None),
                "resume": st.summary(),
                "ok": ok,
            })
    return {"fichier": chemin, "sceaux": sceaux}


def main() -> int:
    p = argparse.ArgumentParser(description="Vérifie le sceau PAdES d'exports SDOP.")
    p.add_argument("pdf", nargs="+", help="exemplaire(s) à vérifier")
    p.add_argument("--racine", action="append", default=[],
                   help="certificat racine de confiance (PEM/DER), répétable ; "
                        "défaut : SDOP_PADES_RACINE")
    p.add_argument("--chaine", action="append", default=[],
                   help="certificat intermédiaire supplémentaire, si absent du sceau")
    p.add_argument("--json", action="store_true", help="sortie JSON")
    a = p.parse_args()

    racines = a.racine or [r for r in [os.environ.get("SDOP_PADES_RACINE", "")] if r]
    try:
        contexte = ValidationContext(
            trust_roots=[load_cert_from_pemder(r) for r in racines],
            other_certs=[load_cert_from_pemder(c) for c in a.chaine],
            allow_fetching=False, revocation_mode="soft-fail")
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"certificat illisible : {exc}\n")
        return 3

    rc = 0
    rapports = []
    for chemin in a.pdf:
        try:
            r = verifier(chemin, contexte, bool(racines))
        except (OSError, ValueError) as exc:
            sys.stderr.write(f"{chemin} : illisible ({exc})\n")
            return 3
        rapports.append(r)
        if not r["sceaux"]:
            rc = max(rc, 2)
        elif not all(s["ok"] for s in r["sceaux"]):
            rc = max(rc, 1)

    if a.json:
        print(json.dumps(rapports, ensure_ascii=False, indent=1))
        return rc

    for r in rapports:
        print(f"{r['fichier']} : {len(r['sceaux'])} sceau(x)")
        if not r["sceaux"]:
            print("  ✗ AUCUNE signature — cet exemplaire n'est pas scellé")
        for s in r["sceaux"]:
            marque = "✓" if s["ok"] else "✗"
            print(f"  {marque} {s['champ']} — {s['signataire']}")
            print(f"      émetteur      : {s['emetteur']}")
            print(f"      raison        : {s['raison']}")
            print(f"      signé le      : {s['signe_le']}  (certificat jusqu'au {s['certificat_expire_le']})")
            print(f"      intact        : {'oui' if s['intact'] else 'NON'}"
                  f" · fichier entier : {'oui' if s['fichier_entier'] else 'NON'}"
                  f" · certification sans modification : {'oui' if s['certification_sans_modification'] else 'NON'}")
            conf = {True: "oui", False: "NON", None: "inconnue (aucune racine donnée)"}[s["confiance"]]
            print(f"      confiance     : {conf}")
            print(f"      résumé pyHanko: {s['resume']}")
    print({0: "VERDICT : OK", 1: "VERDICT : NON OK", 2: "VERDICT : NON SCELLÉ"}[rc])
    return rc


if __name__ == "__main__":
    sys.exit(main())
