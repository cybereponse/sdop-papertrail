#!/usr/bin/env python3
"""
Balayage des échéances : alerte à J-7, scellement des documents échus.

À planifier côté infra (timer systemd quotidien), comme `ledger/digest.sh` —
pas d'ordonnanceur dans l'application (ARCHITECTURE.md).

Le scellement n'est volontairement PAS une route HTTP. Un endpoint capable de
rendre des documents définitivement illisibles serait une cible ; et l'opération
exige de toute façon les clés publiques des détenteurs, qui viennent du coffre.

    SDOP_SEAL_PUBKEY_A / _B   clés publiques X25519 (base64 ou PEM)
    SDOP_DOC_DIR, SDOP_LEDGER_DIR

Usage :
    sdop-sceller.py --dry-run     n'écrit rien, montre ce qui serait fait
    sdop-sceller.py --alertes     liste les échéances proches (J-7)
    sdop-sceller.py               scelle réellement les documents échus
"""
import argparse
import os
import sys

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RACINE, "watermark"))
# Dans l'image, le script est copié à côté des modules (/app).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RACINE, "ledger"))

import ledger          # noqa: E402
import sealing         # noqa: E402
import store           # noqa: E402


def cles_detenteurs():
    a, b = os.environ.get("SDOP_SEAL_PUBKEY_A"), os.environ.get("SDOP_SEAL_PUBKEY_B")
    if not a or not b:
        sys.exit("ERR: SDOP_SEAL_PUBKEY_A et SDOP_SEAL_PUBKEY_B sont requis — "
                 "deux détenteurs distincts, sinon le double contrôle n'existe pas.")
    if a.strip() == b.strip():
        sys.exit("ERR: les deux clés sont identiques — ce n'est pas un double "
                 "contrôle, c'est un seul détenteur en double.")
    return sealing.load_public_key(a), sealing.load_public_key(b)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--alertes", action="store_true")
    ap.add_argument("--jours-alerte", type=int, default=7)
    args = ap.parse_args()

    if args.alertes:
        proches = store.expiring_soon(args.jours_alerte)
        if not proches:
            print(f"Aucune échéance dans les {args.jours_alerte} jours.")
            return 0
        print(f"Échéances dans les {args.jours_alerte} jours :")
        for d in proches:
            print(f"  {d['expires_at'][:10]}  {d['tlp']:<18} {d['doc_id'][:12]}  "
                  f"émetteur {d['published_by']}  « {d['original_name']} »")
        return 0

    echus = store.expired_documents()
    if not echus:
        print("Aucun document échu.")
        return 0

    if args.dry_run:
        print(f"{len(echus)} document(s) seraient scellés :")
        for d in echus:
            print(f"  {d['expires_at'][:10]}  {d['doc_id'][:12]}  {d['tlp']}")
        return 0

    pub_a, pub_b = cles_detenteurs()
    for d in echus:
        resultat = store.seal_document(d["doc_id"], pub_a, pub_b)
        ledger.append({
            "event": "document_sealed", "doc_id": d["doc_id"], "tlp": d["tlp"],
            "actor": "systeme", "expires_at": d["expires_at"],
            "clear_sha256": resultat["sha256"], "clear_bytes": resultat["bytes"],
            "scheme": "xor-2-of-2/x25519-hkdf-sha256/aes-256-gcm",
        })
        print(f"  scellé : {d['doc_id'][:12]}  {d['tlp']}  "
              f"({resultat['bytes']} octets, sha256 {resultat['sha256'][:12]})")
    print(f"{len(echus)} document(s) scellés. "
          "Leur réouverture exige désormais les DEUX clés privées, hors ligne.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
