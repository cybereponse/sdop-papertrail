#!/usr/bin/env python3
"""
Descellement d'un document — exige les DEUX clés privées, réunies.

Opération hors ligne, à faire sur un poste de confiance en présence des deux
détenteurs. Le service, lui, n'a aucun moyen de rouvrir un document scellé :
c'est l'objet même du scellement.

    sdop-desceller.py <fichier-scellé> --cle-a a.pem --cle-b b.pem --sortie clair.pdf

Les clés privées ne sont jamais lues par le service, ne transitent pas par le
réseau, et ne doivent pas rester sur la machine après l'opération.

Le descellement doit être inscrit au ledger à la remise en service — ce script
ne le fait pas lui-même : il tourne hors de la machine qui détient le journal.
Il affiche l'entrée à ajouter.
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "watermark"))

from cryptography.hazmat.primitives import serialization  # noqa: E402

import sealing  # noqa: E402


def charger_privee(chemin: str):
    """Clé privée d'un détenteur, chiffrée par sa phrase de passe (demandée à
    l'écran, jamais en argument) ; une clé non chiffrée est encore acceptée."""
    import getpass
    with open(chemin, "rb") as f:
        pem = f.read()
    if b"ENCRYPTED" in pem:
        phrase = getpass.getpass(f"Phrase de passe de {os.path.basename(chemin)} : ")
        return serialization.load_pem_private_key(pem, password=phrase.encode())
    return serialization.load_pem_private_key(pem, password=None)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scelle")
    ap.add_argument("--cle-a", required=True, help="clé privée du premier détenteur")
    ap.add_argument("--cle-b", required=True, help="clé privée du second détenteur")
    ap.add_argument("--sortie", required=True)
    ap.add_argument("--motif", default="", help="raison du descellement, pour le journal")
    args = ap.parse_args()

    with open(args.scelle, "rb") as f:
        blob = f.read()
    if not sealing.is_sealed(blob):
        sys.exit("ERR: ce fichier n'est pas scellé.")

    try:
        clair = sealing.unseal(blob, charger_privee(args.cle_a),
                               charger_privee(args.cle_b))
    except sealing.SealingError as exc:
        sys.exit(f"ERR: descellement refusé — {exc}")

    with open(args.sortie, "wb") as f:
        f.write(clair)
    empreinte = hashlib.sha256(clair).hexdigest()
    print(f"✔ Descellé : {args.sortie} ({len(clair)} octets)")
    print(f"  sha256 : {empreinte}")
    print()
    print("  Entrée à inscrire au ledger à la remise en service :")
    print("  " + json.dumps({
        "event": "document_unsealed",
        "source": os.path.basename(args.scelle),
        "clear_sha256": empreinte,
        "motif": args.motif,
        "at": datetime.now(timezone.utc).isoformat(),
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
