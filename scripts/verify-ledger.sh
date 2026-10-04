#!/usr/bin/env bash
# Vérifie l'intégrité de chaque segment d'un journal SDOP.
#
# Deux niveaux de preuve, et ils ne disent pas la même chose :
#
#   sans ancrage  la chaîne de hachage prouve que rien n'a été RÉÉCRIT dans ce
#                 qui reste. Une troncature propre reste invisible.
#   avec ancrage  si un digest signé (ledger/digest.sh) existe pour le segment,
#                 son nombre d'entrées et son dernier hash sont exigés : une
#                 suppression des dernières entrées devient visible.
#
# Un segment invalide ne dit pas QUOI a été modifié — il dit que quelque chose
# l'a été, ce qui suffit à déclencher une investigation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEDGER_DIR="${LEDGER_DIR:-${ROOT}/var/journal}"
PY="${ROOT}/watermark/.venv/bin/python"
[[ -x "${PY}" ]] || PY="python3"

shopt -s nullglob
segments=("${LEDGER_DIR}"/ledger-*.jsonl)
if (( ${#segments[@]} == 0 )); then
    echo "Aucun segment dans ${LEDGER_DIR} — rien à vérifier."
    exit 0
fi

PYTHONPATH="${ROOT}/ledger" "${PY}" - "${LEDGER_DIR}" "${segments[@]}" <<'PYEOF'
import glob
import os
import sys

import ledger

ledger_dir, segments = sys.argv[1], sys.argv[2:]


def ancrage(segment: str):
    """Dernier digest publié pour ce segment : (entries, last_hash, fichier)."""
    trouve = None
    for digest in sorted(glob.glob(os.path.join(ledger_dir, "digest-*.txt"))):
        champs = {}
        with open(digest) as f:
            for ligne in f:
                cle, _, valeur = ligne.partition(" ")
                champs[cle.strip()] = valeur.strip()
        if champs.get("segment") != os.path.basename(segment):
            continue
        if "entries" in champs and "last_hash" in champs:
            trouve = (int(champs["entries"]), champs["last_hash"],
                      os.path.basename(digest))
    return trouve


code = 0
for path in segments:
    nom = os.path.basename(path)
    try:
        n = ledger.count(path)
    except ledger.LedgerError as exc:
        print(f"  [✗] {nom} — illisible : {exc}")
        code = 1
        continue

    ancre = ancrage(path)
    if ancre is None:
        if ledger.verify(path):
            print(f"  [✓] {nom} — {n} entrée(s), chaîne intacte "
                  f"(sans ancrage : une troncature resterait invisible)")
        else:
            print(f"  [✗] {nom} — CHAÎNE ROMPUE")
            code = 1
        continue

    attendu_n, attendu_h, digest = ancre
    if ledger.verify(path, expected_count=attendu_n, expected_last_hash=attendu_h):
        print(f"  [✓] {nom} — {n} entrée(s), chaîne intacte et conforme "
              f"à l'ancrage {digest}")
    elif ledger.verify(path):
        print(f"  [✗] {nom} — chaîne valide mais DIVERGENTE de l'ancrage "
              f"{digest} : {n} entrée(s) contre {attendu_n} attendues "
              f"→ troncature ou journal remplacé")
        code = 1
    else:
        print(f"  [✗] {nom} — CHAÎNE ROMPUE")
        code = 1

sys.exit(code)
PYEOF
