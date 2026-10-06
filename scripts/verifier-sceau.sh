#!/usr/bin/env bash
# Vérifie le sceau PAdES d'exports SDOP avec le pyHanko épinglé du service
# (watermark/requirements.txt), dans le venv de dev-run.sh — créé s'il manque.
#
#   scripts/verifier-sceau.sh --racine <racine.crt> exemplaire.pdf [autre.pdf …]
#   (ou SDOP_PADES_RACINE=<racine.crt>)
#
# Options et codes de sortie : scripts/verifier-sceau.py.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${ROOT}/watermark/.venv"
if [[ ! -x "${VENV}/bin/python" ]]; then
    echo "==> création du venv ${VENV}" >&2
    python3 -m venv "${VENV}"
    "${VENV}/bin/pip" install -q --upgrade pip
    "${VENV}/bin/pip" install -q --require-hashes -r "${ROOT}/watermark/requirements.txt"
fi
exec "${VENV}/bin/python" "${ROOT}/scripts/verifier-sceau.py" "$@"
