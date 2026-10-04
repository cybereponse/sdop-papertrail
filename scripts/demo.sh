#!/usr/bin/env bash
# Démo de bout en bout du service watermark (voir scripts/demo.py).
# Crée le venv si nécessaire — aucune installation hors du dépôt.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${ROOT}/watermark/.venv"

if [[ ! -x "${VENV}/bin/python" ]]; then
    echo "==> création du venv ${VENV}"
    python3 -m venv "${VENV}"
    "${VENV}/bin/pip" install -q --upgrade pip
    "${VENV}/bin/pip" install -q --require-hashes -r "${ROOT}/watermark/requirements.txt"
fi

exec "${VENV}/bin/python" "${ROOT}/scripts/demo.py"
