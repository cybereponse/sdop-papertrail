#!/usr/bin/env bash
# Lance le service watermark SANS le socle identité partagé (devbox / démo).
#
# Pourquoi ce script existe : le socle (mTLS + Authentik) est un déploiement
# séparé et n'est pas toujours présent sur le poste de
# développement. L'identité est alors fournie par l'ENVIRONNEMENT du processus
# (SDOP_TRUST_MODE=dev), jamais par la requête — voir watermark/identity.py.
# Aucun chemin de code « identité fournie par le client » n'est introduit.
#
# Usage :
#   scripts/dev-run.sh                 # démarre sur 127.0.0.1:5000
#   SDOP_PORT=5050 scripts/dev-run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${ROOT}/watermark/.venv"
VAR="${ROOT}/var"

if [[ ! -x "${VENV}/bin/python" ]]; then
    echo "==> création du venv ${VENV}"
    python3 -m venv "${VENV}"
    "${VENV}/bin/pip" install -q --upgrade pip
    "${VENV}/bin/pip" install -q --require-hashes -r "${ROOT}/watermark/requirements.txt"
fi

mkdir -p "${VAR}/documents" "${VAR}/journal"

export PYTHONPATH="${ROOT}/watermark:${ROOT}/ledger"
export SDOP_TRUST_MODE=dev
export SDOP_DEV_IDENTITY=1
export SDOP_DEV_USER="${SDOP_DEV_USER:-analyste.delta}"
export SDOP_DEV_CERT_CN="${SDOP_DEV_CERT_CN:-analyste.delta}"
# Émetteur ET lecteur sur les trois niveaux : le poste de dev doit pouvoir
# exercer tous les chemins. En production, ces groupes viennent d'Authentik.
export SDOP_DEV_GROUPS="${SDOP_DEV_GROUPS:-tlp-red-emetteurs|tlp-amber-strict-emetteurs|tlp-amber-emetteurs}"
export SDOP_DOC_DIR="${VAR}/documents"
export SDOP_LEDGER_DIR="${VAR}/journal"
export SDOP_BIND="${SDOP_BIND:-127.0.0.1}"
export SDOP_PORT="${SDOP_PORT:-5000}"
export SDOP_TILE_SECRET="${SDOP_TILE_SECRET:-dev-secret-non-sensible}"

echo "==> SDOP watermark (mode dev) sur http://${SDOP_BIND}:${SDOP_PORT}"
echo "    identité : ${SDOP_DEV_USER} [${SDOP_DEV_GROUPS}]"
echo "    documents: ${SDOP_DOC_DIR}"
echo "    journal  : ${SDOP_LEDGER_DIR}"
exec "${VENV}/bin/python" "${ROOT}/watermark/app.py"
