#!/usr/bin/env bash
# Digest quotidien signé PGP du segment ledger courant — ARCHITECTURE.md
#
# Ancrage anti-altération. Deux attaques distinctes, deux réponses :
#   - une entrée RÉÉCRITE casse la chaîne de hachage, ledger.verify() la voit
#     sans aide extérieure ;
#   - une troncature PROPRE (supprimer les N dernières lignes) laisse une
#     chaîne parfaitement valide. Seul un ancrage extérieur la révèle. C'est
#     pourquoi ce digest publie le NOMBRE d'entrées et le DERNIER hash, pas
#     seulement l'empreinte du fichier : rejoués dans
#     `ledger.verify(path, expected_count=…, expected_last_hash=…)`, ils
#     rendent la suppression visible.
#
# Le digest ne vaut que s'il est exporté HORS de la machine (boîte mail dédiée,
# tier externe) : sur place, qui peut tronquer le journal peut aussi réécrire
# le digest. La signature PGP empêche de le refabriquer, pas de le supprimer.
#
# Aucun chemin ni clé en dur : LEDGER_DIR et GPG_SIGNING_KEY viennent de
# l'environnement (déployé/planifié côté infra — timer systemd, hors de ce
# dépôt applicatif). Ne déverrouille ni ne génère de clé : signe avec une clé
# déjà présente dans le trousseau de l'exécutant.
set -euo pipefail

LEDGER_DIR="${LEDGER_DIR:?LEDGER_DIR non défini}"
GPG_SIGNING_KEY="${GPG_SIGNING_KEY:?GPG_SIGNING_KEY non défini}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"

SEGMENT="${LEDGER_DIR}/ledger-$(date -u +%Y-%m).jsonl"
DIGEST_FILE="${LEDGER_DIR}/digest-$(date -u +%F).txt"

if [[ ! -f "${SEGMENT}" ]]; then
    echo "ERR: segment introuvable : ${SEGMENT}" >&2
    exit 1
fi

# Refuse de signer un journal déjà rompu : un digest sur une chaîne cassée
# donnerait une fausse assurance à la vérification du lendemain.
if ! PYTHONPATH="${HERE}" "${PYTHON}" -c "
import sys, ledger
sys.exit(0 if ledger.verify('${SEGMENT}') else 1)
"; then
    echo "ERR: chaîne rompue dans ${SEGMENT} — digest non produit" >&2
    exit 2
fi

PYTHONPATH="${HERE}" "${PYTHON}" - "${SEGMENT}" > "${DIGEST_FILE}" <<'PYEOF'
import hashlib
import os
import sys
from datetime import datetime, timezone

import ledger

path = sys.argv[1]
with open(path, "rb") as f:
    sha = hashlib.sha256(f.read()).hexdigest()

print(f"date       {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
print(f"segment    {os.path.basename(path)}")
print(f"sha256     {sha}")
print(f"entries    {ledger.count(path)}")
print(f"last_hash  {ledger.last_hash(path)}")
PYEOF

gpg --batch --yes --detach-sign --armor \
    --local-user "${GPG_SIGNING_KEY}" "${DIGEST_FILE}"

echo "✔ Digest signé : ${DIGEST_FILE}.asc"
cat "${DIGEST_FILE}"
