#!/usr/bin/env bash
# Tire les secrets machine de SDOP SUR la machine de déploiement — jamais sur un
# poste, jamais affichés. À lancer en root, depuis le répertoire de déploiement :
#
#   sudo bash scripts/gen-secrets.sh
#
# Ce qui est tiré, chacun seulement s'il manque (idempotent, non destructeur —
# régénérer SDOP_CONTENT_KEY rendrait illisibles les documents déjà chiffrés) :
#
#   .env  SDOP_CONTENT_KEY   clé AES-256 du chiffrement au repos (EX-8), base64
#   .env  SDOP_TILE_SECRET   secret de signature des URL de tuiles
#   .env  SDOP_SIGNING_KEY   CHEMIN, côté conteneur, de la clé ci-dessous
#   secrets/sdop-signing.pem clé Ed25519 des manifestes d'export (SEC-014),
#                            lisible du seul uid du service (nobody, 65534)
#
# Et, si SDOP_DIGEST_HOME est défini (répertoire préparé par l'hôte), la clé
# GnuPG machine qui signe le digest quotidien du ledger (ledger/digest.sh) :
# son empreinte est écrite dans $SDOP_DIGEST_HOME/fingerprint, sa partie
# publique dans $SDOP_DIGEST_HOME/digest-pubkey.asc.
#
# Le coffre reste la source de vérité : le dépôt des valeurs y est un geste
# humain (script jetable fourni par l'exploitant). Contrôle sans lecture :
#   grep -q '^SDOP_CONTENT_KEY=.\+' .env
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ ${EUID} -eq 0 ]] || { echo "ERREUR : à lancer en root (sudo)." >&2; exit 1; }
# Le .env est lu par `docker compose`, lancé par le compte d'exploitation.
PROPRIO="${SUDO_USER:-root}"
umask 077

ENV="${ROOT}/.env"
[[ -f "${ENV}" ]] || : > "${ENV}"

ajoute() {
    local cle="$1" valeur
    if grep -q "^${cle}=.\+" "${ENV}"; then
        echo "  ${cle} : déjà présent, conservé"
        return
    fi
    valeur="$2"
    # Une ligne vide `CLE=` éventuelle est remplacée, pas doublée.
    sed -i "/^${cle}=\$/d" "${ENV}"
    printf '%s=%s\n' "${cle}" "${valeur}" >> "${ENV}"
    echo "  ${cle} : tiré"
}

ajoute SDOP_CONTENT_KEY "$(openssl rand -base64 32)"
ajoute SDOP_TILE_SECRET "$(openssl rand -hex 32)"
ajoute SDOP_SIGNING_KEY "/secrets/sdop-signing.pem"
chown "${PROPRIO}" "${ENV}"
chmod 600 "${ENV}"

install -d -m 700 "${ROOT}/secrets"
PEM="${ROOT}/secrets/sdop-signing.pem"
if [[ -s "${PEM}" ]]; then
    echo "  secrets/sdop-signing.pem : déjà présente, conservée"
else
    openssl genpkey -algorithm ed25519 -out "${PEM}"
    echo "  secrets/sdop-signing.pem : tirée (Ed25519)"
fi
# Monté seul dans le conteneur : les permissions de l'hôte y sont celles vues
# par le service, qui tourne en nobody (watermark/Dockerfile, USER nobody).
chown 65534:65534 "${PEM}"
chmod 400 "${PEM}"

if [[ -n "${SDOP_DIGEST_HOME:-}" ]]; then
    install -d -m 700 "${SDOP_DIGEST_HOME}" "${SDOP_DIGEST_HOME}/gnupg"
    export GNUPGHOME="${SDOP_DIGEST_HOME}/gnupg"
    if [[ -s "${SDOP_DIGEST_HOME}/fingerprint" ]]; then
        echo "  clé de digest : déjà présente, conservée"
    else
        # Clé machine sans phrase : le timer la sert sans humain. Ce qu'elle
        # garantit est borné (README § « Ce que la chaîne ne prouve pas seule ») :
        # elle empêche de REFABRIQUER un digest, pas de le supprimer.
        gpg --batch --pinentry-mode loopback --passphrase '' \
            --quick-gen-key "SDOP ledger digest ($(hostname))" ed25519 sign never 2>/dev/null
        gpg --batch --list-secret-keys --with-colons \
            | awk -F: '/^fpr:/ {print $10; exit}' > "${SDOP_DIGEST_HOME}/fingerprint"
        echo "  clé de digest : tirée"
    fi
    gpg --batch --armor --export "$(cat "${SDOP_DIGEST_HOME}/fingerprint")" \
        > "${SDOP_DIGEST_HOME}/digest-pubkey.asc"
    chmod 644 "${SDOP_DIGEST_HOME}/digest-pubkey.asc"
    echo "  empreinte de la clé de digest : $(cat "${SDOP_DIGEST_HOME}/fingerprint")"
fi

echo "✔ Secrets SDOP en place — aucune valeur affichée."
