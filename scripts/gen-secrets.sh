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
# Sceau PAdES des exports (watermark/pades.py) — FACULTATIF, rien sans
# configuration explicite. Seulement si SDOP_PADES_SUJET est défini
# (environnement, ou ligne du .env), sujet de la demande au format
# `openssl req -subj`, par exemple « /C=FR/O=Mon organisme/CN=SDOP — sceau » ;
# SDOP_PADES_SAN, facultatif, au format `subjectAltName` (« email:role@… »).
# Aucune identité par défaut : une valeur inventée signerait au nom d'un autre.
#   secrets/sdop-pades.key   clé ECDSA P-256 du sceau, lisible du seul uid du
#                            service ; ne quitte pas la machine (copie au
#                            coffre : geste humain)
#   secrets/sdop-pades.csr   sa demande de certificat (publique), à faire
#                            signer par l'AC de l'organisation (geste humain)
# Le certificat rendu (suivi de sa chaîne) se dépose en secrets/sdop-pades.crt,
# puis on RELANCE ce script : il vérifie qu'il porte la bonne clé et ajoute
# SDOP_PADES_KEY et SDOP_PADES_CERT au .env. Jamais avant : une configuration
# partielle empêche le service de démarrer. Le sceau reste FACULTATIF : un
# export sort non scellé si le sceau manque ou expire. Le rendre obligatoire
# est une décision d'exploitation, à poser à la main dans le .env :
# SDOP_PADES_REQUIRED=1 (un sceau absent ou expiré suspend alors les exports).
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

# ── Sceau PAdES des exports (watermark/pades.py) — facultatif ─────────────
# La clé naît ici et n'en sort pas (sauf copie au coffre, geste humain) ; seule
# la CSR, publique, part vers l'AC.
CLE_SCEAU="${ROOT}/secrets/sdop-pades.key"
CSR_SCEAU="${ROOT}/secrets/sdop-pades.csr"
CRT_SCEAU="${ROOT}/secrets/sdop-pades.crt"
# Valeur d'une ligne du .env, guillemets englobants retirés : écrite
# `SDOP_PADES_SUJET="/C=FR/O=…"`, elle reste sûre pour bash comme pour compose.
valeur_env() {
    local v; v="$(grep -m1 "^$1=" "${ENV}" 2>/dev/null | cut -d= -f2- || true)"
    v="${v#\"}"; v="${v%\"}"; v="${v#\'}"; v="${v%\'}"
    printf '%s' "${v}"
}
SUJET_SCEAU="${SDOP_PADES_SUJET:-$(valeur_env SDOP_PADES_SUJET)}"
SAN_SCEAU="${SDOP_PADES_SAN:-$(valeur_env SDOP_PADES_SAN)}"
if [[ -z "${SUJET_SCEAU}" && ! -s "${CLE_SCEAU}" ]]; then
    echo "  sceau PAdES : non configuré (SDOP_PADES_SUJET absent) — rien tiré, exports non scellés"
else
    if [[ -s "${CLE_SCEAU}" ]]; then
        echo "  secrets/sdop-pades.key : déjà présente, conservée"
    else
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${CLE_SCEAU}"
        echo "  secrets/sdop-pades.key : tirée (ECDSA P-256)"
    fi
    chown 65534:65534 "${CLE_SCEAU}"
    chmod 400 "${CLE_SCEAU}"
    if [[ ! -s "${CSR_SCEAU}" ]]; then
        [[ -n "${SUJET_SCEAU}" ]] \
            || { echo "ERREUR : clé de sceau présente mais SDOP_PADES_SUJET absent — CSR impossible" >&2; exit 1; }
        extensions=()
        [[ -n "${SAN_SCEAU}" ]] && extensions=(-addext "subjectAltName=${SAN_SCEAU}")
        openssl req -new -key "${CLE_SCEAU}" -out "${CSR_SCEAU}" -utf8 \
            -subj "${SUJET_SCEAU}" "${extensions[@]}"
        echo "  secrets/sdop-pades.csr : produite (publique, à faire signer)"
    fi
    chmod 644 "${CSR_SCEAU}"
    if [[ -s "${CRT_SCEAU}" ]]; then
        # Le certificat doit porter la clé d'ici : sinon le service refuserait de
        # démarrer — autant le dire maintenant.
        if [[ "$(openssl x509 -in "${CRT_SCEAU}" -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum)" \
              != "$(openssl pkey -in "${CLE_SCEAU}" -pubout -outform DER | sha256sum)" ]]; then
            echo "ERREUR : secrets/sdop-pades.crt ne correspond pas à secrets/sdop-pades.key" >&2
            exit 1
        fi
        chmod 644 "${CRT_SCEAU}"
        ajoute SDOP_PADES_KEY "/secrets/sdop-pades.key"
        ajoute SDOP_PADES_CERT "/secrets/sdop-pades.crt"
        chown "${PROPRIO}" "${ENV}"
        chmod 600 "${ENV}"
        echo "  sceau PAdES : actif au prochain démarrage, FACULTATIF (SDOP_PADES_REQUIRED=1 à poser à la main pour l'exiger)"
    else
        echo "  secrets/sdop-pades.crt : absent — sceau inactif tant qu'il n'est pas déposé"
    fi
fi

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
