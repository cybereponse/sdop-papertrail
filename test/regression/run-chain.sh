#!/usr/bin/env bash
# Palier 2 de bout en bout, sur un Docker LOCAL : certs de test, copie fraîche
# du vhost réel, build, démarrage, attente des sondes de santé, scénarios.
#
# Pourquoi ce script existe : un poste de développement peut piloter le Docker
# d'une VM ; la CI et la machine de validation, elles, ont un Docker local. Sans ce script, la même séquence serait écrite trois fois et
# divergerait — c'est exactement ce que SEC-010 reprochait au harnais.
#
# Variables : SDOP_TEST_PORT, SDOP_WM_PORT, SDOP_CHAIN_PORT, SDOP_EXT_PORT,
# SDOP_CHAIN_IP (déduite de DOCKER_HOST, voir plus bas)
# (décaler les QUATRE, pas trois : un port laissé à sa valeur par défaut suffit
# à faire échouer la pile sur un daemon partagé — décaler si le
# daemon est partagé), KEEP_UP=1 pour laisser la pile debout après les tests.
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${TEST_DIR}"

export SDOP_TEST_PORT="${SDOP_TEST_PORT:-8081}"
export SDOP_WM_PORT="${SDOP_WM_PORT:-8082}"
export SDOP_CHAIN_PORT="${SDOP_CHAIN_PORT:-8446}"
export SDOP_EXT_PORT="${SDOP_EXT_PORT:-8447}"

# Où joindre les ports publiés par la pile.
#
# Sur un Docker local, c'est la boucle locale. Sur un Docker DISTANT — le dind
# de la CI — les ports sont publiés dans le netns de ce daemon, et la boucle
# locale du harnais ne mène nulle part : la pile démarre, nginx tourne, et
# chaque scénario échoue sur une connexion refusée. C'est la raison pour
# laquelle le job `chain` n'a jamais réussi depuis son introduction, alors
# que `docker compose up` y réussissait parfaitement.
#
# Constaté avec un runner en réseau host et un dind voisin : la pile n'est
# joignable depuis le job qu'à l'adresse du dind, jamais par sa boucle locale.
#
# DOCKER_HOST porte précisément cette adresse quand le daemon est distant, et
# n'est pas défini quand il est local. On en déduit la cible plutôt que de la
# configurer : une variable de plus à renseigner serait une variable de plus à
# oublier.
if [[ -z "${SDOP_CHAIN_IP:-}" ]]; then
    if [[ -n "${DOCKER_HOST:-}" ]] && [[ "${DOCKER_HOST}" == tcp://* || "${DOCKER_HOST}" == ssh://* ]]; then
        SDOP_CHAIN_IP="$(printf '%s' "${DOCKER_HOST}" | sed -E 's|^[a-z]+://||; s|^[^@]*@||; s|:[0-9]+$||')"
        echo "==> daemon distant (${DOCKER_HOST}) : scénarios visant ${SDOP_CHAIN_IP}"
    else
        SDOP_CHAIN_IP=127.0.0.1
    fi
fi
export SDOP_CHAIN_IP

COMPOSE=(docker compose)
[[ -f .env ]] && COMPOSE+=(--env-file .env)

cleanup() {
    if [[ "${KEEP_UP:-0}" != "1" ]]; then
        echo "==> arrêt de la pile"
        "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "==> certificats de test (jetables)"
bash regression/gen-test-certs.sh | tail -1

echo "==> copie fraîche du vhost réel dans le contexte de build"
# Copié, jamais maintenu à part : ce qui est testé doit être exactement ce qui
# sera déployé (voir README.md du dossier test/).
mkdir -p regression/nginx-build/conf.d
cp ../nginx/conf.d/app.conf regression/nginx-build/conf.d/app.conf
cp ../nginx/conf.d/sdop-trusted-headers.inc regression/nginx-build/conf.d/sdop-trusted-headers.inc
cp ../nginx/conf.d/ext.conf regression/nginx-build/conf.d/ext.conf
cp ../nginx/conf.d/sdop-limits.conf regression/nginx-build/conf.d/sdop-limits.conf
cp ../nginx/conf.d/sdop-ext-headers.inc regression/nginx-build/conf.d/sdop-ext-headers.inc
cp ../nginx/conf.d/sdop-ext-locations.inc regression/nginx-build/conf.d/sdop-ext-locations.inc

echo "==> build"
"${COMPOSE[@]}" build

echo "==> validation de la configuration nginx"
# `docker compose config` ne lit pas les fichiers nginx : une erreur de syntaxe
# s'y voit seulement au démarrage, sous forme d'un conteneur qui redémarre en
# boucle et de scénarios qui échouent pour une raison sans rapport.
if ! "${COMPOSE[@]}" run --rm --entrypoint nginx nginx -t 2>&1 | tail -3; then
    echo "ERR: configuration nginx invalide — scénarios non lancés." >&2
    exit 1
fi

echo "==> démarrage"
"${COMPOSE[@]}" up -d

echo "==> attente des sondes de santé"
# `up -d` rend la main avant que les services soient prêts. Un verify lancé
# trop tôt échoue pour une raison qui n'a rien à voir avec ce qu'il teste.
#
# Les conteneurs SANS sonde (nginx : il n'écoute qu'en mTLS, aucune sonde HTTP
# simple n'aurait de sens) rendent un champ Health vide. Les compter comme
# « pas prêts » ferait attendre la boucle entière à chaque exécution, pour
# rien — on ne retient que les services qui ont réellement une sonde.
for _ in $(seq 1 40); do
    restants=$("${COMPOSE[@]}" ps --format '{{.Health}}' \
        | grep -v '^$' | grep -cv '^healthy$' || true)
    [[ "${restants}" == "0" ]] && break
    sleep 5
done
"${COMPOSE[@]}" ps --format 'table {{.Name}}\t{{.Status}}'

echo "==> scénarios"
bash regression/verify_chain.sh
