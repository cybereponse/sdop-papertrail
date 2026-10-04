#!/usr/bin/env bash
# Démo autonome SDOP — pilotée par `make quickstart*` (voir demo/README.md).
#
#   up      construit, crée PKI et clés au premier appel (conservées ensuite),
#           valide la configuration nginx, démarre, exporte le certificat
#           client et la CA de démo dans var/quickstart/<projet>/
#   down    arrête — documents, journal, PKI et clés CONSERVÉS
#   renew   réémet les certificats feuilles (même CA), redémarre nginx
#   check   recette : scénarios de la chaîne, isolement, journal non vide
#   reset   DÉTRUIT documents, journal, PKI et clés de la démo (confirmation)
#
# Ne touche ni au déploiement intégré (../docker-compose.yml) ni au harnais
# (../test/) : projet Compose `sdop-demo` (ou COMPOSE_PROJECT_NAME), volumes et
# réseaux à lui, marqués org.sdop.demo=1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO="${ROOT}/demo"
DOMAIN="sdop.localhost"

PORT="${SDOP_DEMO_PORT:-8443}"
if ! [[ "${PORT}" =~ ^[0-9]{1,5}$ ]] || (( 10#${PORT} < 1 || 10#${PORT} > 65535 )); then
    echo "ERR: SDOP_DEMO_PORT doit être un port (1-65535) : « ${PORT} »" >&2; exit 2
fi
export SDOP_DEMO_PORT="${PORT}"

# Projet Compose EFFECTIF, fixé ici et passé explicitement (-p) : c'est lui
# qu'on affiche, lui qu'on confirme, lui qu'on supprime (SEC-029).
PROJECT="${COMPOSE_PROJECT_NAME:-sdop-demo}"
if ! [[ "${PROJECT}" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
    echo "ERR: nom de projet Compose invalide : « ${PROJECT} »" >&2; exit 2
fi
# Exports propres à chaque instance : deux projets ne partagent pas leurs clés.
OUT="${ROOT}/var/quickstart/${PROJECT}"

# --project-directory : le `.env` éventuel de la racine (déploiement intégré)
# n'est jamais lu par la démo.
COMPOSE=(docker compose -p "${PROJECT}" --project-directory "${DEMO}" -f "${DEMO}/compose.yml")

pki() {
    "${COMPOSE[@]}" --profile outils run --rm -T --no-deps pki python - "$@" \
        < "${DEMO}/pki.py"
}

# Copie un fichier du volume `ca` vers l'hôte, sans bind-mount (démon distant).
exporter() {
    local src="$1" dst="$2" mode="$3"
    "${COMPOSE[@]}" --profile outils run --rm -T --no-deps pki cat "/ca/${src}" \
        > "${OUT}/${dst}.tmp"
    chmod "${mode}" "${OUT}/${dst}.tmp"
    mv "${OUT}/${dst}.tmp" "${OUT}/${dst}"
}

exporter_tout() {
    mkdir -p "${OUT}"
    chmod 700 "${OUT}"
    exporter ca.crt                ca.crt              644
    exporter client/client.p12     sdop-demo-client.p12 600
    # PEM pour curl et la recette ; noms attendus par verify_chain.sh.
    exporter client/client.crt     client.crt          644
    exporter client/client.key     client.key          600
    exporter client/revoked.crt    client-revoque.crt  644
    exporter client/revoked.key    client-revoque.key  600
}

attendre_sante() {
    for _ in $(seq 1 40); do
        restants=$("${COMPOSE[@]}" ps --format '{{.Health}}' \
            | grep -v '^$' | grep -cv '^healthy$' || true)
        [[ "${restants}" == "0" ]] && return 0
        sleep 3
    done
    echo "ERR: services pas en bonne santé :" >&2
    "${COMPOSE[@]}" ps >&2
    return 1
}

cmd_up() {
    echo "==> build"
    "${COMPOSE[@]}" build
    echo "==> PKI et clés de démo"
    pki
    exporter_tout
    echo "==> validation de la configuration nginx"
    if ! "${COMPOSE[@]}" run --rm --entrypoint nginx nginx -t 2>&1 | tail -2; then
        echo "ERR: configuration nginx invalide." >&2
        exit 1
    fi
    echo "==> démarrage"
    "${COMPOSE[@]}" up -d
    attendre_sante
    # La CRL est régénérée à chaque `up` : nginx la relit au reload.
    "${COMPOSE[@]}" exec -T nginx nginx -s reload >/dev/null
    cat <<EOF

✔ SDOP démo démarrée — ⚠ AUCUNE AUTHENTIFICATION RÉELLE, documents fictifs uniquement.

  Application  https://app.${DOMAIN}:${PORT}/
  Accès lien   https://ext.${DOMAIN}:${PORT}/lien/<jeton>

  Deux réglages navigateur, distincts (voir demo/README.md) :
   1. Certificat CLIENT (mTLS) — importer :
        ${OUT}/sdop-demo-client.p12   (mot de passe : sdop-demo)
   2. Certificat SERVEUR — signé par la CA de démo ${OUT}/ca.crt :
        accepter l'avertissement, ou faire confiance à cette CA dans un
        PROFIL de navigateur dédié. Ne pas l'installer dans le magasin système.

  Si *.localhost ne résout pas : ajouter à /etc/hosts
        127.0.0.1 app.${DOMAIN} ext.${DOMAIN} ${DOMAIN}

  Arrêter : make quickstart-down     Recette : make quickstart-check
EOF
}

cmd_down() {
    "${COMPOSE[@]}" down
    echo "✔ Démo arrêtée — documents, journal, PKI et clés conservés."
}

cmd_renew() {
    pki --renew
    exporter_tout
    "${COMPOSE[@]}" restart nginx
    echo "✔ Certificats réémis (même CA) — réimporter ${OUT}/sdop-demo-client.p12."
}

cmd_reset() {
    # Ce que `down -v` peut retirer, calculé depuis le modèle Compose RÉSOLU (et
    # non depuis un filtre d'étiquettes, qui ne voit pas un volume homonyme sans
    # étiquette) : conteneurs du projet, volumes et réseaux nommés par le modèle.
    # Chacun doit porter org.sdop.demo=1 ET l'étiquette de ce projet, sinon
    # refus. Toute erreur d'inventaire arrête tout (SEC-029).
    local modele attendus existants_v existants_r conteneurs
    local etrangers=() ressources=() type nom info
    modele="$("${COMPOSE[@]}" --profile outils config --format json)" \
        || { echo "ERR: modèle Compose illisible — rien supprimé" >&2; exit 1; }
    attendus="$(python3 -c '
import json, sys
d = json.load(sys.stdin)
for cle, v in sorted((d.get("volumes") or {}).items()):
    if v.get("external"): sys.exit("volume externe : " + cle)
    print("volume", v["name"])
for cle, v in sorted((d.get("networks") or {}).items()):
    if v.get("external"): sys.exit("réseau externe : " + cle)
    print("réseau", v["name"])
' <<< "${modele}")" || { echo "ERR: inventaire du modèle impossible — rien supprimé" >&2; exit 1; }
    existants_v="$(docker volume ls --format '{{.Name}}')" \
        || { echo "ERR: liste des volumes impossible — rien supprimé" >&2; exit 1; }
    existants_r="$(docker network ls --format '{{.Name}}')" \
        || { echo "ERR: liste des réseaux impossible — rien supprimé" >&2; exit 1; }
    conteneurs="$(docker ps -a --filter "label=com.docker.compose.project=${PROJECT}" \
        --format '{{.Names}} {{.Label "org.sdop.demo"}} {{.Label "com.docker.compose.project"}} {{.Label "com.docker.compose.oneoff"}}')" \
        || { echo "ERR: liste des conteneurs impossible — rien supprimé" >&2; exit 1; }

    local montes="" m
    while read -r nom marque projet ponctuel; do
        [[ -z "${nom}" ]] && continue
        # Un `run` encore présent (outil PKI interrompu) : `down` ne le retire
        # pas et garde ses volumes « en usage » — refuser plutôt qu'annoncer un
        # nettoyage qui n'aura pas lieu.
        if [[ "${ponctuel}" == "True" ]]; then
            echo "ERR: conteneur ponctuel ${nom} encore présent (outil PKI interrompu ?)." >&2
            echo "     Le retirer d'abord : docker rm -f ${nom} — rien supprimé." >&2
            exit 1
        fi
        ressources+=("conteneur ${nom}")
        [[ "${marque}" == "1" && "${projet}" == "${PROJECT}" ]] || etrangers+=("conteneur ${nom}")
        # Volumes RÉELLEMENT montés : `down -v` retire aussi les volumes
        # anonymes, que le modèle ne nomme pas.
        m="$(docker inspect -f '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}} {{end}}{{end}}' "${nom}")" \
            || { echo "ERR: inspection du conteneur ${nom} impossible — rien supprimé" >&2; exit 1; }
        montes+="${m}"
    done <<< "${conteneurs}"
    for m in ${montes}; do
        grep -qxF -- "volume ${m}" <<< "${attendus}" \
            || attendus+=$'\n'"volume ${m}"
    done

    while read -r type nom; do
        [[ -z "${nom}" ]] && continue
        if [[ "${type}" == volume ]]; then
            grep -qxF -- "${nom}" <<< "${existants_v}" || continue
            info="$(docker volume inspect -f '{{index .Labels "org.sdop.demo"}} {{index .Labels "com.docker.compose.project"}}' "${nom}")" \
                || { echo "ERR: inspection du volume ${nom} impossible — rien supprimé" >&2; exit 1; }
        else
            grep -qxF -- "${nom}" <<< "${existants_r}" || continue
            info="$(docker network inspect -f '{{index .Labels "org.sdop.demo"}} {{index .Labels "com.docker.compose.project"}}' "${nom}")" \
                || { echo "ERR: inspection du réseau ${nom} impossible — rien supprimé" >&2; exit 1; }
        fi
        ressources+=("${type} ${nom}")
        [[ "${info}" == "1 ${PROJECT}" ]] || etrangers+=("${type} ${nom}")
    done <<< "${attendus}"

    if (( ${#etrangers[@]} )); then
        echo "ERR: le projet « ${PROJECT} » viserait des ressources qui ne sont pas" >&2
        echo "     celles de cette démo — rien supprimé :" >&2
        printf '       %s\n' "${etrangers[@]}" >&2
        exit 1
    fi
    echo "⚠ Détruit DÉFINITIVEMENT, pour le projet Compose « ${PROJECT} » :"
    printf '    %s\n' ${ressources[@]+"${ressources[@]}"}
    echo "    ${OUT}"
    if [[ "${CONFIRM:-}" != "${PROJECT}" ]]; then
        read -r -p "Taper le nom du projet pour confirmer : " c
        [[ "${c}" == "${PROJECT}" ]] || { echo "Annulé."; exit 1; }
    fi
    "${COMPOSE[@]}" --profile outils down -v
    # Postcondition : rien de ce qui était inventorié ne doit subsister.
    local restes=() vols nets
    vols="$(docker volume ls --format '{{.Name}}')" \
        || { echo "ERR: vérification impossible après suppression" >&2; exit 1; }
    nets="$(docker network ls --format '{{.Name}}')" \
        || { echo "ERR: vérification impossible après suppression" >&2; exit 1; }
    [[ -z "$(docker ps -aq --filter "label=com.docker.compose.project=${PROJECT}")" ]] \
        || restes+=("conteneur(s) du projet")
    while read -r type nom; do
        [[ -z "${nom}" ]] && continue
        if [[ "${type}" == volume ]]; then grep -qxF -- "${nom}" <<< "${vols}" && restes+=("volume ${nom}")
        else grep -qxF -- "${nom}" <<< "${nets}" && restes+=("réseau ${nom}"); fi
    done <<< "${attendus}"
    if (( ${#restes[@]} )); then
        echo "ERR: réinitialisation incomplète — subsistent :" >&2
        printf '       %s\n' "${restes[@]}" >&2
        echo "     Exports locaux conservés (${OUT})." >&2
        exit 1
    fi
    rm -rf "${OUT}"
    echo "✔ Démo « ${PROJECT} » réinitialisée."
}

cmd_check() {
    local echecs=0

    # Les scénarios de lien et de débit consomment le quota du limiteur nginx
    # (zones en mémoire) : deux recettes rapprochées échoueraient en 429 pour
    # une raison étrangère à ce qu'elles vérifient. nginx redémarré = quota vide.
    "${COMPOSE[@]}" restart nginx >/dev/null 2>&1 \
        || { echo "ERR: redémarrage de nginx impossible" >&2; exit 1; }
    local _
    for _ in $(seq 1 30); do
        [[ "$(curl -s -o /dev/null -w '%{http_code}' --resolve "app.${DOMAIN}:${PORT}:${SDOP_CHAIN_IP:-127.0.0.1}" \
              --cacert "${OUT}/ca.crt" --cert "${OUT}/client.crt" --key "${OUT}/client.key" \
              "https://app.${DOMAIN}:${PORT}/health" 2>/dev/null)" == 200 ]] && break
        sleep 1
    done

    echo "==> isolement : seul nginx est publié, et sur la boucle locale (SEC-005)"
    # Lu dans la configuration du conteneur : `compose port` répond « :0 » avec
    # un code 0 pour un port non publié, inutilisable comme preuve.
    for svc in watermark placeholder authentik-server; do
        id=$("${COMPOSE[@]}" ps -q "${svc}")
        liaisons=$(docker inspect -f '{{json .HostConfig.PortBindings}}' "${id}" 2>/dev/null || echo "?")
        if [[ "${liaisons}" == "{}" || "${liaisons}" == "null" ]]; then
            echo "  [✓] ${svc} : aucun port publié"
        else
            echo "  [✗] ${svc} : ${liaisons}"; echecs=$((echecs+1))
        fi
    done
    ecoute=$("${COMPOSE[@]}" port nginx 443 || true)
    if [[ "${ecoute}" == "127.0.0.1:${PORT}" ]]; then
        echo "  [✓] nginx publié sur 127.0.0.1:${PORT} seulement"
    else
        echo "  [✗] nginx publié sur « ${ecoute} »"; echecs=$((echecs+1))
    fi

    echo "==> aucun backend ne joint un autre backend (réseaux séparés, SEC-005)"
    # Pour chaque origine : un témoin (elle-même, par son nom) qui doit
    # réussir — sinon la sonde est inopérante depuis cette origine — puis
    # chaque autre backend, par son NOM et par chacune de ses ADRESSES IP : une
    # absence de DNS ne prouve pas une absence de route.
    local -a services=(watermark:5000 placeholder:8080 authentik-server:9000)
    # sonde <origine> <hôte> <port> : 0 = connexion établie, 3 = refus ou
    # absence de route MESURÉS. Tout autre code (exec impossible, Python absent,
    # conteneur arrêté…) est une erreur de recette, jamais un « bloqué ».
    sonde() {
        local rc=0
        "${COMPOSE[@]}" exec -T "$1" python -c "
import socket, sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2)
except OSError:
    sys.exit(3)
sys.exit(0)" "$2" "$3" 2>/dev/null || rc=$?
        return "${rc}"
    }
    for origine_svc in "${services[@]}"; do
        local origine="${origine_svc%%:*}" port_o="${origine_svc##*:}"
        local rc=0
        sonde "${origine}" "${origine}" "${port_o}" || rc=$?
        if (( rc == 0 )); then
            echo "  [✓] témoin : ${origine} joint ${origine}:${port_o}"
        else
            echo "  [✗] témoin : ${origine} ne joint pas ${origine}:${port_o} (code ${rc}) — sonde inopérante"
            echecs=$((echecs+1)); continue
        fi
        for cible_svc in "${services[@]}"; do
            local cible="${cible_svc%%:*}" port="${cible_svc##*:}" ips hote
            [[ "${cible}" == "${origine}" ]] && continue
            ips="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.GlobalIPv6Address}} {{end}}' \
                "$("${COMPOSE[@]}" ps -q "${cible}")")" \
                || { echo "  [✗] adresses de ${cible} illisibles"; echecs=$((echecs+1)); continue; }
            # Docker rend une adresse absente par « invalid IP » ou une chaîne
            # vide selon les versions : ne garder que de vraies adresses.
            local brut="${ips}" x
            ips=""
            for x in ${brut}; do
                [[ "${x}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || "${x}" =~ ^[0-9a-fA-F:]+:[0-9a-fA-F:]*$ ]] \
                    && ips+="${x} "
            done
            if [[ -z "${ips// /}" ]]; then
                echo "  [✗] aucune adresse connue pour ${cible} — sonde par IP impossible"
                echecs=$((echecs+1)); continue
            fi
            for hote in "${cible}" ${ips}; do
                rc=0; sonde "${origine}" "${hote}" "${port}" || rc=$?
                case "${rc}" in
                    0) echo "  [✗] ${origine} joint ${cible} (${hote}:${port})"; echecs=$((echecs+1)) ;;
                    3) echo "  [✓] ${origine} ne joint pas ${cible} (${hote}:${port})" ;;
                    *) echo "  [✗] sonde ${origine} → ${hote}:${port} en erreur (code ${rc}) — rien de mesuré"
                       echecs=$((echecs+1)) ;;
                esac
            done
        done
    done

    echo "==> garde-fou du faux fournisseur d'identité (nom hors .localhost)"
    code=$("${COMPOSE[@]}" exec -T authentik-server python -c "
import urllib.request, urllib.error
r = urllib.request.Request('http://localhost:9000/outpost.goauthentik.io/auth/nginx',
                           headers={'Host': 'sdop.example.net'})
try:
    print(urllib.request.urlopen(r).status)
except urllib.error.HTTPError as e:
    print(e.code)")
    if [[ "${code}" == "403" ]]; then
        echo "  [✓] identité refusée hors domaine de démo (403)"
    else
        echo "  [✗] stub a répondu ${code} hors domaine de démo"; echecs=$((echecs+1))
    fi

    echo "==> scénarios de la chaîne (mêmes que le harnais)"
    if ! SDOP_CHAIN_CERTS="${OUT}" SDOP_CHAIN_PORT="${PORT}" SDOP_EXT_PORT="${PORT}" \
         SDOP_CHAIN_HOST="app.${DOMAIN}" SDOP_CHAIN_EXT_HOST="ext.${DOMAIN}" \
         SDOP_CHAIN_STUB_USER="${STUB_USERNAME:-demo}" SDOP_CHAIN_CLIENT_CN="demo-user" \
         SDOP_CHAIN_IP="${SDOP_CHAIN_IP:-127.0.0.1}" \
         bash "${ROOT}/test/regression/verify_chain.sh"; then
        echecs=$((echecs+1))
    fi

    echo "==> journal de la démo : au moins un événement, chaîne intacte"
    # Dans le conteneur : c'est le volume de la démo qui est vérifié, pas un
    # journal local qui traînerait sur le poste. verify-ledger.sh réussit sur un
    # répertoire vide ; ici un journal vide est un échec.
    if "${COMPOSE[@]}" exec -T watermark python - <<'PY'
import glob, sys
import ledger
segments = sorted(glob.glob("/journal/ledger-*.jsonl"))
total = 0
for s in segments:
    if not ledger.verify(s):
        print(f"  [✗] {s} : chaîne rompue"); sys.exit(1)
    total += ledger.count(s)
if total == 0:
    print("  [✗] aucun événement journalisé"); sys.exit(1)
print(f"  [✓] {len(segments)} segment(s), {total} événement(s), chaînes intactes")
PY
    then :; else echecs=$((echecs+1)); fi

    echo ""
    if (( echecs > 0 )); then
        echo "✗ Recette démo : ${echecs} bloc(s) en échec."
        exit 1
    fi
    echo "✔ Recette démo réussie."
}

case "${1:-}" in
    up|down|renew|reset|check) "cmd_$1" ;;
    *) echo "usage: $0 up|down|renew|check|reset" >&2; exit 2 ;;
esac
