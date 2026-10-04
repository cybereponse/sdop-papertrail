#!/usr/bin/env bash
# Critères d'acceptation automatisés — SDOP (Lot 1)
# Exerce SDOP + le socle identité partagé (nginx/Authentik/step-ca) : les deux
# doivent tourner. Le socle est un dépôt séparé (pas dupliqué ici) — voir
# CORE_DIR.
# Nécessite : curl, openssl, docker
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Chemin par défaut : dépôts clonés en frères, sous le même répertoire parent.
# Surcharger via CORE_DIR=/chemin/vers/core si ce n'est pas le cas.
CORE_DIR_DEFAULT="${ROOT}/../identity-stack/core"
CORE="$(cd "${CORE_DIR:-${CORE_DIR_DEFAULT}}" 2>/dev/null && pwd)" || {
    echo "ERR: core/ introuvable (CORE_DIR=${CORE_DIR:-${CORE_DIR_DEFAULT}})."
    echo "     SDOP dépend d'un socle identité (nginx + Authentik + step-ca) :"
    echo "     positionner CORE_DIR sur son répertoire core/."
    exit 1
}

# Les secrets (DOMAIN_INTERNAL, etc.) vivent dans core/.env — SDOP n'a pas de
# secret propre.
if [[ -f "${CORE}/.env" ]]; then
    set -a; source "${CORE}/.env"; set +a
fi

DOMAIN_CORE="${DOMAIN_INTERNAL:-example.internal}"
DOMAIN_SDOP="${DOMAIN_SDOP:-sdop.example.internal}"
APP_URL="https://app.${DOMAIN_SDOP}"
CA_CERT="${CORE}/pki/certs/root_ca.crt"
CLIENT_CERT="${CORE}/pki/certs/client/test-user.crt"
CLIENT_KEY="${CORE}/pki/certs/client/test-user.key"

PASS=0; FAIL=0; SKIP=0

check() {
    local desc="$1" result="$2"
    if [[ "${result}" == "ok" ]]; then
        echo "  [✓] ${desc}"; PASS=$((PASS+1))
    elif [[ "${result}" == SKIP* ]]; then
        echo "  [~] ${desc} — ${result}"; SKIP=$((SKIP+1))
    else
        echo "  [✗] ${desc} — ${result}"; FAIL=$((FAIL+1))
    fi
}

echo ""
echo "═══════════════════════════════════════════════════════"
echo " SDOP — Critères d'acceptation (Lot 1)"
echo "═══════════════════════════════════════════════════════"

# --- 0. Configuration compose valide (core + sdop) ---
echo ""
echo "--- 0. Validation configuration"
if docker compose --project-directory "${CORE}" config -q 2>/dev/null; then
    check "docker compose config (core)" "ok"
else
    check "docker compose config (core)" "invalide — voir: cd ${CORE} && docker compose config"
fi
if docker compose --project-directory "${ROOT}" config -q 2>/dev/null; then
    check "docker compose config (sdop)" "ok"
else
    check "docker compose config (sdop)" "invalide — voir: docker compose config"
fi

# --- 1. Healthchecks ---
# Aucun nom de conteneur en dur. Ceux du socle viennent de core/.env, sourcé
# plus haut ; les miens sont demandés à Compose — un nom qu'on ne calcule pas
# ne peut pas être faux.
echo ""
echo "--- 1. Healthchecks conteneurs"

# Tous les conteneurs n'ont pas de healthcheck (le nginx du socle n'en a pas) :
# sans ce repli, `.State.Health.Status` rend la chaîne vide et un conteneur
# sain est compté en échec.
etat_conteneur() {
    docker inspect \
        --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
        "$1" 2>/dev/null || echo "absent"
}
sain() { [[ "$1" == "healthy" || "$1" == "running" ]]; }

# `starting` n'est ni sain ni en panne : c'est le start_period du healthcheck,
# et le verdict dépendrait alors de la seconde où verify est lancé. Un harnais
# qui échoue selon l'heure ne dit rien du service. On attend, borné.
etat_stabilise() {
    local cible="$1" status
    for _ in $(seq 1 30); do
        status="$(etat_conteneur "${cible}")"
        [[ "${status}" == "starting" ]] || { echo "${status}"; return; }
        sleep 1
    done
    echo "starting (toujours, après 30 s)"
}

for svc in "${CN_POSTGRESQL:?CN_POSTGRESQL absent de core/.env}" \
           "${CN_AUTHENTIK_SERVER:?CN_AUTHENTIK_SERVER absent de core/.env}" \
           "${CN_STEPCA:?CN_STEPCA absent de core/.env}" \
           "${CN_NGINX:?CN_NGINX absent de core/.env}"; do
    status="$(etat_stabilise "${svc}")"
    check "socle — ${svc}" "$(sain "${status}" && echo ok || echo "${status}")"
done

mes_conteneurs="$(docker compose --project-directory "${ROOT}" ps -q 2>/dev/null || true)"
if [[ -z "${mes_conteneurs}" ]]; then
    check "conteneurs SDOP (demandés à Compose)" "aucun conteneur — run: make up"
else
    while read -r cid; do
        [[ -z "${cid}" ]] && continue
        nom="$(docker inspect --format='{{.Name}}' "${cid}" 2>/dev/null | sed 's|^/||')"
        status="$(etat_stabilise "${cid}")"
        check "sdop — ${nom:-${cid:0:12}}" "$(sain "${status}" && echo ok || echo "${status}")"
    done <<< "${mes_conteneurs}"
fi

# --- 2. Absence docker.sock ---
echo ""
echo "--- 2. Absence de montage docker.sock"
result=$(grep -rn "docker.sock" "${ROOT}" "${CORE}" --include="*.yml" --include="*.yaml" 2>/dev/null \
    | grep -v "^Binary" | grep -v "#" || true)
check "grep docker.sock (sdop + core)" "$([[ -z "${result}" ]] && echo ok || echo "TROUVÉ: ${result}")"

# --- 3. Refus sans cert client (TLS) ---
echo ""
echo "--- 3. mTLS — refus sans certificat client"
http_code=$(curl -sk --cacert "${CA_CERT}" -o /dev/null -w "%{http_code}" \
    "${APP_URL}" 2>/dev/null || echo "000")
check "Refus sans cert client (000 ou 400)" \
    "$([[ "${http_code}" == "000" || "${http_code}" == "400" ]] && echo ok || echo "code=${http_code}")"

# --- 4. Redirection avec cert valide non authentifié ---
echo ""
# On ne suit PAS la redirection : la chaîne vers Authentik en compte deux,
# légitimes, et `-L --max-redirs 1` faisait sortir curl en erreur. Le
# `|| echo "000"` concaténait alors sa sortie partielle au repli — d'où le
# un faux "code=302000", qui n'était pas un défaut du service.
echo "--- 4. Redirection vers Authentik avec cert valide"
if [[ -f "${CLIENT_CERT}" && -f "${CLIENT_KEY}" ]]; then
    http_code=$(curl -sk --cacert "${CA_CERT}" \
        --cert "${CLIENT_CERT}" --key "${CLIENT_KEY}" \
        -o /dev/null -w "%{http_code}" \
        "${APP_URL}" 2>/dev/null || echo "000")
    check "Cert valide => 302 ou 200 (page login)" \
        "$([[ "${http_code}" == "302" || "${http_code}" == "200" ]] && echo ok || echo "code=${http_code}")"
else
    check "Cert client test-user absent" "SKIP — run: cd ${CORE} && make gen-client-cert"
fi

# --- 5. Strip headers forgés ---
# Nécessite une session Authentik ouverte (mot de passe + TOTP franchis par un
# outil de recette du socle d'identité) ; un script bash ne le fait pas seul. Sans AUTH_COOKIE, SKIP — jamais
# silencieusement "ok".
# La cible est /_identite, pas la racine : depuis le Lot 2 la racine sert la
# visionneuse en HTML, et le parse JSON échouait sur une page parfaitement
# correcte.
echo ""
echo "--- 5. Strip des headers forgés"
if [[ -f "${CLIENT_CERT}" && -f "${CLIENT_KEY}" && -n "${AUTH_COOKIE:-}" ]]; then
    tmp_resp="$(mktemp)"
    curl -sk --cacert "${CA_CERT}" \
        --cert "${CLIENT_CERT}" --key "${CLIENT_KEY}" \
        -H "X-Authentik-Username: hacker-inject" \
        -H "X-Authentik-Meta-App: forge" \
        -H "X-Client-Cert-CN: faux-cn" \
        -H "Cookie: ${AUTH_COOKIE}" \
        -o "${tmp_resp}" "${APP_URL}/_identite" 2>/dev/null || true
    result=$(python3 - "${tmp_resp}" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"réponse non JSON (session expirée ?) : {e}")
    sys.exit(0)
ident = d.get("identite_de_confiance", {})
# La sonde ne rend plus que les NOMS des en-têtes hors liste blanche (SEC-002).
autres = {h.lower() for h in d.get("autres_entetes_recus", [])}
problemes = []
if ident.get("X-Authentik-Username") == "hacker-inject":
    problemes.append("X-Authentik-Username non strippé")
if ident.get("X-Client-Cert-CN") == "faux-cn":
    problemes.append("X-Client-Cert-CN non strippé")
if "x-authentik-meta-app" in autres:
    problemes.append("X-Authentik-Meta-App non strippé")
if "cookie" in autres or "authorization" in autres:
    problemes.append("la sonde restitue Cookie/Authorization (régression SEC-002)")
print(" ; ".join(problemes) if problemes else "ok")
PY
)
    rm -f "${tmp_resp}"
    check "Headers forgés strippés (username/CN/meta-app)" "${result}"
else
    check "Strip headers forgés" "SKIP — nécessite AUTH_COOKIE (cookie d'une session Authentik ouverte)"
fi

# --- 6. Certs signés par CA interne ---
echo ""
echo "--- 6. Certificats serveur signés par la CA interne"
if [[ -f "${CA_CERT}" ]]; then
    # ext : le vhost externe (accès sans compte par lien magique) n'existait
    # pas quand ce bloc a été écrit. Son certificat se vérifie comme les autres.
    for entry in "auth:${DOMAIN_CORE}" "app:${DOMAIN_SDOP}" "ext:${DOMAIN_SDOP}"; do
        svc="${entry%%:*}"; dom="${entry#*:}"
        cert="${CORE}/pki/certs/server/${svc}.crt"
        if [[ -f "${cert}" ]]; then
            result=$(openssl verify -CAfile "${CA_CERT}" "${cert}" 2>&1)
            check "Cert ${svc}.${dom}" "$([[ "${result}" == *"OK"* ]] && echo ok || echo "${result}")"
        else
            check "Cert ${svc}.${dom}" "absent — run: cd ${CORE} && make bootstrap"
        fi
    done
else
    check "root_ca.crt" "absent — run: cd ${CORE} && make bootstrap"
fi

# --- 7. Aucun secret committé ---
echo ""
echo "--- 7. Aucun secret réel committé"
if git -C "${ROOT}" rev-parse HEAD >/dev/null 2>&1; then
    tracked=$( { git -C "${ROOT}" ls-files | grep -E "(^|/)\.env$" || true; git -C "${CORE}" ls-files | grep -E "(^|/)\.env$" || true; } )
    check ".env absent de git ls-files (sdop + core)" "$([[ -z "${tracked}" ]] && echo ok || echo ".env tracké : ${tracked}")"
else
    check "Dépôt git non initialisé" "SKIP"
fi

# --- 8. Cohérence du vhost nginx installé ---
# `make install-vhost` fait un `cp`, pas un lien symbolique (bind-mount seul
# côté core/ — voir Makefile) : une édition de app.conf non suivie d'un
# nouvel install-vhost diverge silencieusement de ce qui tourne réellement.
echo ""
echo "--- 8. Vhost nginx à jour (make install-vhost)"
# `install-vhost` copie les quatre fichiers ; n'en vérifier qu'un laissait
# dériver en silence les trois autres — dont les fragments d'en-têtes, qui
# portent à eux seuls la propriété de strip.
for f in "${ROOT}"/nginx/conf.d/*; do
    nom="$(basename "${f}")"
    deploye="${CORE}/proxy/nginx/conf.d/${nom}"
    if [[ -f "${deploye}" ]]; then
        check "${nom} identique au fichier déployé" \
            "$([[ "$(sha256sum "${f}" | cut -d' ' -f1)" == "$(sha256sum "${deploye}" | cut -d' ' -f1)" ]] \
                && echo ok || echo "divergent — relancer : make install-vhost")"
    else
        check "${nom} déployé" "jamais installé — run: make install-vhost"
    fi
done

# --- Résumé ---
echo ""
echo "═══════════════════════════════════════════════════════"
echo " Résultat : ${PASS} passé(s) / ${SKIP} ignoré(s) / $((PASS+FAIL+SKIP)) total"
[[ $FAIL -eq 0 ]] \
    && echo " Statut   : ✓ TOUS LES CRITÈRES AUTOMATISÉS PASSENT" \
    || echo " Statut   : ✗ ${FAIL} critère(s) à corriger"
echo "═══════════════════════════════════════════════════════"
echo ""
exit $(( FAIL > 0 ? 1 : 0 ))
