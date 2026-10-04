#!/usr/bin/env bash
# Palier 2 — scénarios contre la vraie chaîne stubbée (nginx réel + stub-auth
# + placeholder + watermark). Voir ../README.md.
#
# La sonde d'identité (placeholder) vit désormais sous /_identite : c'est elle
# qui rend le strip+inject observable. L'application SDOP (watermark) est
# servie à la racine et exercée ici de bout en bout : publier, consulter,
# exporter — toujours à travers nginx, jamais en direct.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Les défauts sont ceux du harnais. La démo autonome (demo/quickstart.sh)
# rejoue les MÊMES scénarios contre sa propre pile en surchargeant ces cinq
# variables — un seul jeu de scénarios, pas deux qui divergent.
CERTS="${SDOP_CHAIN_CERTS:-$DIR/nginx-build/certs}"
PORT="${SDOP_CHAIN_PORT:-8446}"
HOST="${SDOP_CHAIN_HOST:-app.sdop.example.internal}"
EXT_HOST="${SDOP_CHAIN_EXT_HOST:-ext.sdop.example.internal}"
STUB_USER="${SDOP_CHAIN_STUB_USER:-test-regression}"
CLIENT_CN="${SDOP_CHAIN_CLIENT_CN:-test-user}"
EXT_PORT="${SDOP_EXT_PORT:-8447}"
EXT_BASE="https://${EXT_HOST}:${EXT_PORT}"

# Le certificat serveur est VÉRIFIÉ contre la CA de test (pas de -k) et le nom
# demandé est le vrai `server_name` du vhost, résolu localement par --resolve.
# Utiliser -k reviendrait à tester toute la chaîne SAUF ce que le TLS garantit :
# qu'on parle bien au serveur attendu (SEC-010).
# Adresse où les ports de la pile sont RÉELLEMENT publiés. 127.0.0.1 sur un
# Docker local ; sur un Docker distant — le dind de la CI — les ports vivent
# dans le netns de ce daemon et la boucle locale du harnais ne mène nulle part.
# run-chain.sh la déduit de DOCKER_HOST.
CHAIN_IP="${SDOP_CHAIN_IP:-127.0.0.1}"

BASE="https://${HOST}:${PORT}"
RESOLVE=(--resolve "${HOST}:${PORT}:${CHAIN_IP}")
TLS=("${RESOLVE[@]}" --cacert "${CERTS}/ca.crt")
MTLS=("${TLS[@]}" --cert "${CERTS}/client.crt" --key "${CERTS}/client.key")
# Vhost externe : certificat serveur vérifié, AUCUN certificat client — c'est
# tout l'objet de ce chemin.
EXT=(--resolve "${EXT_HOST}:${EXT_PORT}:${CHAIN_IP}" --cacert "${CERTS}/ca.crt")

PASS=0; FAIL=0
check() {
    local desc="$1" ok="$2"
    if [[ "$ok" == "ok" ]]; then
        echo "  [✓] ${desc}"; PASS=$((PASS+1))
    else
        echo "  [✗] ${desc} — ${ok}"; FAIL=$((FAIL+1))
    fi
}

echo "--- 0. Le certificat serveur est valide et au bon nom ---"
# Scénario propre à SEC-010 : si ce test échoue, tous les suivants ne prouvent
# plus rien sur l'identité du serveur.
code=$(curl -s "${TLS[@]}" --cert "${CERTS}/client.crt" --key "${CERTS}/client.key" \
    -o /dev/null -w "%{http_code}" "${BASE}/health" 2>/dev/null || echo "000")
check "certificat serveur vérifié contre la CA de test (sans -k)" \
    "$([[ "${code}" == "200" ]] && echo ok || echo "code=${code}")"

echo "--- 0b. Un serveur présentant un autre certificat est refusé ---"
# Vérifie que la vérification TLS mord vraiment : la même requête contre une CA
# qui n'a pas signé ce serveur doit échouer.
openssl req -x509 -newkey rsa:2048 -days 1 -nodes -keyout /tmp/sdop-wrong.key \
    -out /tmp/sdop-wrong.crt -subj "/CN=Autre CA" >/dev/null 2>&1
# On teste le CODE DE SORTIE de curl, pas le code HTTP : quand la poignée de
# main TLS échoue, il n'y a pas de réponse HTTP du tout, et `-w %{http_code}`
# ne produit rien d'exploitable.
if curl -s "${RESOLVE[@]}" --cacert /tmp/sdop-wrong.crt \
        --cert "${CERTS}/client.crt" --key "${CERTS}/client.key" \
        -o /dev/null "${BASE}/health" 2>/dev/null; then
    resultat="la connexion a abouti alors que la CA ne signe pas ce serveur"
else
    resultat="ok"
fi
rm -f /tmp/sdop-wrong.key /tmp/sdop-wrong.crt
check "refus si la CA ne correspond pas" "${resultat}"

echo "--- 1. Sans certificat client → refus ---"
code=$(curl -s "${TLS[@]}" -o /dev/null -w "%{http_code}" "${BASE}/" 2>/dev/null || echo "000")
check "refus sans cert client (000/400)" \
    "$([[ "${code}" == "000" || "${code}" == "400" ]] && echo ok || echo "code=${code}")"

echo "--- 1b. Certificat client RÉVOQUÉ → refus (ssl_crl) ---"
# Une version antérieure acceptait l'absence de révocation temps réel ; `ssl_crl`
# est désormais actif dans app.conf. Ce scénario vérifie qu'il mord : le
# certificat révoqué est signé par la MÊME CA de test que `client.crt`, et
# n'est refusé que parce qu'il figure dans crl.pem.
#
# Deux pièges, tous deux vérifiés :
#   · nginx garde la CRL en mémoire — un `ssl_crl` ajouté sans reload ne
#     change rien (ici la pile démarre avec, donc sans objet) ;
#   · si crl.pem manque ou est périmée, nginx refuse TOUT client, et le
#     scénario 2 tomberait aussi. Un échec isolé ici veut bien dire qu'un
#     certificat révoqué passe.
code=$(curl -s "${TLS[@]}" \
    --cert "${CERTS}/client-revoque.crt" --key "${CERTS}/client-revoque.key" \
    -o /dev/null -w "%{http_code}" "${BASE}/" 2>/dev/null || echo "000")
check "refus du certificat révoqué (000/400), CA identique au certificat accepté" \
    "$([[ "${code}" == "000" || "${code}" == "400" ]] && echo ok || echo "code=${code}")"

echo "--- 2. Cert valide + stub connecté (sonde /_identite) ---"
resp=$(curl -s "${MTLS[@]}" "${BASE}/_identite")
result=$(echo "${resp}" | STUB_USER="${STUB_USER}" CLIENT_CN="${CLIENT_CN}" python3 -c "
import json, os, sys
d = json.load(sys.stdin)
ident = d['identite_de_confiance']
pb = []
if ident.get('X-Authentik-Username') != os.environ['STUB_USER']:
    pb.append(f\"username inattendu: {ident.get('X-Authentik-Username')}\")
if ident.get('X-Client-Cert-CN') != os.environ['CLIENT_CN']:
    pb.append(f\"CN inattendu: {ident.get('X-Client-Cert-CN')}\")
print(' ; '.join(pb) if pb else 'ok')
")
check "identité stub correctement injectée" "${result}"

echo "--- 3. Forgery : en-têtes forgés envoyés par le client ---"
resp=$(curl -s "${MTLS[@]}" \
    -H "X-Authentik-Username: hacker-inject" \
    -H "X-Client-Cert-CN: faux-cn" \
    -H "X-Authentik-Groups: tlp-red-emetteurs" \
    -H "X-Authentik-Meta-App: forge" \
    "${BASE}/_identite")
result=$(echo "${resp}" | STUB_USER="${STUB_USER}" CLIENT_CN="${CLIENT_CN}" python3 -c "
import json, os, sys
d = json.load(sys.stdin)
ident = d['identite_de_confiance']
# Noms seulement depuis SEC-002 : la sonde ne rend plus aucune valeur.
autres = {h.lower() for h in d['autres_entetes_recus']}
pb = []
if ident.get('X-Authentik-Username') != os.environ['STUB_USER']:
    pb.append('X-Authentik-Username non strippé')
if ident.get('X-Client-Cert-CN') != os.environ['CLIENT_CN']:
    pb.append('X-Client-Cert-CN non strippé')
if ident.get('X-Authentik-Groups') != 'tlp-amber-emetteurs':
    pb.append(f\"X-Authentik-Groups non strippé: {ident.get('X-Authentik-Groups')}\")
if 'x-authentik-meta-app' in autres:
    pb.append('X-Authentik-Meta-App non strippé')
if 'cookie' in autres or 'authorization' in autres:
    pb.append('la sonde restitue Cookie/Authorization (régression SEC-002)')
print(' ; '.join(pb) if pb else 'ok')
")
check "en-têtes forgés strippés (chaîne réelle nginx/conf.d/app.conf)" "${result}"

echo "--- 4. Application SDOP servie à la racine ---"
resp=$(curl -s "${MTLS[@]}" "${BASE}/")
check "page d'accueil SDOP rendue" \
    "$(echo "${resp}" | grep -q "SDOP — diffusion documentaire attribuée" \
        && echo ok || echo 'page inattendue')"

echo "--- 5. Publication + consultation + export (identité du stub) ---"
PDF="$(mktemp "${TMPDIR:-/tmp}/sdop-chain-XXXXXX").pdf"
# PDF minimal valide, écrit sans dépendance : une page, pas de contenu utile.
printf '%%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\ntrailer<</Root 1 0 R>>\n' > "${PDF}"

pub=$(curl -s "${MTLS[@]}" -H "Accept: application/json" \
    -F "tlp=TLP:AMBER" -F "document=@${PDF}" "${BASE}/api/publish")
DOC=$(echo "${pub}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('doc_id',''))" 2>/dev/null || echo "")
rm -f "${PDF}"
check "publication acceptée pour un émetteur habilité" \
    "$([[ -n "${DOC}" ]] && echo ok || echo "réponse: ${pub:0:160}")"

if [[ -n "${DOC}" ]]; then
    code=$(curl -s "${MTLS[@]}" -o /dev/null -w "%{http_code}" "${BASE}/viewer/${DOC}")
    check "visionneuse accessible au lecteur habilité" \
        "$([[ "${code}" == "200" ]] && echo ok || echo "code=${code}")"

    ctype=$(curl -s "${MTLS[@]}" -o /dev/null -w "%{content_type}" \
        "${BASE}/api/export/${DOC}.pdf")
    check "export filigrané servi en application/pdf" \
        "$([[ "${ctype}" == "application/pdf" ]] && echo ok || echo "content-type=${ctype}")"

    # Le stub n'est habilité qu'en AMBER : publier en RED doit être refusé
    # CÔTÉ SERVEUR, même si le client prétend le contraire dans ses en-têtes.
    PDF2="$(mktemp "${TMPDIR:-/tmp}/sdop-chain-XXXXXX").pdf"
    printf '%%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\ntrailer<</Root 1 0 R>>\n' > "${PDF2}"
    code=$(curl -s "${MTLS[@]}" -o /dev/null -w "%{http_code}" \
        -H "X-Authentik-Groups: tlp-red-emetteurs" \
        -F "tlp=TLP:RED" -F "document=@${PDF2}" "${BASE}/api/publish")
    rm -f "${PDF2}"
    check "publication TLP:RED refusée malgré un groupe forgé (403)" \
        "$([[ "${code}" == "403" ]] && echo ok || echo "code=${code}")"

    code=$(curl -s "${MTLS[@]}" -o /dev/null -w "%{http_code}" \
        "${BASE}/api/view/${DOC}/page/0.png")
    check "tuile sans URL signée refusée (403)" \
        "$([[ "${code}" == "403" ]] && echo ok || echo "code=${code}")"
fi

# Pas de scénario « habilité mais non destinataire » ici : le stub n'expose
# qu'une seule identité, et c'est elle qui publie — elle est donc émettrice de
# tout document créé par ce harnais, donc toujours autorisée. Distinguer
# « émetteur » de « habilité non destinataire » exigerait un second compte, que
# le stub ne sait pas fournir. Ce cas est couvert au Palier 1
# (test_habilite_mais_non_destinataire_refuse) ; le prétendre vérifié ici
# donnerait une assurance fausse.

echo "--- 7. Lien nominatif : second facteur exigé ---"
if [[ -n "${DOC}" ]]; then
    lien=$(curl -s "${MTLS[@]}" -H "Accept: application/json" \
        -F "destinataire=victime@exemple.invalid" "${BASE}/api/lien/${DOC}")
    JETON=$(echo "${lien}" | python3 -c "
import json,sys
d=json.load(sys.stdin); print(d.get('url','').rsplit('/',1)[-1])" 2>/dev/null || echo "")
    CODE=$(echo "${lien}" | python3 -c "
import json,sys; print(json.load(sys.stdin).get('code') or '')" 2>/dev/null || echo "")
    check "lien émis pour un TLP:AMBER" \
        "$([[ -n "${JETON}" && ${#CODE} -eq 8 ]] && echo ok || echo "réponse: ${lien:0:120}")"

    if [[ -n "${JETON}" ]]; then
        # Le vhost externe est joignable SANS certificat client : c'est sa
        # raison d'être. Le second facteur, lui, reste exigé.
        code=$(curl -s "${EXT[@]}" -o /dev/null -w "%{http_code}" \
            "${EXT_BASE}/lien/${JETON}")
        check "page de lien servie sans certificat client (200)" \
            "$([[ "${code}" == "200" ]] && echo ok || echo "code=${code}")"

        code=$(curl -s "${EXT[@]}" -o /dev/null -w "%{http_code}" \
            -X POST -d "facteur=MAUVAIS1" "${EXT_BASE}/lien/${JETON}")
        check "lien sans le bon code refusé (403)" \
            "$([[ "${code}" == "403" ]] && echo ok || echo "code=${code}")"

        # SEC-020 à travers le vrai nginx : une origine étrangère est refusée
        # AVANT toute consommation du lien…
        corps=$(curl -s "${EXT[@]}" -w "|%{http_code}" -X POST \
            -H "Origin: https://voisin.example.org" -H "Sec-Fetch-Site: same-site" \
            -d "facteur=${CODE}" "${EXT_BASE}/lien/${JETON}")
        check "ouverture de lien depuis une origine voisine refusée (403 provenance)" \
            "$([[ "${corps##*|}" == "403" && "${corps}" == *provenance* ]] \
               && echo ok || echo "réponse=${corps: -80}")"

        # … et la MÊME origine passe alors que nginx transmet `Host` sans port
        # et que le navigateur annonce l'origine avec son port public.
        # En-têtes d'un vrai navigateur sur notre formulaire : la page porte
        # Referrer-Policy no-referrer, donc Origin vaut « null » même en
        # same-origin (spécification Fetch) ; Sec-Fetch-Site tranche.
        reponse=$(curl -s "${EXT[@]}" -i -X POST -d "facteur=${CODE}" \
            -H "Origin: null" -H "Sec-Fetch-Site: same-origin" \
            "${EXT_BASE}/lien/${JETON}")
        check "bon code : session ouverte (303 + cookie)" \
            "$(echo "${reponse}" | grep -qi '^HTTP/.* 303' \
               && echo "${reponse}" | grep -qi 'set-cookie: sdop_lien' \
               && echo ok || echo 'pas de session')"

        # SEC-018 à travers le vrai vhost externe : la session ouvre SON
        # document, et aucun autre — même diffusé à la même personne, au même
        # niveau. Sans ce scénario, la portée n'est prouvée qu'au Palier 1.
        SESSION=$(echo "${reponse}" | tr -d '\r' \
            | sed -nE 's/^[Ss]et-[Cc]ookie: sdop_lien=([^;]+).*/\1/p' | head -1)
        PDF5="$(mktemp "${TMPDIR:-/tmp}/sdop-chain-XXXXXX").pdf"
        printf '%%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\ntrailer<</Root 1 0 R>>\n' > "${PDF5}"
        DOC_B=$(curl -s "${MTLS[@]}" -H "Accept: application/json" \
            -F "tlp=TLP:AMBER" -F "document=@${PDF5}" \
            -F "destinataires=victime@exemple.invalid" "${BASE}/api/publish" \
            | python3 -c "import json,sys; print(json.load(sys.stdin).get('doc_id',''))" 2>/dev/null || echo "")
        rm -f "${PDF5}"
        code_a=$(curl -s "${EXT[@]}" -o /dev/null -w "%{http_code}" \
            -b "sdop_lien=${SESSION}" "${EXT_BASE}/viewer/${DOC}")
        code_b=$(curl -s "${EXT[@]}" -o /dev/null -w "%{http_code}" \
            -b "sdop_lien=${SESSION}" "${EXT_BASE}/viewer/${DOC_B}")
        code_bx=$(curl -s "${EXT[@]}" -o /dev/null -w "%{http_code}" \
            -b "sdop_lien=${SESSION}" "${EXT_BASE}/api/export/${DOC_B}.pdf")
        check "session de lien : son document 200, autre document du même destinataire 404 (SEC-018)" \
            "$([[ -n "${SESSION}" && -n "${DOC_B}" && "${code_a}" == "200" \
                  && "${code_b}" == "404" && "${code_bx}" == "404" ]] \
               && echo ok || echo "session=${SESSION:+oui} doc_b=${DOC_B:+oui} a=${code_a} b=${code_b} export_b=${code_bx}")"

        # SEC-023 : rien de conservable par un cache, à travers nginx.
        entetes=$(curl -s "${EXT[@]}" -o /dev/null -D - "${EXT_BASE}/lien/${JETON}")
        check "page de lien : Cache-Control no-store (SEC-023)" \
            "$(echo "${entetes}" | grep -qi '^cache-control:.*no-store' \
               && echo ok || echo 'no-store absent')"

        # Le vhost externe ne doit exposer QUE le strict nécessaire.
        for interdit in "/" "/api/publish" "/_identite" "/api/pubkey"; do
            code=$(curl -s "${EXT[@]}" -o /dev/null -w "%{http_code}" \
                "${EXT_BASE}${interdit}")
            check "vhost externe : ${interdit} fermé (404)" \
                "$([[ "${code}" == "404" ]] && echo ok || echo "code=${code}")"
        done
    fi
fi

echo "--- 8. TLP:RED jamais diffusable par lien ---"
PDF4="$(mktemp "${TMPDIR:-/tmp}/sdop-chain-XXXXXX").pdf"
printf '%%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n' > "${PDF4}"
code=$(curl -s "${MTLS[@]}" -o /dev/null -w "%{http_code}" \
    -H "X-Authentik-Groups: tlp-red-emetteurs" \
    -F "tlp=TLP:RED" -F "document=@${PDF4}" "${BASE}/api/publish")
rm -f "${PDF4}"
check "publication TLP:RED toujours refusée au stub AMBER (403)" \
    "$([[ "${code}" == "403" ]] && echo ok || echo "code=${code}")"

echo "--- 9. Vhost interne : provenance vérifiée (SEC-020) ---"
# Même origine, port compris dans Origin, nginx transmettant Host sans port.
PDF6="$(mktemp "${TMPDIR:-/tmp}/sdop-chain-XXXXXX").pdf"
printf '%%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\ntrailer<</Root 1 0 R>>\n' > "${PDF6}"
code=$(curl -s "${MTLS[@]}" -o /dev/null -w "%{http_code}" -X POST \
    -H "Accept: application/json" -H "Origin: ${BASE}" -H "Sec-Fetch-Site: same-origin" \
    -F "tlp=TLP:AMBER" -F "document=@${PDF6}" "${BASE}/api/publish")
rm -f "${PDF6}"
check "publication de même origine (port dans Origin) acceptée (201)" \
    "$([[ "${code}" == "201" ]] && echo ok || echo "code=${code}")"

corps=$(curl -s "${MTLS[@]}" -w "|%{http_code}" -X POST \
    -H "Origin: https://voisin.example.org" \
    -F "tlp=TLP:AMBER" "${BASE}/api/publish")
check "publication depuis une origine voisine refusée (403 provenance)" \
    "$([[ "${corps##*|}" == "403" && "${corps}" == *provenance* ]] \
       && echo ok || echo "réponse=${corps: -80}")"

# EN DERNIER : ce scénario épuise volontairement le quota de l'adresse du
# harnais sur le vhost externe — tout scénario placé après en hériterait.
echo "--- 10. Vhost externe : limitation de débit (SEC-011) ---"
codes=$(for _ in $(seq 1 45); do
    curl -s "${EXT[@]}" -o /dev/null -w "%{http_code}\n" "${EXT_BASE}/lien/rafale"
done | sort | uniq -c | tr '\n' ' ')
check "rafale sur /lien : 429 après le seuil, 200 avant" \
    "$([[ "${codes}" == *" 429"* && "${codes}" == *" 200"* ]] \
       && echo ok || echo "codes: ${codes}")"

echo ""
echo "Résultat : ${PASS} passé(s) / $((PASS+FAIL)) total"
exit $(( FAIL > 0 ? 1 : 0 ))
