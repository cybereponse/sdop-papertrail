# nginx de la démo autonome — les VHOSTS RÉELS du dépôt, rendus pour le
# domaine de démonstration au moment du build, jamais maintenus à part.
#
# Contexte = racine du dépôt (liste blanche : nginx.Dockerfile.dockerignore).
# Seul le nom de domaine change : chaîne mTLS, forward-auth, strip+inject,
# limitation de débit et périmètre du vhost externe sont ceux qui sont
# déployés. Les vhosts intégrés (nginx/conf.d/) ne sont pas modifiés.
#
# Aucune clé dans l'image : certificats et CRL viennent du volume `pki`, monté
# en lecture seule sur /etc/ssl/core (voir demo/pki.py).
#
# Même image épinglée que le harnais de test (SEC-012) — mettre à jour les deux
# ensemble.
FROM nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10

ARG SDOP_DEMO_DOMAIN=sdop.localhost

# Prérequis de niveau http ($ssl_client_s_dn_cn) : le même fichier que le
# harnais de test, pas une copie.
COPY test/regression/nginx-build/nginx.conf /etc/nginx/nginx.conf
COPY nginx/conf.d/app.conf nginx/conf.d/ext.conf nginx/conf.d/sdop-limits.conf \
     nginx/conf.d/sdop-trusted-headers.inc nginx/conf.d/sdop-ext-headers.inc \
     nginx/conf.d/sdop-ext-locations.inc /etc/nginx/conf.d/

# Rendu limité au nom de domaine (liste blanche d'UNE substitution, pas
# d'envsubst : les variables nginx `$host`, `$request_uri`… restent intactes).
# Le build échoue si le domaine source n'apparaît plus, ou s'il en reste une
# trace : un vhost à moitié rendu servirait sous le mauvais nom.
RUN set -eu; \
    grep -q 'sdop\.example\.internal' /etc/nginx/conf.d/app.conf; \
    sed -i "s/sdop\.example\.internal/${SDOP_DEMO_DOMAIN}/g" /etc/nginx/conf.d/*.conf; \
    rm -f /etc/nginx/conf.d/default.conf; \
    if grep -q 'example\.internal' /etc/nginx/conf.d/*.conf; then \
        echo "domaine interne restant après rendu" >&2; exit 1; \
    fi
