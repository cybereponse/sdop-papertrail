# Contexte de build = ce dossier (nginx-build/), peuplé juste avant `docker
# compose build` par ../run-chain.sh : conf.d/app.conf (copie fraîche du
# fichier réel du dépôt) et certs/ (générés par ../gen-test-certs.sh). Pas de
# bind-mount : le démon Docker peut être distant (VM, dind).
# Image épinglée par DIGEST, pas par tag : un tag est mutable, et « la
# même image » peut changer sous les pieds entre deux builds (SEC-012).
# Mise à jour : résoudre le nouveau digest avec
#   docker buildx imagetools inspect <image>:<tag>
# puis remplacer la ligne ci-dessous — jamais un simple retag.
FROM nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10
COPY nginx.conf /etc/nginx/nginx.conf
COPY conf.d/app.conf /etc/nginx/conf.d/app.conf
# Fragment inclus par app.conf — sans lui nginx refuse de démarrer.
COPY conf.d/sdop-trusted-headers.inc /etc/nginx/conf.d/sdop-trusted-headers.inc
COPY certs/ca.crt /etc/ssl/core/root_ca.crt
# app.conf porte `ssl_crl` : sans ce fichier nginx refuse de démarrer, et toute
# la pile de test tomberait sans que la cause soit évidente.
COPY certs/crl.pem /etc/ssl/core/crl.pem
COPY certs/server.crt /etc/ssl/core/server/app.crt
COPY certs/server.key /etc/ssl/core/server/app.key
# Vhost externe (accès par lien, sans mTLS) — son propre certificat.
COPY conf.d/ext.conf /etc/nginx/conf.d/ext.conf
# Zones de limitation de débit (niveau http) référencées par le vhost externe.
COPY conf.d/sdop-limits.conf /etc/nginx/conf.d/sdop-limits.conf
COPY conf.d/sdop-ext-headers.inc /etc/nginx/conf.d/sdop-ext-headers.inc
COPY conf.d/sdop-ext-locations.inc /etc/nginx/conf.d/sdop-ext-locations.inc
COPY certs/ext.crt /etc/ssl/core/server/ext.crt
COPY certs/ext.key /etc/ssl/core/server/ext.key
