# En-têtes du vhost externe — strip sans injection.
#
# Même règle nginx que pour le vhost interne : `proxy_set_header` au niveau
# `server` n'est pas hérité par un `location` qui en déclare un. D'où ce
# fragment, inclus dans chaque location plutôt que recopié.
#
# Différence essentielle avec sdop-trusted-headers.inc : ici on ne REMPLACE
# aucun en-tête d'identité par une valeur vérifiée — il n'y a pas d'outpost pour
# la fournir. On les vide tous. Un porteur de lien est identifié par sa session,
# résolue côté applicatif ; s'il pouvait poser X-Authentik-Username, il se
# ferait passer pour n'importe qui.

proxy_set_header X-Authentik-Username  "";
proxy_set_header X-Authentik-Groups    "";
proxy_set_header X-Authentik-Email     "";
proxy_set_header X-Authentik-Uid       "";
proxy_set_header X-Authentik-Name      "";
proxy_set_header X-Authentik-Jwt       "";
proxy_set_header X-Client-Cert-CN      "";
proxy_set_header X-Client-Cert         "";
proxy_set_header Authorization         "";

proxy_set_header X-Forwarded-For   $remote_addr;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header Host              $host;
proxy_http_version 1.1;
