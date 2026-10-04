# En-têtes de confiance SDOP — strip + inject.
#
# ⚠️ RÈGLE NGINX : proxy_set_header déclaré au niveau `server` N'EST PAS hérité
#    par un `location` qui en déclare un seul. Tous les strips ET toutes les
#    injections doivent donc vivre au MÊME niveau, dans CHAQUE location qui
#    relaie vers un backend. Ce fichier existe pour ça : il est `include`-é dans
#    chaque location plutôt que recopié — deux copies divergent, une inclusion
#    non. Extension `.inc` volontaire : conf.d n'auto-charge que `*.conf`, ce
#    fragment ne doit jamais être interprété comme un bloc serveur autonome.
#
# Après modification : `make install-vhost` (copie app.conf ET ce fragment),
# puis reload nginx côté core/.

# Valeurs vérifiées par l'outpost Authentik (subrequête auth_request) :
proxy_set_header X-Authentik-Username $ak_username;
proxy_set_header X-Authentik-Groups   $ak_groups;
proxy_set_header X-Authentik-Email    $ak_email;
proxy_set_header X-Authentik-Uid      $ak_uid;

# En-têtes Authentik non utilisés — strippés explicitement :
proxy_set_header X-Authentik-Name             "";
proxy_set_header X-Authentik-Jwt              "";
proxy_set_header X-Authentik-Meta-Jwks        "";
proxy_set_header X-Authentik-Meta-Outpost     "";
proxy_set_header X-Authentik-Meta-Provider    "";
proxy_set_header X-Authentik-Meta-App         "";
proxy_set_header X-Authentik-Meta-Version     "";
proxy_set_header Authorization                "";

# IP réelle fixée par le proxy (non spoofable) :
proxy_set_header X-Forwarded-For   $remote_addr;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;

# Identité du certificat client TLS (imposée par mTLS) :
proxy_set_header X-Client-Cert-CN $ssl_client_s_dn_cn;
proxy_set_header X-Client-Cert    $ssl_client_escaped_cert;

proxy_set_header Host $host;
proxy_http_version 1.1;
