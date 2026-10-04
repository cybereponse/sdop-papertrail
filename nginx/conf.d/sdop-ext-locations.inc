# Corps commun du vhost d'accès par lien (ext), inclus par :
#   conf.d/ext.conf            nom interne, certificat de la CA du socle
#   public/sdop-public.conf    nom public sdop.example.org, Let's Encrypt (p seulement)
# Un seul jeu de règles pour les deux noms : ce qui est ouvert, et ce qui ne
# l'est pas, ne peut pas diverger. Bornes et justification : en-tête d'ext.conf.
#
# Ce fichier n'est valide QU'À L'INTÉRIEUR d'un bloc server (inclus, jamais
# chargé seul : nginx.conf n'inclut que conf.d/*.conf).

# PAS de ssl_verify_client ici : c'est tout l'objet de ce vhost.
# PAS d'auth_request : il n'y a pas de session Authentik à interroger.

client_max_body_size 1m;          # rien ne se dépose par ce chemin

# Limitation de débit (SEC-011, volet public) — zones et seuils commentés dans
# conf.d/sdop-limits.conf. 429 plutôt que le 503 par défaut : un client doit
# comprendre qu'il va trop vite, pas que le service est en panne.
limit_req_status  429;
limit_conn_status 429;
limit_req_log_level warn;
limit_conn sdop_ext_conn 50;

add_header Strict-Transport-Security "max-age=31536000" always;
add_header X-Content-Type-Options nosniff always;
add_header Referrer-Policy no-referrer always;

# Tout ce qui n'est pas explicitement ouvert n'existe pas.
location / {
    return 404;
}

# Page de saisie du second facteur et sa validation.
location ~ "^/lien/[A-Za-z0-9_-]+$" {
    limit_req zone=sdop_ext_lien burst=30 nodelay;
    include /etc/nginx/conf.d/sdop-ext-headers.inc;
    proxy_pass http://watermark:5000;
}

# Visionneuse d'un document, tuiles, export. L'autorisation reste entière
# côté applicatif : la session de lien ne vaut que pour SON document.
location ~ "^/viewer/[0-9a-f]{32}$" {
    limit_req zone=sdop_ext_pages burst=60 nodelay;
    include /etc/nginx/conf.d/sdop-ext-headers.inc;
    proxy_pass http://watermark:5000;
}

location ~ "^/api/view/[0-9a-f]{32}/page/[0-9]+\.png$" {
    # Sans nodelay : une rafale de tuiles (document long) est étalée, pas
    # refusée — refuser ferait des pages blanches dans la visionneuse.
    limit_req zone=sdop_ext_tuiles burst=500;
    include /etc/nginx/conf.d/sdop-ext-headers.inc;
    proxy_pass http://watermark:5000;
}

location ~ "^/api/export/[0-9a-f]{32}\.pdf$" {
    limit_req zone=sdop_ext_export burst=5 nodelay;
    include /etc/nginx/conf.d/sdop-ext-headers.inc;
    proxy_read_timeout 120s;
    proxy_pass http://watermark:5000;
}
