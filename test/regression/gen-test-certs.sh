#!/usr/bin/env bash
# Génère une CA + certs serveur/client JETABLES pour Palier 2 (test/ uniquement).
# Jamais la vraie PKI (step-ca), jamais commité, régénéré à chaque appel.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/nginx-build/certs"
rm -rf "$DIR"
mkdir -p "$DIR"

openssl req -x509 -newkey rsa:2048 -days 30 -nodes \
    -keyout "$DIR/ca.key" -out "$DIR/ca.crt" \
    -subj "/CN=SDOP Test CA (jetable, non confiance)" >/dev/null 2>&1

# SAN obligatoire : curl (comme tout client TLS moderne) ignore le CN pour la
# vérification du nom. Sans SAN, la seule façon de joindre la chaîne est `-k`,
# c'est-à-dire sans vérifier le certificat — on testerait alors tout SAUF ce que
# le TLS est censé garantir (SEC-010).
openssl req -newkey rsa:2048 -nodes \
    -keyout "$DIR/server.key" -out "$DIR/server.csr" \
    -subj "/CN=app.sdop.example.internal" \
    -addext "subjectAltName=DNS:app.sdop.example.internal" >/dev/null 2>&1
openssl x509 -req -in "$DIR/server.csr" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" \
    -CAcreateserial -days 30 -out "$DIR/server.crt" \
    -copy_extensions copy >/dev/null 2>&1

# Certificat du vhost externe (accès par lien, sans mTLS).
openssl req -newkey rsa:2048 -nodes \
    -keyout "$DIR/ext.key" -out "$DIR/ext.csr" \
    -subj "/CN=ext.sdop.example.internal" \
    -addext "subjectAltName=DNS:ext.sdop.example.internal" >/dev/null 2>&1
openssl x509 -req -in "$DIR/ext.csr" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" \
    -CAcreateserial -days 30 -out "$DIR/ext.crt" \
    -copy_extensions copy >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes \
    -keyout "$DIR/client.key" -out "$DIR/client.csr" \
    -subj "/CN=test-user" >/dev/null 2>&1
openssl x509 -req -in "$DIR/client.csr" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" \
    -set_serial 0x1001 -days 30 -out "$DIR/client.crt" >/dev/null 2>&1

# Deuxième certificat client, celui-là RÉVOQUÉ. app.conf porte `ssl_crl` : sans
# CRL, nginx refuse de démarrer, et sans certificat révoqué la CRL ne prouve
# rien. Les deux naissent donc ici, et le scénario de révocation de
# verify_chain.sh devient une régression plutôt qu'une mesure ponctuelle.
openssl req -newkey rsa:2048 -nodes \
    -keyout "$DIR/client-revoque.key" -out "$DIR/client-revoque.csr" \
    -subj "/CN=test-revoque" >/dev/null 2>&1
openssl x509 -req -in "$DIR/client-revoque.csr" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" \
    -set_serial 0x2002 -days 30 -out "$DIR/client-revoque.crt" >/dev/null 2>&1

# La CA de test n'a pas d'intermédiaire : une seule liste suffit. En production
# la CRL est CONCATÉNÉE (intermédiaire + racine), parce que nginx exige une
# liste pour chaque autorité de la chaîne présentée.
cat > "$DIR/ca.cnf" <<CNF
[ca]
default_ca = CA_test
[CA_test]
database         = $DIR/index.txt
crlnumber        = $DIR/crlnumber
certificate      = $DIR/ca.crt
private_key      = $DIR/ca.key
default_md       = sha256
# nginx REFUSE tout client si la CRL est périmée : une CRL à durée courte
# transforme une révocation en panne. 30 jours, comme les certificats de test.
default_crl_days = 30
CNF
: > "$DIR/index.txt"
echo 1000 > "$DIR/crlnumber"
openssl ca -config "$DIR/ca.cnf" -revoke "$DIR/client-revoque.crt" >/dev/null 2>&1
openssl ca -config "$DIR/ca.cnf" -gencrl -out "$DIR/crl.pem" >/dev/null 2>&1

rm -f "$DIR"/*.csr "$DIR"/*.srl "$DIR"/ca.cnf "$DIR"/index.txt* "$DIR"/crlnumber*
chmod 600 "$DIR"/*.key
echo "✔ Certs de test générés dans $DIR (jetables, jamais commités)"
echo "  dont client-revoque.crt, inscrit dans crl.pem"
