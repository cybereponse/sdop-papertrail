"""
PKI et clés de la démo autonome — exécuté DANS l'image watermark (qui embarque
`cryptography`), lu sur l'entrée standard :

    docker compose ... run --rm -T pki python - [--renew] < demo/pki.py

Pourquoi en Python dans un conteneur plutôt qu'openssl sur l'hôte : aucune
dépendance côté poste (ni version d'openssl, ni LibreSSL macOS), et aucun
bind-mount — les fichiers vivent dans deux volumes Docker, ce qui marche aussi
avec un démon distant (VM, dind). Les clés n'entrent jamais dans une image.

Cycle de vie (revue du 2026-10-04, à l'opposé du harnais de test jetable) :
  · premier appel  : tout est créé ;
  · appels suivants : rien n'est régénéré, sauf la CRL (nginx refuse TOUT
    client si elle est périmée — la rafraîchir à chaque démarrage évite qu'une
    démo laissée de côté tombe en panne) ;
  · `--renew`      : certificats feuilles réémis par la MÊME CA (le poste qui
    lui fait confiance n'a rien à refaire). Clés applicatives conservées.

Volumes (chacun ne voit que ce dont il a besoin) :
  /pki   monté dans nginx (ro)      root_ca.crt, crl.pem, server/{app,ext}.{crt,key}
  /ca    jamais monté ailleurs      ca.key, ca.crt, client/ (P12 exporté vers l'hôte)
  /keys  monté dans watermark (ro)  signing.pem, content.key, tile.secret

AUCUNE de ces clés ne protège quoi que ce soit de réel : CA de démonstration,
à ne jamais installer comme autorité de confiance système.
"""
import base64
import datetime as dt
import os
import secrets
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PKI = "/pki"
CA = "/ca"
KEYS = "/keys"
DOMAIN = os.environ.get("SDOP_DEMO_DOMAIN", "sdop.localhost")
CLIENT_CN = os.environ.get("SDOP_DEMO_CLIENT_CN", "demo-user")
P12_PASSWORD = os.environ.get("SDOP_DEMO_P12_PASSWORD", "sdop-demo").encode()
NOBODY = 65534          # utilisateur du conteneur watermark
NGINX_GID = 101         # groupe nginx de l'image nginx:alpine

MAINTENANT = dt.datetime.now(dt.timezone.utc)
UN_JOUR = dt.timedelta(days=1)


def _ecrire(chemin, contenu: bytes, mode=0o600, uid=0, gid=0):
    os.makedirs(os.path.dirname(chemin), exist_ok=True)
    tmp = chemin + ".tmp"
    with open(tmp, "wb") as f:
        f.write(contenu)
    os.chmod(tmp, mode)
    os.chown(tmp, uid, gid)
    os.replace(tmp, chemin)


def _pem_cle(cle) -> bytes:
    return cle.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _pem_cert(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _nom(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SDOP demo"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca():
    cle_p, cert_p = f"{CA}/ca.key", f"{CA}/ca.crt"
    if os.path.exists(cle_p) and os.path.exists(cert_p):
        with open(cle_p, "rb") as f:
            cle = serialization.load_pem_private_key(f.read(), None)
        with open(cert_p, "rb") as f:
            return cle, x509.load_pem_x509_certificate(f.read())
    cle = ec.generate_private_key(ec.SECP256R1())
    nom = _nom("SDOP demo CA (not trusted, do not install system-wide)")
    cert = (x509.CertificateBuilder()
            .subject_name(nom).issuer_name(nom)
            .public_key(cle.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(MAINTENANT - UN_JOUR)
            .not_valid_after(MAINTENANT + 1825 * UN_JOUR)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True,
                                         False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(cle.public_key()),
                           critical=False)
            .sign(cle, hashes.SHA256()))
    # Clé de CA dans un volume que nginx ne monte pas.
    _ecrire(cle_p, _pem_cle(cle))
    _ecrire(cert_p, _pem_cert(cert), mode=0o644)
    print("  CA de démonstration créée")
    return cle, cert


def _feuille(ca_cle, ca_cert, cn, *, sans=None, client=False, jours=365):
    cle = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder()
         .subject_name(_nom(cn)).issuer_name(ca_cert.subject)
         .public_key(cle.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(MAINTENANT - UN_JOUR)
         .not_valid_after(MAINTENANT + jours * UN_JOUR)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.ExtendedKeyUsage(
             [ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]),
             critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
             ca_cle.public_key()), critical=False))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]),
                            critical=False)
    return cle, b.sign(ca_cle, hashes.SHA256())


def _feuilles(ca_cle, ca_cert, renouveler: bool):
    cible = f"{PKI}/server/app.crt"
    if os.path.exists(cible) and not renouveler:
        with open(cible, "rb") as f:
            fin = x509.load_pem_x509_certificate(f.read()).not_valid_after_utc
        reste = (fin - MAINTENANT).days
        if reste < 30:
            print(f"  ⚠ certificats de démo expirent dans {reste} j — "
                  "`make quickstart-renew`")
        return
    # Serveur interne : nom canonique + nom court (redirigé par app.conf).
    cle, cert = _feuille(ca_cle, ca_cert, f"app.{DOMAIN}", sans=[f"app.{DOMAIN}", DOMAIN])
    _ecrire(f"{PKI}/server/app.key", _pem_cle(cle), mode=0o640, gid=NGINX_GID)
    _ecrire(f"{PKI}/server/app.crt", _pem_cert(cert), mode=0o644)
    # Serveur externe (accès par lien, sans certificat client).
    cle, cert = _feuille(ca_cle, ca_cert, f"ext.{DOMAIN}", sans=[f"ext.{DOMAIN}"])
    _ecrire(f"{PKI}/server/ext.key", _pem_cle(cle), mode=0o640, gid=NGINX_GID)
    _ecrire(f"{PKI}/server/ext.crt", _pem_cert(cert), mode=0o644)
    # Client : certificat + P12 à importer dans le navigateur. Chiffrement
    # PBES1 SHA1/3DES + MAC SHA1 : le seul que le trousseau macOS et les
    # navigateurs anciens acceptent encore. Le mot de passe est public — il
    # n'est là que parce que plusieurs magasins refusent un P12 sans mot de passe.
    cle, cert = _feuille(ca_cle, ca_cert, CLIENT_CN, client=True)
    chiffrement = (serialization.PrivateFormat.PKCS12.encryption_builder()
                   .kdf_rounds(50000)
                   .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
                   .hmac_hash(hashes.SHA1())
                   .build(P12_PASSWORD))
    p12 = pkcs12.serialize_key_and_certificates(
        CLIENT_CN.encode(), cle, cert, [ca_cert], chiffrement)
    _ecrire(f"{CA}/client/client.p12", p12, mode=0o600)
    _ecrire(f"{CA}/client/client.crt", _pem_cert(cert), mode=0o644)
    _ecrire(f"{CA}/client/client.key", _pem_cle(cle), mode=0o600)
    # Second client, RÉVOQUÉ : la recette vérifie que la CRL mord vraiment.
    cle, cert = _feuille(ca_cle, ca_cert, "demo-revoked", client=True)
    _ecrire(f"{CA}/client/revoked.crt", _pem_cert(cert), mode=0o644)
    _ecrire(f"{CA}/client/revoked.key", _pem_cle(cle), mode=0o600)
    _ecrire(f"{CA}/revoked.serial", str(cert.serial_number).encode())
    print("  certificats serveur et client " + ("réémis" if renouveler else "créés"))


def _crl(ca_cle, ca_cert):
    revoques = []
    serial_p = f"{CA}/revoked.serial"
    if os.path.exists(serial_p):
        with open(serial_p) as f:
            revoques.append(x509.RevokedCertificateBuilder()
                            .serial_number(int(f.read().strip()))
                            .revocation_date(MAINTENANT - UN_JOUR).build())
    b = (x509.CertificateRevocationListBuilder()
         .issuer_name(ca_cert.subject)
         .last_update(MAINTENANT - UN_JOUR)
         .next_update(MAINTENANT + 90 * UN_JOUR))
    for r in revoques:
        b = b.add_revoked_certificate(r)
    # Nom attendu par app.conf (`ssl_client_certificate`).
    _ecrire(f"{PKI}/root_ca.crt", _pem_cert(ca_cert), mode=0o644)
    _ecrire(f"{PKI}/crl.pem", b.sign(ca_cle, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM), mode=0o644)


def _cles_applicatives():
    """Clés du service : conservées d'un démarrage à l'autre, sinon les
    documents chiffrés au repos deviendraient illisibles au redémarrage."""
    # Racine du volume traversable par watermark (nobody), non listable.
    os.makedirs(KEYS, exist_ok=True)
    os.chmod(KEYS, 0o711)
    if not os.path.exists(f"{KEYS}/signing.pem"):
        _ecrire(f"{KEYS}/signing.pem", _pem_cle(ed25519.Ed25519PrivateKey.generate()),
                uid=NOBODY)
    if not os.path.exists(f"{KEYS}/content.key"):
        _ecrire(f"{KEYS}/content.key", base64.b64encode(secrets.token_bytes(32)),
                uid=NOBODY)
    if not os.path.exists(f"{KEYS}/tile.secret"):
        _ecrire(f"{KEYS}/tile.secret", secrets.token_urlsafe(32).encode(), uid=NOBODY)


def main():
    renouveler = "--renew" in sys.argv[1:]
    os.umask(0o077)
    ca_cle, ca_cert = _ca()
    _feuilles(ca_cle, ca_cert, renouveler)
    _crl(ca_cle, ca_cert)
    _cles_applicatives()
    print("  PKI et clés de démo prêtes")


if __name__ == "__main__":
    main()
