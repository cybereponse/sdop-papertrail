"""
Chemins et environnement des tests Palier 1.

Deux applications Flask coexistent dans ce dépôt et exposent toutes les deux un
module `app` : `placeholder/app.py` (Lot 1) et `watermark/app.py` (Lot 2). Pour
éviter que l'une masque l'autre dans sys.path, seul `placeholder/` est ajouté au
chemin d'import sous le nom `app` ; le service watermark est chargé
explicitement par chemin de fichier (voir test_watermark.py).

Les variables d'environnement SDOP_* sont posées ICI, avant tout import : les
modules du service lisent leur configuration au chargement (répertoire des
documents, du journal, mode de confiance), choix assumé pour qu'un service
démarré ne puisse pas voir sa configuration changer en cours de route.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

sys.path.insert(0, os.path.join(ROOT, "placeholder"))

# Bac à sable des tests watermark — jamais /documents ni /journal.
TEST_SANDBOX = tempfile.mkdtemp(prefix="sdop-test-")
os.environ.setdefault("SDOP_DOC_DIR", os.path.join(TEST_SANDBOX, "documents"))
os.environ.setdefault("SDOP_LEDGER_DIR", os.path.join(TEST_SANDBOX, "journal"))
# Mode de confiance réel (en-têtes posés par le proxy) : c'est le contrat à
# tester, pas le mode dev.
os.environ.setdefault("SDOP_TRUST_MODE", "proxy")
os.environ.setdefault("SDOP_TILE_SECRET", "secret-de-test")
# DPI réduit : les tests exercent la chaîne, pas la qualité d'impression.
os.environ.setdefault("SDOP_RENDER_DPI", "72")


def _pki_de_sceau(dossier: str) -> tuple[str, str, str]:
    """PKI de test à la forme de la vraie : racine → intermédiaire → sceau.

    Rend (clé du sceau, certificat du sceau suivi de sa chaîne, racine). Le
    profil du sceau reprend celui prévu sur la step-ca Services : KU
    digitalSignature + contentCommitment, EKU de signature de document.
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

    maintenant = datetime.datetime.now(datetime.timezone.utc)

    def certificat(cn, cle, emetteur=None, cle_emetteur=None, ac=False, chemin=None):
        nom = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        b = (x509.CertificateBuilder().subject_name(nom)
             .issuer_name(emetteur.subject if emetteur else nom)
             .public_key(cle.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(maintenant - datetime.timedelta(minutes=5))
             .not_valid_after(maintenant + datetime.timedelta(days=30))
             .add_extension(x509.BasicConstraints(ca=ac, path_length=chemin), critical=True))
        if ac:
            b = b.add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        else:
            b = b.add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            b = b.add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.EMAIL_PROTECTION,
                ObjectIdentifier("1.3.6.1.4.1.311.10.3.12"),
                ObjectIdentifier("1.3.6.1.5.5.7.3.36")]), critical=False)
        return b.sign(cle_emetteur or cle, hashes.SHA256())

    cle_racine = ec.generate_private_key(ec.SECP256R1())
    racine = certificat("SDOP test — racine", cle_racine, ac=True, chemin=1)
    cle_inter = ec.generate_private_key(ec.SECP256R1())
    inter = certificat("SDOP test — intermédiaire", cle_inter, racine, cle_racine,
                       ac=True, chemin=0)
    cle_sceau = ec.generate_private_key(ec.SECP256R1())
    sceau = certificat("SDOP test — sceau des exports", cle_sceau, inter, cle_inter)

    pem = serialization.Encoding.PEM
    os.makedirs(dossier, exist_ok=True)
    chemins = tuple(os.path.join(dossier, n)
                    for n in ("sceau.key", "sceau-chaine.crt", "racine.crt"))
    with open(chemins[0], "wb") as f:
        f.write(cle_sceau.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    with open(chemins[1], "wb") as f:
        f.write(sceau.public_bytes(pem) + inter.public_bytes(pem))
    with open(chemins[2], "wb") as f:
        f.write(racine.public_bytes(pem))
    return chemins


# Sceau PAdES des exports (watermark/pades.py) : actif dans les tests, comme en
# production. SDOP_TEST_PADES_ROOT n'est lu que par les tests (ancre de
# confiance du validateur), jamais par le service.
_cle, _chaine, _racine = _pki_de_sceau(os.path.join(TEST_SANDBOX, "pades"))
os.environ.setdefault("SDOP_PADES_KEY", _cle)
os.environ.setdefault("SDOP_PADES_CERT", _chaine)
os.environ.setdefault("SDOP_TEST_PADES_ROOT", _racine)
