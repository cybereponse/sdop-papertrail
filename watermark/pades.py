"""
Sceau PAdES des exports — SDOP.

Le manifeste Ed25519 (manifest.py, SEC-014) prouve ce que le serveur a produit,
mais il voyage à côté du fichier et se vérifie avec un outil à nous. Le sceau
PAdES est la même promesse lisible par n'importe quel lecteur PDF : « cet
exemplaire sort de SDOP, il n'a pas été modifié depuis ».

Où il se pose : sur CHAQUE export, après le rendu et avant le manifeste. Le
destinataire ne reçoit jamais le PDF source (§6.2) — chaque export est
re-rastérisé avec un filigrane nominatif — donc une signature posée sur
l'original ne survivrait pas. Et le manifeste doit décrire les octets scellés,
pas ceux d'avant le sceau.

Ce qu'il est : une signature de CERTIFICATION, « aucune modification permise »
(DocMDP P=1), PAdES (ETSI.CAdES.detached), invisible — les pages sont des
images, aucun champ ne s'y dessine. `Reason` porte l'identifiant de
consultation : un exemplaire retrouvé se rattache au journal par son sceau.

Ce qu'il n'est pas (phase 1, PKI interne) : reconnu hors des postes qui ont la
racine CYBEREPONSE (« validité inconnue » ailleurs), ni horodaté par un tiers
(l'heure est celle du serveur). Un certificat reconnu nativement et une TSA
RFC 3161 ne changeront que les fichiers de configuration.

Configuration (lue au chargement, comme le reste du service) :
  SDOP_PADES_KEY       chemin de la clé privée PEM, non chiffrée (fichier
                       0400, monté en lecture seule, hors du dépôt)
  SDOP_PADES_CERT      chemin du certificat du sceau EN PREMIER, suivi de sa
                       chaîne jusqu'à l'intermédiaire
  SDOP_PADES_REQUIRED  « 1 » : un export ne sort pas sans sceau. Défaut :
                       FACULTATIF — sans sceau valide, l'export sort non
                       scellé (le manifeste le dit : pades_cert_sha256 nul).

Les deux chemins vides : pas de sceau. Un seul des deux, un fichier absent ou
illisible, une clé qui ne correspond pas au certificat : le service refuse de
démarrer — jamais un sceau silencieusement absent.
"""
import hashlib
import io
import os
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyhanko.keys import load_private_key_from_pemder
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.fields import MDPPerm, SigSeedSubFilter
from pyhanko_certvalidator.registry import SimpleCertificateStore
from asn1crypto import x509 as asn1_x509

#: Nom du champ de signature posé dans chaque export.
FIELD = "SceauSDOP"


class ConfigurationSceau(RuntimeError):
    """Configuration du sceau incohérente : le service ne doit pas démarrer."""


class SceauIndisponible(RuntimeError):
    """Sceau exigé mais absent ou expiré au moment de l'export."""


def _certificats(pem: bytes) -> list[x509.Certificate]:
    try:
        return x509.load_pem_x509_certificates(pem)
    except ValueError as exc:
        raise ConfigurationSceau(f"certificats illisibles : {exc}") from exc


def charger(cle_path: str, cert_path: str):
    """Signataire prêt à sceller, ou None si le sceau n'est pas configuré.

    Toute configuration partielle ou incohérente lève ConfigurationSceau.
    """
    if not cle_path and not cert_path:
        return None
    if not cle_path or not cert_path:
        raise ConfigurationSceau(
            "SDOP_PADES_KEY et SDOP_PADES_CERT vont ensemble : un seul est défini")
    for chemin in (cle_path, cert_path):
        if not os.path.isfile(chemin):
            raise ConfigurationSceau(f"fichier absent : {chemin}")

    with open(cert_path, "rb") as f:
        certs = _certificats(f.read())
    if not certs:
        raise ConfigurationSceau(f"aucun certificat dans {cert_path}")
    with open(cle_path, "rb") as f:
        try:
            cle = serialization.load_pem_private_key(f.read(), password=None)
        except (ValueError, TypeError) as exc:
            raise ConfigurationSceau(f"clé illisible : {exc}") from exc

    feuille = certs[0]
    brut = serialization.PublicFormat.SubjectPublicKeyInfo
    if (cle.public_key().public_bytes(serialization.Encoding.DER, brut)
            != feuille.public_key().public_bytes(serialization.Encoding.DER, brut)):
        raise ConfigurationSceau(
            "la clé ne correspond pas au premier certificat de SDOP_PADES_CERT")
    if feuille.not_valid_before_utc > datetime.now(timezone.utc):
        raise ConfigurationSceau("certificat du sceau pas encore valide")

    def asn1(c: x509.Certificate) -> asn1_x509.Certificate:
        return asn1_x509.Certificate.load(c.public_bytes(serialization.Encoding.DER))

    return signers.SimpleSigner(
        signing_cert=asn1(feuille),
        signing_key=load_private_key_from_pemder(cle_path, passphrase=None),
        cert_registry=SimpleCertificateStore.from_certs([asn1(c) for c in certs[1:]]),
    )


REQUIRED = os.environ.get("SDOP_PADES_REQUIRED") == "1"
_SIGNER = charger(os.environ.get("SDOP_PADES_KEY", ""),
                  os.environ.get("SDOP_PADES_CERT", ""))


def _fin_de_validite() -> datetime | None:
    if _SIGNER is None:
        return None
    return _SIGNER.signing_cert.not_valid_after


def disponible() -> bool:
    """Un sceau configuré ET encore valide maintenant."""
    fin = _fin_de_validite()
    return fin is not None and fin > datetime.now(timezone.utc)


def cert_sha256() -> str | None:
    """Empreinte du certificat du sceau (DER) — inscrite au manifeste."""
    if _SIGNER is None:
        return None
    return hashlib.sha256(_SIGNER.signing_cert.dump()).hexdigest()


def not_after() -> str | None:
    fin = _fin_de_validite()
    return fin.isoformat() if fin else None


def seal(pdf: bytes, *, view_id: str) -> bytes:
    """Scelle un export. Lève SceauIndisponible si aucun sceau valide."""
    if not disponible():
        raise SceauIndisponible("sceau PAdES absent ou expiré")
    meta = signers.PdfSignatureMetadata(
        field_name=FIELD,
        subfilter=SigSeedSubFilter.PADES,
        md_algorithm="sha256",
        reason=f"Exemplaire SDOP {view_id}",
        certify=True,
        docmdp_permissions=MDPPerm.NO_CHANGES,
    )
    sortie = io.BytesIO()
    signers.PdfSigner(meta, signer=_SIGNER).sign_pdf(
        IncrementalPdfFileWriter(io.BytesIO(pdf)), output=sortie)
    return sortie.getvalue()
