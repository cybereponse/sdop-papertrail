"""
Chiffrement au repos et scellement à deux clés — SDOP (EX-7, EX-8).

Une seule brique pour deux usages, et c'est délibéré : un document est chiffré
dès son dépôt avec la **clé de service**, puis **rescellé** à sa péremption avec
deux clés détenues par deux personnes. Même format, même code, une seule
enveloppe à auditer.

Le piège que ce module existe pour éviter
------------------------------------------
Chiffrer vers deux clés publiques — ce que font nativement PGP ou age — donne à
**chacune** le pouvoir d'ouvrir seule. Ce n'est pas du double contrôle, c'est
deux détenteurs indépendants. Pour qu'aucune ne suffise, il faut partager le
secret lui-même :

    K      = clé de contenu aléatoire (AES-256-GCM)
    part_A = aléatoire de même longueur
    part_B = K XOR part_A
    part_A --> chiffrée vers la clé publique du premier détenteur
    part_B --> chiffrée vers la clé publique du second
    K      = part_A XOR part_B        (les deux parts, ou rien)

Chaque part prise isolément est un aléa parfait : elle n'apprend rien sur K.
C'est un partage de secret 2-sur-2, le cas le plus simple de Shamir.

Enveloppe d'une part vers une clé publique : X25519 éphémère, dérivation HKDF,
puis AES-256-GCM. Pas de clé privée côté serveur, jamais.

Les clés privées des détenteurs sont créées et conservées par des humains, hors
de ce dépôt et hors de la machine — écrites par un humain, jamais par un
agent. Le service ne connaît que les clés publiques.
"""
import json
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"SDOPSEAL"
VERSION = 1
NONCE_LEN = 12
KEY_LEN = 32

#: Clé de chiffrement au repos (base64), depuis le coffre. Absente, les
#: documents sont stockés en clair et `AT_REST_ENABLED` vaut False : le service
#: fonctionne, mais /health le dit — un chiffrement qu'on croit actif et qui ne
#: l'est pas serait pire que pas de chiffrement du tout.
_SERVICE_KEY_B64 = os.environ.get("SDOP_CONTENT_KEY", "")
AT_REST_ENABLED = bool(_SERVICE_KEY_B64)


class SealingError(Exception):
    """Chiffrement ou descellement impossible."""


def _service_key() -> bytes:
    import base64
    cle = base64.b64decode(_SERVICE_KEY_B64)
    if len(cle) != KEY_LEN:
        raise SealingError("SDOP_CONTENT_KEY doit faire 32 octets (base64)")
    return cle


# --------------------------------------------------------------------------
# Chiffrement symétrique — utilisé au repos et pour le contenu scellé
# --------------------------------------------------------------------------

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    return (MAGIC + struct.pack("!B", VERSION) + nonce
            + AESGCM(key).encrypt(nonce, plaintext, MAGIC))


def decrypt(blob: bytes, key: bytes) -> bytes:
    if not blob.startswith(MAGIC):
        raise SealingError("format inconnu")
    version = struct.unpack("!B", blob[len(MAGIC):len(MAGIC) + 1])[0]
    if version != VERSION:
        raise SealingError(f"version d'enveloppe inconnue : {version}")
    debut = len(MAGIC) + 1
    nonce = blob[debut:debut + NONCE_LEN]
    try:
        return AESGCM(key).decrypt(nonce, blob[debut + NONCE_LEN:], MAGIC)
    except Exception as exc:
        raise SealingError(f"déchiffrement refusé : {exc}") from exc


def is_encrypted(blob: bytes) -> bool:
    return blob.startswith(MAGIC)


def encrypt_at_rest(plaintext: bytes) -> bytes:
    return encrypt(plaintext, _service_key()) if AT_REST_ENABLED else plaintext


def decrypt_at_rest(blob: bytes) -> bytes:
    if not is_encrypted(blob):
        return blob
    return decrypt(blob, _service_key())


# --------------------------------------------------------------------------
# Enveloppe asymétrique d'une part
# --------------------------------------------------------------------------

def _derive(partage: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=None,
                info=info).derive(partage)


def load_public_key(pem_ou_b64: str) -> X25519PublicKey:
    import base64
    donnees = pem_ou_b64.strip()
    if donnees.startswith("-----"):
        return serialization.load_pem_public_key(donnees.encode())
    return X25519PublicKey.from_public_bytes(base64.b64decode(donnees))


def _enveloppe(part: bytes, destinataire: X25519PublicKey) -> dict:
    import base64
    ephemere = X25519PrivateKey.generate()
    cle = _derive(ephemere.exchange(destinataire), b"sdop-seal-part")
    nonce = os.urandom(NONCE_LEN)
    return {
        "ephemeral": base64.b64encode(ephemere.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "part": base64.b64encode(
            AESGCM(cle).encrypt(nonce, part, MAGIC)).decode(),
    }


def _ouvrir_enveloppe(env: dict, prive: X25519PrivateKey) -> bytes:
    import base64
    pub = X25519PublicKey.from_public_bytes(base64.b64decode(env["ephemeral"]))
    cle = _derive(prive.exchange(pub), b"sdop-seal-part")
    try:
        return AESGCM(cle).decrypt(base64.b64decode(env["nonce"]),
                                   base64.b64decode(env["part"]), MAGIC)
    except Exception as exc:
        raise SealingError(f"part illisible avec cette clé : {exc}") from exc


# --------------------------------------------------------------------------
# Scellement 2-sur-2
# --------------------------------------------------------------------------

def seal(plaintext: bytes, pub_a: X25519PublicKey, pub_b: X25519PublicKey) -> bytes:
    """Scelle un document : ni A ni B ne peut l'ouvrir seul."""
    K = AESGCM.generate_key(256)
    part_a = os.urandom(KEY_LEN)
    part_b = bytes(x ^ y for x, y in zip(K, part_a))
    enveloppe = {
        "version": VERSION,
        "scheme": "xor-2-of-2/x25519-hkdf-sha256/aes-256-gcm",
        "parts": [_enveloppe(part_a, pub_a), _enveloppe(part_b, pub_b)],
    }
    entete = json.dumps(enveloppe, sort_keys=True,
                        separators=(",", ":")).encode()
    return (MAGIC + struct.pack("!BI", VERSION, len(entete)) + entete
            + encrypt(plaintext, K))


def unseal(blob: bytes, priv_a: X25519PrivateKey | None,
           priv_b: X25519PrivateKey | None) -> bytes:
    """Descelle — exige les DEUX clés privées. Une seule ne suffit jamais."""
    if priv_a is None or priv_b is None:
        raise SealingError(
            "descellement impossible : les deux clés sont requises")
    if not blob.startswith(MAGIC):
        raise SealingError("format inconnu")
    debut = len(MAGIC)
    _, taille = struct.unpack("!BI", blob[debut:debut + 5])
    debut += 5
    enveloppe = json.loads(blob[debut:debut + taille])
    env_a, env_b = enveloppe["parts"]
    part_a = _ouvrir_enveloppe(env_a, priv_a)
    part_b = _ouvrir_enveloppe(env_b, priv_b)
    K = bytes(x ^ y for x, y in zip(part_a, part_b))
    return decrypt(blob[debut + taille:], K)


def is_sealed(blob: bytes) -> bool:
    """Un document scellé porte un en-tête d'enveloppe, pas un simple nonce."""
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 5:
        return False
    try:
        _, taille = struct.unpack("!BI", blob[len(MAGIC):len(MAGIC) + 5])
        entete = blob[len(MAGIC) + 5:len(MAGIC) + 5 + taille]
        return json.loads(entete).get("scheme", "").startswith("xor-2-of-2")
    except Exception:
        return False
