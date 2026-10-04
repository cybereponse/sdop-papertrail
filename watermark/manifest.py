"""
Manifeste d'artefact signé — SDOP (SEC-014).

Le ledger enregistrait l'empreinte de la **source**, calculée au dépôt, puis
servait un rendu dont personne ne gardait trace. Face à un exemplaire retrouvé,
on pouvait donc corréler une consultation, pas prouver que ces octets-là étaient
bien ceux que le serveur avait produits. `ARCHITECTURE.md` affirmait pourtant
que « la signature de l'artefact rendu est inscrite au ledger ».

Ce module produit cette preuve : un **manifeste canonique** décrivant ce qui a
été diffusé, et sa **signature détachée** Ed25519.

Pourquoi détachée : un PDF ne peut pas contenir l'empreinte de ses propres
octets finaux. La signature voyage donc à côté, et se vérifie hors ligne avec la
seule clé publique.

Pourquoi une clé distincte du secret des URL de tuiles : ces deux secrets n'ont
ni la même durée de vie, ni le même rayon d'action. Le secret des tuiles est
éphémère et sert à empêcher le partage d'une URL ; la clé de signature engage le
service sur ce qu'il a produit et doit pouvoir tourner sans invalider autre
chose. `key_id` est inscrit dans le manifeste précisément pour permettre cette
rotation.

La clé privée vient de SDOP_SIGNING_KEY (chemin d'un fichier PEM, déposé par un
humain depuis le coffre de secrets de l'opérateur). Sans elle, une clé
éphémère est tirée au démarrage : les manifestes restent cohérents entre eux
pendant la vie du processus, mais ne prouvent rien au-delà. `EPHEMERAL_KEY` le
signale, et /health l'expose pour que ce ne soit jamais une surprise.
"""
import base64
import hashlib
import json
import os
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

# Version du générateur : un manifeste doit dire avec quoi il a été produit,
# sinon on ne peut pas rejouer la vérification des années plus tard.
GENERATOR = "sdop-watermark/2"

_KEY_PATH = os.environ.get("SDOP_SIGNING_KEY", "")


def _charger_cle() -> tuple[Ed25519PrivateKey, bool]:
    if _KEY_PATH and os.path.exists(_KEY_PATH):
        with open(_KEY_PATH, "rb") as f:
            cle = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(cle, Ed25519PrivateKey):
            raise TypeError("SDOP_SIGNING_KEY doit être une clé Ed25519")
        return cle, False
    return Ed25519PrivateKey.generate(), True


_PRIVATE, EPHEMERAL_KEY = _charger_cle()
_PUBLIC = _PRIVATE.public_key()


def public_key_raw() -> bytes:
    return _PUBLIC.public_bytes(serialization.Encoding.Raw,
                                serialization.PublicFormat.Raw)


def public_key_b64() -> str:
    return base64.b64encode(public_key_raw()).decode()


#: Identifiant court de la clé — permet la rotation sans ambiguïté.
KEY_ID = hashlib.sha256(public_key_raw()).hexdigest()[:16]


def canonical(manifest: dict) -> bytes:
    """Forme canonique signée. Toute divergence ici invalide les signatures."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()


def build(*, doc: dict, view_id: str, actor: str, kind: str,
          artifact: bytes, source_sha256: str) -> dict:
    """Manifeste de ce qui a été diffusé.

    `source_sha256` est l'empreinte des octets **effectivement relus et rendus**
    (vérifiée par store, SEC-015), pas la valeur historique du sidecar.
    """
    return {
        "generator": GENERATOR,
        "key_id": KEY_ID,
        "kind": kind,                     # "export" | "tile"
        "doc_id": doc["doc_id"],
        "tlp": doc["tlp"],
        "view_id": view_id,
        "actor": actor,
        "source_sha256": source_sha256,
        "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        "artifact_bytes": len(artifact),
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }


def sign(manifest: dict) -> str:
    return base64.b64encode(_PRIVATE.sign(canonical(manifest))).decode()


def verify(manifest: dict, signature_b64: str,
           public_key_b64_: str | None = None) -> bool:
    """Vérifie une signature détachée. Utilisable hors ligne par un tiers."""
    try:
        if public_key_b64_ is None:
            pub = _PUBLIC
        else:
            pub = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(public_key_b64_))
        pub.verify(base64.b64decode(signature_b64), canonical(manifest))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
