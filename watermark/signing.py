"""
URL de tuile signées, à durée de vie courte (ARCHITECTURE.md).

Chaque tuile PNG de la visionneuse est servie via une URL signée HMAC-SHA256
valable SDOP_TILE_TTL secondes. La signature couvre le doc_id, le numéro de
page, l'identifiant de consultation ET l'utilisateur de confiance : une URL
recopiée vers un autre compte ne vaut rien, et de toute façon l'autorisation
(authz) est **re-vérifiée** à chaque requête de tuile — la signature est une
défense en profondeur contre le partage d'URL, pas le contrôle d'accès.

Le secret vient de SDOP_TILE_SECRET. S'il est absent, un secret aléatoire est
tiré au démarrage : les URL émises deviennent invalides au redémarrage du
service (dégradation acceptable, durée de vie d'une URL = 60 s par défaut),
mais aucun secret par défaut n'existe dans le code.
"""
import base64
import hmac
import os
import secrets
import time
from hashlib import sha256

TTL = int(os.environ.get("SDOP_TILE_TTL", "60"))

_SECRET = (os.environ.get("SDOP_TILE_SECRET") or "").encode() or secrets.token_bytes(32)

EPHEMERAL_SECRET = not os.environ.get("SDOP_TILE_SECRET")


def _payload(doc_id: str, page: int, view_id: str, user: str, expires: int) -> bytes:
    # Séparateur « \x00 » : impossible dans les champs, donc pas d'ambiguïté
    # entre deux découpages différents du même message concaténé.
    return "\x00".join([doc_id, str(page), view_id, user, str(expires)]).encode()


def sign(doc_id: str, page: int, view_id: str, user: str,
         ttl: int | None = None) -> tuple[int, str]:
    expires = int(time.time()) + (TTL if ttl is None else ttl)
    mac = hmac.new(_SECRET, _payload(doc_id, page, view_id, user, expires), sha256)
    return expires, base64.urlsafe_b64encode(mac.digest()).decode().rstrip("=")


def verify(doc_id: str, page: int, view_id: str, user: str, expires: str,
           signature: str) -> bool:
    try:
        exp = int(expires)
    except (TypeError, ValueError):
        return False
    if exp < int(time.time()):
        return False
    mac = hmac.new(_SECRET, _payload(doc_id, page, view_id, user, exp), sha256)
    expected = base64.urlsafe_b64encode(mac.digest()).decode().rstrip("=")
    return hmac.compare_digest(expected, signature or "")
