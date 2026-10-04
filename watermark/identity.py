"""
Identité de confiance — SDOP (ARCHITECTURE.md).

Règle non négociable : `username`, `groups` et `ip` viennent EXCLUSIVEMENT des
en-têtes posés par le reverse proxy du socle partagé (outpost Authentik + mTLS).
Jamais du corps de la requête, jamais d'un paramètre d'URL, jamais d'un en-tête
« de confiance » laissé au choix du client — nginx les écrase tous (strip+inject
regroupé dans `location /` de nginx/conf.d/app.conf).

Deux modes de confiance, choisis côté serveur par SDOP_TRUST_MODE :

- `proxy` (défaut, seul mode déployable) : l'identité est lue dans les en-têtes.
  Si l'en-tête d'identité est absent, la requête est refusée (401) — l'absence
  signifie « pas passé par le proxy », donc pas d'identité prouvée.
- `dev` : l'identité vient de VARIABLES D'ENVIRONNEMENT du processus, pas de la
  requête. C'est ce qui permet de faire tourner l'application sans le socle
  (devbox, démo locale) sans jamais introduire le chemin de code « identité
  fournie par le client », qui serait la vulnérabilité que tout le reste du
  projet existe pour empêcher. Refuse de démarrer si SDOP_DEV_IDENTITY != "1".
"""
import os

from flask import abort, request

TRUST_MODE = os.environ.get("SDOP_TRUST_MODE", "proxy")

H_USER = "X-Authentik-Username"
H_GROUPS = "X-Authentik-Groups"
H_EMAIL = "X-Authentik-Email"
H_CERT_CN = "X-Client-Cert-CN"


class Identity:
    """Identité de confiance d'une requête.

    `doc_scope` n'est posé que pour un porteur de lien : le seul document que
    sa session autorise. Il accompagne l'identité jusqu'à chaque décision
    d'accès — une session ouverte pour un document n'en ouvre aucun autre, même
    de même niveau et adressé à la même personne (SEC-018).
    """
    __slots__ = ("user", "groups", "ip", "cert_cn", "email", "doc_scope")

    def __init__(self, user, groups, ip, cert_cn="", email="", doc_scope=None):
        self.user = user
        self.groups = groups
        self.ip = ip
        self.cert_cn = cert_cn
        self.email = email
        self.doc_scope = doc_scope

    def as_dict(self):
        return {
            "user": self.user,
            "groups": self.groups,
            "ip": self.ip,
            "cert_cn": self.cert_cn,
            "email": self.email,
        }


def _split_groups(raw: str) -> list[str]:
    # L'outpost Authentik sépare les groupes par « | » (cf. ARCHITECTURE.md).
    return [g.strip() for g in (raw or "").replace(",", "|").split("|") if g.strip()]


def _from_proxy() -> Identity:
    user = request.headers.get(H_USER, "").strip()
    if not user:
        # Pas d'en-tête = pas passé par le proxy = pas d'identité prouvée.
        abort(401)
    ip = (request.headers.get("X-Forwarded-For", "") or "").split(",")[0].strip()
    return Identity(
        user=user,
        groups=_split_groups(request.headers.get(H_GROUPS, "")),
        ip=ip or request.headers.get("X-Real-IP", "").strip(),
        cert_cn=request.headers.get(H_CERT_CN, "").strip(),
        email=request.headers.get(H_EMAIL, "").strip(),
    )


def _from_env() -> Identity:
    if os.environ.get("SDOP_DEV_IDENTITY") != "1":
        # Garde-fou : le mode dev ne s'active pas par accident ni par un seul
        # réglage oublié dans un compose de production.
        abort(500)
    return Identity(
        user=os.environ.get("SDOP_DEV_USER", "dev-local"),
        groups=_split_groups(os.environ.get("SDOP_DEV_GROUPS", "")),
        ip=request.remote_addr or "127.0.0.1",
        cert_cn=os.environ.get("SDOP_DEV_CERT_CN", "dev-local"),
        email=os.environ.get("SDOP_DEV_EMAIL", ""),
    )


def trusted_identity() -> Identity:
    """Identité de confiance de la requête courante, ou abort(401)."""
    if TRUST_MODE == "dev":
        return _from_env()
    return _from_proxy()
