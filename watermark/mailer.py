"""Envoi du lien de consultation par courriel.

Règle du produit : le courriel porte le LIEN, jamais le second facteur. Le code
se dicte de vive voix (ou le destinataire utilise son TOTP) : un tiers qui lit la
messagerie du destinataire ne doit pas pouvoir ouvrir le document.

Ce que le courriel ne contient pas non plus : le nom du fichier (il peut nommer
la victime ou l'incident) et le contenu. Seuls le niveau TLP, l'émetteur
(cybeRéponse), l'échéance du lien et la consigne.

Transport : SMTP soumission (587) en STARTTLS OBLIGATOIRE, certificat du
serveur vérifié contre une CA explicite (SDOP_SMTP_CAFILE) — jamais de repli en
clair, jamais de vérification désactivée. Le mot de passe est lu dans un fichier
monté (SDOP_SMTP_PASSWORD_FILE), jamais dans l'environnement.

Non configuré (SDOP_SMTP_HOST vide) : `configured()` rend False et l'interface
dit à l'analyste de transmettre le lien lui-même. Pas d'erreur silencieuse.
"""
from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

HOST = os.environ.get("SDOP_SMTP_HOST", "")
PORT = int(os.environ.get("SDOP_SMTP_PORT", "587"))
USER = os.environ.get("SDOP_SMTP_USER", "")
PASSWORD_FILE = os.environ.get("SDOP_SMTP_PASSWORD_FILE", "")
CAFILE = os.environ.get("SDOP_SMTP_CAFILE", "")
FROM = os.environ.get("SDOP_SMTP_FROM", "")
FROM_NAME = os.environ.get("SDOP_SMTP_FROM_NAME", "cybeRéponse — diffusion sécurisée")
PUBLIC_URL = os.environ.get("SDOP_PUBLIC_URL", "").rstrip("/")
TIMEOUT = 20


class MailError(Exception):
    """Envoi impossible — le message est montré à l'analyste et journalisé."""


def configured() -> bool:
    return bool(HOST and FROM and PUBLIC_URL)


def public_link(path: str) -> str:
    return f"{PUBLIC_URL}{path}"


def _password() -> str:
    if not PASSWORD_FILE:
        return ""
    try:
        with open(PASSWORD_FILE, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError as exc:
        raise MailError(f"mot de passe SMTP illisible ({exc.strerror})") from exc


def build_message(destinataire: str, sujet: str, corps: str,
                  reply_to: str = "") -> EmailMessage:
    """Enveloppe commune à tout courriel sortant : expéditeur, Message-ID, corps."""
    msg = EmailMessage()
    msg["From"] = formataddr((FROM_NAME, FROM))
    msg["To"] = destinataire
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = sujet
    msg["Message-ID"] = make_msgid(domain=FROM.rsplit("@", 1)[-1] or None)
    msg.set_content(corps)
    return msg


def build(destinataire: str, lien: str, tlp: str, heures: int,
          reply_to: str = "") -> EmailMessage:
    """Courriel au destinataire d'un lien — jamais le code, jamais le nom du fichier."""
    return build_message(
        destinataire, f"[{tlp}] Un document cybeRéponse vous est adressé",
        f"""Bonjour,

Un document classé {tlp} vous a été adressé par votre analyste cybeRéponse.

Pour le consulter, ouvrez ce lien personnel :

  {lien}

Un CODE vous sera demandé. Il ne figure pas dans ce message : votre analyste vous
le communique séparément, par téléphone. Ne le demandez jamais par courriel.

Ce lien est valable {heures} heures et ne sert qu'à vous. Après cinq codes
erronés, il est verrouillé ; demandez-en alors un nouveau à votre analyste.

{tlp} : diffusion limitée à votre organisation, sur le besoin d'en connaître.
Ne transférez pas ce message.

Vigilance : cybeRéponse ne vous demandera jamais de mot de passe par courriel.
En cas de doute sur ce message, rappelez votre analyste par un canal que vous
connaissez déjà.

--
cybeRéponse — diffusion sécurisée
Ce message est envoyé automatiquement ; pour répondre, écrivez à votre analyste.
""", reply_to)


def send(msg: EmailMessage) -> str:
    """Envoie et rend le Message-ID. Lève MailError en cas d'échec."""
    if not configured():
        raise MailError("envoi de courriel non configuré sur ce serveur")
    if not CAFILE:
        raise MailError("SDOP_SMTP_CAFILE absent : envoi refusé sans vérification TLS")
    try:
        # DANS le try : une CA illisible (fichier non monté, par exemple) doit
        # donner « échec d'envoi », pas une erreur 500 qui
        # fait perdre le code du lien déjà émis.
        ctx = ssl.create_default_context(cafile=CAFILE)
        with smtplib.SMTP(HOST, PORT, timeout=TIMEOUT) as smtp:
            smtp.ehlo()
            smtp.starttls(context=ctx)   # lève si STARTTLS absent ou certificat invalide
            smtp.ehlo()
            if USER:
                smtp.login(USER, _password())
            smtp.send_message(msg)
    except (OSError, smtplib.SMTPException, ssl.SSLError) as exc:
        raise MailError(f"envoi refusé : {exc.__class__.__name__}: {exc}") from exc
    return msg["Message-ID"]
