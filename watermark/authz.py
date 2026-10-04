"""
Autorisation SDOP — résolution d'un doc_id opaque et contrôle des droits
(ARCHITECTURE.md : « le client n'envoie jamais de document_path »).

Modèle de droits — décision prise ici, à défaut de spécification amont :

- Trois niveaux TLP seulement : `TLP:RED`, `TLP:AMBER+STRICT`, `TLP:AMBER`.
- Trois groupes Authentik par niveau, préfixés `tlp-` (groupes créés côté
  `core/`, cf. README.md § Étapes manuelles) :
    * `tlp-<slug>-lecteurs`    → CONSULTER les documents de ce niveau
    * `tlp-<slug>-relecteurs`  → consulter et VISER
    * `tlp-<slug>-emetteurs`   → PUBLIER à ce niveau, consulter et viser

  Les noms `emetteurs` et `relecteurs` viennent du blueprint de référence du
  socle ; `lecteurs` est ajouté par la V1 — le besoin d'un rôle en lecture seule
  n'était couvert nulle part.
- **Aucune hiérarchie implicite** : appartenir à `tlp-red-lecteurs` ne donne
  AUCUN droit sur l'AMBER et réciproquement. Un relecteur habilité à plusieurs
  niveaux est membre de plusieurs groupes. Le moindre privilège explicite est
  préféré à une hiérarchie devinée — une hiérarchie se décide avec le métier,
  pas dans le code.

L'habilitation est toujours évaluée contre les groupes issus des en-têtes de
confiance (`identity.trusted_identity()`), jamais contre une liste envoyée par
le client.
"""
import os

import store

GROUP_PREFIX = os.environ.get("SDOP_GROUP_PREFIX", "tlp-")

# TLP canonique -> slug de groupe
TLP_SLUGS = {
    "TLP:RED": "red",
    "TLP:AMBER+STRICT": "amber-strict",
    "TLP:AMBER": "amber",
}

# Formes d'écriture acceptées à la publication -> TLP canonique
_ALIASES = {
    "red": "TLP:RED",
    "tlp:red": "TLP:RED",
    "amber+strict": "TLP:AMBER+STRICT",
    "amber-strict": "TLP:AMBER+STRICT",
    "tlp:amber+strict": "TLP:AMBER+STRICT",
    "amber": "TLP:AMBER",
    "tlp:amber": "TLP:AMBER",
}


def normalize_tlp(raw: str | None) -> str | None:
    """Forme canonique d'un niveau TLP, ou None si non reconnu."""
    key = (raw or "").strip().lower().replace(" ", "")
    return _ALIASES.get(key)


def reader_group(tlp: str) -> str:
    return f"{GROUP_PREFIX}{TLP_SLUGS[tlp]}-lecteurs"


def reviewer_group(tlp: str) -> str:
    return f"{GROUP_PREFIX}{TLP_SLUGS[tlp]}-relecteurs"


def publisher_group(tlp: str) -> str:
    return f"{GROUP_PREFIX}{TLP_SLUGS[tlp]}-emetteurs"


def can_read(tlp: str, groups: list[str]) -> bool:
    """Habilitation au niveau — un PLAFOND, pas une permission.

    Être habilité ne donne accès à aucun document en particulier : il faut en
    être destinataire (voir resolve_and_authorize).
    """
    if tlp not in TLP_SLUGS:
        return False
    return any(g in groups for g in
               (reader_group(tlp), reviewer_group(tlp), publisher_group(tlp)))


def can_review(tlp: str, groups: list[str]) -> bool:
    if tlp not in TLP_SLUGS:
        return False
    return reviewer_group(tlp) in groups or publisher_group(tlp) in groups


def can_publish(tlp: str, groups: list[str]) -> bool:
    if tlp not in TLP_SLUGS:
        return False
    return publisher_group(tlp) in groups


#: Administre la plateforme — et ne lit aucun document. Un administrateur n'a
#: pas à consulter un TLP:RED pour gérer le service (EX-2).
ADMIN_GROUP = os.environ.get("SDOP_ADMIN_GROUP", "platform-admins")


def is_admin(groups: list[str]) -> bool:
    return ADMIN_GROUP in groups


def publishable_levels(groups: list[str]) -> list[str]:
    return [tlp for tlp in TLP_SLUGS if can_publish(tlp, groups)]


def readable_levels(groups: list[str]) -> list[str]:
    return [tlp for tlp in TLP_SLUGS if can_read(tlp, groups)]


def is_recipient(meta: dict, subject: str, kind: str | None = None) -> bool:
    """L'émetteur voit ce qu'il a publié ; les autres doivent être désignés.

    L'émetteur n'est pas inscrit dans la liste des destinataires : il doit
    pouvoir vérifier ce qu'il vient de diffuser sans se désigner lui-même. Cet
    accès cesse comme les autres à l'échéance (EX-5).

    `kind` restreint la désignation à une nature (`adresse` pour un porteur de
    lien) : un correspondant n'hérite ni des documents d'un compte homonyme, ni
    du statut d'émetteur (SEC-018).
    """
    sujet = (subject or "").strip().lower()
    if kind is None and sujet == (meta.get("published_by") or "").strip().lower():
        return True
    return store.is_recipient(meta["doc_id"], sujet, kind=kind)


def resolve_and_authorize(doc_id: str, groups: list[str],
                          subject: str | None = None,
                          recipient_kind: str | None = None) -> dict | None:
    """doc_id opaque -> métadonnées, ou None (403/404 indistincts).

    Double condition (exigence EX-1) :

        autoriser = destinataire(document) ET habilité(niveau TLP)

    Être destinataire ne suffit pas, être habilité non plus. Le groupe TLP est
    un plafond ; la liste de destinataires est la permission.

    Volontairement un seul retour `None` pour « inexistant », « interdit » et
    « échu » : un client non habilité ne doit pas pouvoir énumérer les doc_id
    existants, ni déduire d'un code de retour qu'un document a existé.

    `subject=None` n'évalue que le plafond : réservé aux appels internes qui ont
    déjà établi la qualité de destinataire par une autre voie (un lien, par
    exemple). Tout chemin exposé passe un sujet.
    """
    if store.containment_enabled():
        # Confinement : aucun document n'est servi, quel que soit le demandeur.
        return None
    meta = store.get_meta(doc_id)
    if meta is None:
        return None
    if not can_read(meta["tlp"], groups):
        return None
    if meta.get("state") not in (None, "actif") or store.is_expired(meta):
        return None
    if subject is not None and not is_recipient(meta, subject, kind=recipient_kind):
        return None
    return meta
