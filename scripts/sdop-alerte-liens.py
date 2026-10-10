#!/usr/bin/env python3
"""
Contrôle des diffusions par lien non abouties : alerte aux analystes.

Un lien émis est une transaction engagée par un émetteur identifié. Quand elle
n'arrive pas au bout côté destinataire — courriel jamais parti, code refusé,
lien verrouillé, jamais ouvert, ouvert sans qu'une page soit servie — personne
ne le voit : le journal l'enregistre, mais n'alerte sur rien, et un lien expiré
sans usage ne produit même aucun événement. Ce script croise la table des liens
et le ledger, et envoie UN courriel récapitulatif des constats nouveaux.

À planifier côté infra (timer systemd horaire), comme `sdop-sceller.py` et
`ledger/digest.sh` — pas d'ordonnanceur dans l'application (ARCHITECTURE.md).

Ce qu'il ne répète pas : chaque constat est inscrit dans `link_alerts` (une
ligne par lien et par type) ; un run horaire ne signale que du nouveau. Chaque
alerte envoyée laisse un `link_alert_sent` au ledger ; un envoi raté laisse un
`link_alert_failed` et sera retenté, trois fois au plus.

    SDOP_ALERT_TO                   boîte des analystes ; vide = désactivé
    SDOP_ALERT_UNOPENED_HOURS       délai avant de signaler un lien non ouvert (24)
    SDOP_ALERT_VIEW_GRACE_MINUTES   délai après l'ouverture avant « rien affiché » (15)
    SDOP_SMTP_*, SDOP_PUBLIC_URL    comme pour l'envoi des liens (watermark/mailer.py)

Usage :
    sdop-alerte-liens.py --dry-run    imprime le courriel qui partirait, n'écrit rien
    sdop-alerte-liens.py              envoie et inscrit
"""
import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RACINE, "watermark"))
# Dans l'image, le script est copié à côté des modules (/app).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RACINE, "ledger"))

import db              # noqa: E402
import ledger          # noqa: E402
import links           # noqa: E402
import mailer          # noqa: E402
import siem            # noqa: E402
import store           # noqa: E402

ALERT_TO = os.environ.get("SDOP_ALERT_TO", "")
UNOPENED_HOURS = int(os.environ.get("SDOP_ALERT_UNOPENED_HOURS", "24"))
VIEW_GRACE_MINUTES = int(os.environ.get("SDOP_ALERT_VIEW_GRACE_MINUTES", "15"))
MAX_ENVOIS = 3

#: Fenêtre d'observation : la plus longue validité d'un lien, plus une marge
#: pour que l'expiration sans ouverture soit vue par au moins un run.
LOOKBACK = timedelta(hours=max(links.TTL_TOTP_HOURS, links.TTL_CODE_HOURS)) \
    + timedelta(days=7)

EVENEMENTS = frozenset({"link_mail_failed", "link_failed", "link_used",
                        "document_access", "tile_served", "document_export"})
AFFICHAGE = frozenset({"document_access", "tile_served", "document_export"})

#: Types de constat, du plus grave au moins grave : ordre du récapitulatif et
#: choix du libellé du sujet.
KINDS = (
    ("courriel_non_parti", "COURRIEL NON PARTI"),
    ("verrouille", "LIEN VERROUILLÉ"),
    ("expire_sans_ouverture", "EXPIRÉ SANS OUVERTURE"),
    ("ouvert_sans_affichage", "OUVERT, RIEN AFFICHÉ"),
    ("echecs_facteur", "SECOND FACTEUR REFUSÉ"),
    ("non_ouvert", "NON OUVERT"),
)
LIBELLES = dict(KINDS)
RANG = {kind: i for i, (kind, _) in enumerate(KINDS)}

CONSIGNES = {
    "courriel_non_parti": "vérifier l'adresse avec l'émetteur, puis renvoyer le lien "
                          "(« Diffuser par lien ») ou le transmettre par un autre canal.",
    "verrouille": "ce lien ne vaut plus : en réémettre un nouveau et dicter un nouveau code.",
    "expire_sans_ouverture": "réémettre un lien si la diffusion est toujours utile.",
    "ouvert_sans_affichage": "second facteur accepté mais aucune page servie : navigateur "
                             "ou session côté destinataire. Le rappeler ; le lien est "
                             "consommé, réémettre si besoin.",
    "echecs_facteur": "rappeler le destinataire et redicter le code (ou vérifier l'heure "
                      "de son application TOTP).",
    "non_ouvert": "s'assurer que le courriel est bien arrivé (indésirables ?) et relancer "
                  "le destinataire avant l'expiration.",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _dt(valeur: str) -> datetime:
    return datetime.fromisoformat(valeur)


def _fmt(valeur: str) -> str:
    return _dt(valeur).strftime("%Y-%m-%d %H:%M UTC")


# --------------------------------------------------------------------------
# Lecture
# --------------------------------------------------------------------------

def segments(depuis: datetime, jusqua: datetime) -> list[str]:
    """Segments mensuels existants entre deux instants, dans l'ordre."""
    chemins = []
    courant = depuis.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    while courant <= jusqua:
        chemin = ledger._segment_path(ledger.LEDGER_DIR, courant)
        if os.path.exists(chemin) and chemin not in chemins:
            chemins.append(chemin)
        # Mois suivant : le 1er du mois courant + 32 jours tombe toujours dans
        # le mois suivant, dont on reprend le 1er.
        courant = (courant + timedelta(days=32)).replace(day=1)
    return chemins


def charger_evenements(depuis: datetime, jusqua: datetime) -> tuple[list[dict], list[str]]:
    """Événements utiles depuis `depuis`. Rend aussi les segments illisibles."""
    evenements, illisibles = [], []
    for chemin in segments(depuis, jusqua):
        try:
            entrees = ledger.read(chemin)
        except (OSError, ledger.LedgerError, ValueError) as exc:
            illisibles.append(f"{chemin} : {type(exc).__name__}: {exc}")
            continue
        for e in entrees:
            if e.get("event") in EVENEMENTS and e.get("doc_id") \
                    and _dt(e["timestamp"]) >= depuis:
                evenements.append(e)
    return evenements, illisibles


def liens_a_surveiller(maintenant: datetime) -> list[dict]:
    rows = db.connect().execute(
        "SELECT * FROM links WHERE issued_at >= ? ORDER BY issued_at",
        ((maintenant - LOOKBACK).isoformat(),)).fetchall()
    return [dict(r) for r in rows]


def attribuer(liens: list[dict], evenements: list[dict]) -> dict[str, list[dict]]:
    """Rattache chaque événement à un lien : par (sujet, document), le dernier
    lien émis avant l'événement.

    Les événements côté émetteur portent le destinataire en `subject` ; ceux
    côté destinataire le portent en `actor`. Aucun ne porte le jeton : la
    correspondance est par personne et document, au plus près dans le temps.
    """
    par_cle: dict[tuple[str, str], list[dict]] = {}
    for lien in liens:
        par_cle.setdefault((lien["subject"], lien["doc_id"]), []).append(lien)
    for candidats in par_cle.values():
        candidats.sort(key=lambda l: l["issued_at"])

    attribution: dict[str, list[dict]] = {lien["token_hash"]: [] for lien in liens}
    for e in evenements:
        cle = (e.get("subject") or e.get("actor") or "", e["doc_id"])
        candidats = par_cle.get(cle)
        if not candidats:
            continue
        instant = _dt(e["timestamp"])
        retenu = None
        for lien in candidats:
            if _dt(lien["issued_at"]) <= instant:
                retenu = lien
        if retenu is not None:
            attribution[retenu["token_hash"]].append(e)
    return attribution


# --------------------------------------------------------------------------
# Analyse
# --------------------------------------------------------------------------

def analyser(lien: dict, evts: list[dict], maintenant: datetime) -> list[dict]:
    """Constats sur un lien. Un constat = kind, lien, motif, quand, last_event_at, n."""
    constats = []

    def constat(kind, motif, quand=None, last_event_at=None, n=0):
        constats.append({"kind": kind, "lien": lien, "motif": motif,
                         "quand": quand, "last_event_at": last_event_at, "n": n})

    echecs = [e for e in evts if e["event"] == "link_failed"]
    ouvert = lien["state"] == "utilise" or any(e["event"] == "link_used" for e in evts)
    affiche = [e for e in evts if e["event"] in AFFICHAGE and lien["used_at"]
               and _dt(e["timestamp"]) >= _dt(lien["used_at"])]
    emis, expire = _dt(lien["issued_at"]), _dt(lien["expires_at"])

    for e in evts:
        if e["event"] == "link_mail_failed":
            constat("courriel_non_parti", e.get("motif", "échec d'envoi"),
                    quand=e["timestamp"])

    if echecs:
        dernier = echecs[-1]
        motif = dernier.get("motif", "second facteur invalide")
        if ouvert and lien["used_at"] and _dt(lien["used_at"]) > _dt(dernier["timestamp"]):
            motif += " — ouvert ensuite"
        constat("echecs_facteur", motif, quand=dernier["timestamp"],
                last_event_at=dernier["timestamp"], n=len(echecs))

    if lien["state"] == "verrouille":
        constat("verrouille", f"{lien['attempts']} essais refusés",
                quand=echecs[-1]["timestamp"] if echecs else None)

    if lien["state"] == "actif" and not ouvert and not echecs:
        if maintenant >= expire:
            constat("expire_sans_ouverture", f"expiré le {_fmt(lien['expires_at'])}",
                    quand=lien["expires_at"])
        elif maintenant - emis >= timedelta(hours=UNOPENED_HOURS):
            constat("non_ouvert", f"aucune ouverture depuis l'émission, "
                    f"expire le {_fmt(lien['expires_at'])}")

    if lien["state"] == "utilise" and lien["used_at"] and not affiche \
            and maintenant >= _dt(lien["used_at"]) + timedelta(minutes=VIEW_GRACE_MINUTES):
        constat("ouvert_sans_affichage",
                f"second facteur accepté le {_fmt(lien['used_at'])}, aucune page servie",
                quand=lien["used_at"])

    return constats


def filtrer_nouveaux(constats: list[dict]) -> list[dict]:
    """Ne garde que ce qui n'a pas encore été signalé (ou dont l'envoi a échoué)."""
    cx = db.connect()
    nouveaux = []
    for c in constats:
        row = cx.execute("SELECT * FROM link_alerts WHERE token_hash=? AND kind=?",
                         (c["lien"]["token_hash"], c["kind"])).fetchone()
        if row is None:
            nouveaux.append(c)
        elif row["sent_at"] is None and row["attempts"] < MAX_ENVOIS:
            nouveaux.append(c)
        elif c["kind"] == "echecs_facteur" and c["last_event_at"] \
                and (row["last_event_at"] or "") < c["last_event_at"]:
            nouveaux.append(c)
    return nouveaux


# --------------------------------------------------------------------------
# Rédaction
# --------------------------------------------------------------------------

def rediger(constats: list[dict], maintenant: datetime) -> tuple[str, str]:
    constats = sorted(constats, key=lambda c: (RANG[c["kind"]], c["lien"]["issued_at"]))
    pire = constats[0]["kind"]
    n_pire = sum(1 for c in constats if c["kind"] == pire)
    n = len(constats)
    sujet = (f"[SDOP] {n} diffusion{'s' if n > 1 else ''} par lien non "
             f"abouti{'es' if n > 1 else 'e'} — dont {n_pire} {LIBELLES[pire]}")

    lignes = [
        "Bonjour,",
        "",
        f"Le contrôle horaire des liens de diffusion relève {n} situation"
        f"{'s' if n > 1 else ''} nouvelle{'s' if n > 1 else ''} non aboutie"
        f"{'s' if n > 1 else ''} côté destinataire. Les constats déjà signalés ne "
        "sont pas répétés.",
        "",
    ]
    for i, c in enumerate(constats, 1):
        lien = c["lien"]
        doc = store.get_meta(lien["doc_id"]) or {}
        tlp = doc.get("tlp", "?")
        nom = doc.get("original_name") or "(nom inconnu)"
        detail = c["motif"]
        consigne = CONSIGNES[c["kind"]]
        if c["kind"] == "echecs_facteur":
            detail = (f"{c['n']} essai{'s' if c['n'] > 1 else ''} refusé"
                      f"{'s' if c['n'] > 1 else ''}, dernier le {_fmt(c['quand'])} : "
                      f"{c['motif']}")
            if lien["state"] == "utilise":
                # Lien consommé : le compteur d'essais ne bouge plus et le code
                # ne rouvrira rien — session de 48 h finie, ou autre appareil.
                consigne = ("le lien est consommé (session terminée ou autre "
                            "appareil) : réémettre un lien au destinataire.")
            else:
                restants = max(0, links.MAX_ATTEMPTS - lien["attempts"])
                detail += f" ({restants} restant{'s' if restants > 1 else ''})"
        elif c["kind"] == "courriel_non_parti":
            detail = f"le {_fmt(c['quand'])} : {c['motif']}"
        lignes += [
            f"{i}. {LIBELLES[c['kind']]} — {tlp}",
            f"   Émetteur     : {lien['issued_by']}",
            f"   Destinataire : {lien['subject']}  (mode {lien['mode']}, lien émis le "
            f"{_fmt(lien['issued_at'])}, expire le {_fmt(lien['expires_at'])})",
            f"   Document     : « {nom} » (id {lien['doc_id'][:12]})",
            f"   Constat      : {detail}",
            f"   Que faire    : {consigne}",
            "",
        ]
    lignes += [
        "--",
        "SDOP — contrôle des liens (sdop-alerte-liens.py). Message automatique, "
        f"généré le {maintenant.strftime('%Y-%m-%d %H:%M UTC')}.",
        "Trace au journal : événements link_alert_sent.",
    ]
    return sujet, "\n".join(lignes) + "\n"


# --------------------------------------------------------------------------
# Inscription
# --------------------------------------------------------------------------

def enregistrer(constats: list[dict], maintenant: datetime,
                message_id: str | None, erreur: str | None) -> None:
    """Inscrit le résultat de l'envoi : base d'abord (tout ou rien), journal ensuite.

    Le journal est écrit APRÈS la validation : un courriel parti ne doit pas être
    renvoyé parce que le ledger a refusé l'entrée — l'échec du journal fait
    sortir le script en erreur, visible du timer.
    """
    instant = maintenant.isoformat()
    with db.transaction() as cx:
        for c in constats:
            if erreur is None:
                cx.execute(
                    "INSERT INTO link_alerts (token_hash, kind, last_event_at, attempts,"
                    " sent_at, message_id) VALUES (?,?,?,0,?,?)"
                    " ON CONFLICT(token_hash, kind) DO UPDATE SET"
                    " last_event_at=excluded.last_event_at, attempts=0,"
                    " sent_at=excluded.sent_at, message_id=excluded.message_id",
                    (c["lien"]["token_hash"], c["kind"], c["last_event_at"],
                     instant, message_id))
            else:
                cx.execute(
                    "INSERT INTO link_alerts (token_hash, kind, last_event_at, attempts)"
                    " VALUES (?,?,?,1)"
                    " ON CONFLICT(token_hash, kind) DO UPDATE SET"
                    " last_event_at=excluded.last_event_at, attempts=attempts+1,"
                    " sent_at=NULL, message_id=NULL",
                    (c["lien"]["token_hash"], c["kind"], c["last_event_at"]))

    if erreur is not None:
        entree = {"event": "link_alert_failed", "actor": "systeme",
                  "motif": erreur[:500], "constats": len(constats),
                  "destinataire": ALERT_TO}
        siem.emit(entree, ledger_hash=ledger.append(entree))
        return
    for c in constats:
        lien = c["lien"]
        doc = store.get_meta(lien["doc_id"]) or {}
        entree = {"event": "link_alert_sent", "actor": "systeme",
                  "subject": lien["subject"], "doc_id": lien["doc_id"],
                  "tlp": doc.get("tlp"), "kind": c["kind"], "mode": lien["mode"],
                  "issued_by": lien["issued_by"], "message_id": message_id,
                  "destinataire": ALERT_TO}
        entree = {k: v for k, v in entree.items() if v is not None}
        siem.emit(entree, ledger_hash=ledger.append(entree))


# --------------------------------------------------------------------------
# Point d'entrée
# --------------------------------------------------------------------------

def collecter(maintenant: datetime) -> tuple[list[dict], list[str]]:
    liens = liens_a_surveiller(maintenant)
    evenements, illisibles = charger_evenements(maintenant - LOOKBACK, maintenant)
    attribution = attribuer(liens, evenements)
    constats = []
    for lien in liens:
        constats += analyser(lien, attribution[lien["token_hash"]], maintenant)
    return filtrer_nouveaux(constats), illisibles


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true",
                    help="imprime le courriel qui partirait ; n'envoie rien, n'écrit rien")
    args = ap.parse_args(argv)

    if not ALERT_TO:
        print("SDOP_ALERT_TO vide : alerte désactivée.")
        return 0

    maintenant = _now()
    constats, illisibles = collecter(maintenant)
    for message in illisibles:
        print(f"AVERTISSEMENT : segment ignoré — {message}", file=sys.stderr)
    code_sortie = 1 if illisibles else 0

    if not constats:
        print("Aucun lien non abouti à signaler.")
        return code_sortie

    sujet, corps = rediger(constats, maintenant)
    if args.dry_run:
        print(f"Sujet : {sujet}\n")
        print(corps)
        print("(simulation : aucun courriel, aucune écriture)")
        return code_sortie

    if not mailer.configured():
        print("ERR: envoi de courriel non configuré (SDOP_SMTP_HOST, SDOP_SMTP_FROM, "
              "SDOP_PUBLIC_URL) — rien n'est inscrit, les constats seront repris.",
              file=sys.stderr)
        return 2

    try:
        message_id = mailer.send(mailer.build_message(ALERT_TO, sujet, corps))
    except mailer.MailError as exc:
        enregistrer(constats, maintenant, None, str(exc))
        print(f"ERR: alerte non envoyée ({exc}) — {len(constats)} constat(s), "
              "nouvelle tentative au prochain run.", file=sys.stderr)
        return 1

    enregistrer(constats, maintenant, message_id, None)
    print(f"Alerte envoyée à {ALERT_TO} : {len(constats)} constat(s) ({message_id}).")
    return code_sortie


if __name__ == "__main__":
    sys.exit(main())
