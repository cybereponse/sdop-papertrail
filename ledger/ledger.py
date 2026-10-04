"""
SDOP Ledger — chaîne de hachage append-only, segmentée par mois.

Chaque entrée scelle la précédente (prev_hash + entry_hash) : toute
modification a posteriori casse verify(). Segmentation mensuelle pour
permettre une purge RGPD (segments périmés) sans invalider les segments
encore valides.

Ne fait aucune hypothèse sur le support de stockage : LEDGER_DIR est un
chemin de répertoire ordinaire, à monter en volume chiffré/immuable côté
infra le jour venu — aucun changement de code requis pour ça.

Ce que ce module garantit, et ce qu'il ne garantit pas
------------------------------------------------------
Il garantit qu'une entrée **réécrite** casse la chaîne : verify() le voit.
Il ne peut pas, seul, voir une **troncature propre** — supprimer les N
dernières lignes laisse une chaîne parfaitement valide. Seul un ancrage
extérieur le détecte : le digest quotidien signé (digest.sh) publie le nombre
d'entrées et le dernier hash, et verify() sait les exiger
(`expected_count`, `expected_last_hash`). Sans cet ancrage, la chaîne prouve
l'intégrité de ce qui reste, pas qu'il ne manque rien.

Concurrence
-----------
append() lit le dernier hash puis écrit. Les deux opérations sont faites sous
un verrou exclusif (flock) tenu sur le segment : deux processus ne peuvent pas
sceller la même entrée précédente. Le verrou est posix et inter-processus, il
couvre donc plusieurs workers d'un même service comme plusieurs services.
"""
import fcntl
import hashlib
import json
import os
from datetime import datetime, timezone

LEDGER_DIR = os.environ.get("SDOP_LEDGER_DIR", "/journal")

GENESIS = "GENESIS"

# Champs posés par le ledger lui-même. Les laisser écrasables par l'appelant
# permettrait de forger un horodatage ou de rompre le chaînage depuis du code
# applicatif — y compris par accident.
RESERVED = ("timestamp", "prev_hash", "entry_hash")

# Borne sur une entrée sérialisée, verrou de sécurité contre une entrée
# déraisonnable (un champ applicatif non borné, par exemple). Une entrée
# refusée n'écrit rien : l'appelant doit décider quoi faire, pas découvrir plus
# tard un journal à moitié écrit.
MAX_ENTRY_BYTES = int(os.environ.get("SDOP_LEDGER_MAX_ENTRY", "8192"))


class LedgerError(Exception):
    """Entrée refusée, ou segment inexploitable."""


class ReservedField(LedgerError):
    """L'appelant a tenté de poser un champ réservé au ledger."""


class EntryTooLarge(LedgerError):
    """L'entrée sérialisée dépasse MAX_ENTRY_BYTES."""


class TruncatedSegment(LedgerError):
    """Le segment se termine par une ligne incomplète."""


def _canon(entry: dict) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def _segment_path(ledger_dir: str = LEDGER_DIR, when: datetime | None = None) -> str:
    when = when or datetime.now(timezone.utc)
    seg = when.strftime("%Y-%m")
    return os.path.join(ledger_dir, f"ledger-{seg}.jsonl")


def _last_line(f) -> bytes | None:
    """Dernière ligne complète d'un fichier binaire ouvert, ou None s'il est vide.

    Remonte par blocs plutôt que de lire une fenêtre fixe : une entrée plus
    longue que la fenêtre rendait auparavant tout ajout ultérieur impossible.
    """
    f.seek(0, os.SEEK_END)
    size = f.tell()
    if size == 0:
        return None

    block, pos, buf = 4096, size, b""
    while True:
        step = min(block, pos)
        pos -= step
        f.seek(pos)
        buf = f.read(step) + buf
        if not buf.endswith(b"\n"):
            # Écriture interrompue : la chaîner reviendrait à sceller une
            # entrée qui n'existe qu'à moitié.
            raise TruncatedSegment("le segment se termine sans fin de ligne")
        stripped = buf.rstrip(b"\n")
        cut = stripped.rfind(b"\n")
        if cut != -1:
            return stripped[cut + 1:]
        if pos == 0:
            return stripped or None


def _last_hash(path: str) -> str:
    """Dernier entry_hash d'un segment, ou GENESIS s'il n'existe pas encore."""
    if not os.path.exists(path):
        return GENESIS
    with open(path, "rb") as f:
        return _hash_of(_last_line(f))


def _hash_of(line: bytes | None) -> str:
    if line is None:
        return GENESIS
    return json.loads(line)["entry_hash"]


def append(details: dict, ledger_dir: str = LEDGER_DIR) -> str:
    """Ajoute une entrée scellée et renvoie son entry_hash.

    Lève ReservedField, EntryTooLarge ou TruncatedSegment sans rien écrire.
    """
    usurpes = [k for k in RESERVED if k in details]
    if usurpes:
        raise ReservedField(f"champs réservés au ledger : {', '.join(usurpes)}")

    os.makedirs(ledger_dir, exist_ok=True)
    path = _segment_path(ledger_dir)

    # "a+b" : les écritures vont toujours en fin de fichier, même si un autre
    # processus a écrit entre-temps. Le verrou couvre lecture ET écriture.
    with open(path, "a+b") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            prev = _hash_of(_last_line(f))
            entry = {
                **details,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "prev_hash": prev,
            }
            entry["entry_hash"] = hashlib.sha256(
                (_canon(entry) + prev).encode()).hexdigest()
            line = (_canon(entry) + "\n").encode()
            if len(line) > MAX_ENTRY_BYTES:
                raise EntryTooLarge(
                    f"entrée de {len(line)} octets (maximum {MAX_ENTRY_BYTES})")
            f.seek(0, os.SEEK_END)
            f.write(line)
            f.flush()
            # Une preuve qui n'a pas atteint le disque n'est pas une preuve.
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    return entry["entry_hash"]


def read(path: str) -> list[dict]:
    """Entrées d'un segment, dans l'ordre. Lève TruncatedSegment si incomplet."""
    with open(path, "rb") as f:
        data = f.read()
    if data and not data.endswith(b"\n"):
        raise TruncatedSegment("le segment se termine sans fin de ligne")
    return [json.loads(line) for line in data.decode().splitlines() if line.strip()]


def count(path: str) -> int:
    return len(read(path))


def last_hash(path: str) -> str:
    entries = read(path)
    return entries[-1]["entry_hash"] if entries else GENESIS


def verify(path: str, expected_count: int | None = None,
           expected_last_hash: str | None = None) -> bool:
    """Vrai si la chaîne du segment est intacte.

    `expected_count` et `expected_last_hash` viennent d'un ancrage extérieur
    (digest signé). Sans eux, une troncature propre reste invisible : la
    chaîne des entrées restantes est valide. Les passer, c'est vérifier qu'il
    ne manque rien — pas seulement que rien n'a été réécrit.
    """
    try:
        entries = read(path)
    except (TruncatedSegment, ValueError):
        return False

    prev = GENESIS
    for e in entries:
        e = dict(e)
        h = e.pop("entry_hash", None)
        if h is None or e.get("prev_hash") != prev:
            return False
        if hashlib.sha256((_canon(e) + prev).encode()).hexdigest() != h:
            return False
        prev = h

    if expected_count is not None and len(entries) != expected_count:
        return False
    if expected_last_hash is not None and prev != expected_last_hash:
        return False
    return True
