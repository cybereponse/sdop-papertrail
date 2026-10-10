"""
Base de métadonnées SDOP — SQLite.

Pourquoi une base, et pourquoi celle-ci
---------------------------------------
Les métadonnées vivaient en sidecars JSON, un par document. Cela ne porte ni
liste de destinataires, ni échéance interrogeable, ni lien, ni session : il faut
une base. La conception initiale supposait PostgreSQL ; à ~100
utilisateurs et ~10 documents/jour, il ajouterait un service réseau, un jeu de
secrets et une sauvegarde à opérer pour un besoin qu'un fichier couvre. C'est la
proportionnalité du §1 appliquée, et l'écart est écrit dans ARCHITECTURE.

Ce que cette base n'est PAS
---------------------------
Elle n'est pas la preuve. Le ledger reste un fichier append-only chaîné, hors
base : une preuve ne doit pas vivre dans un moteur qui sait faire `UPDATE` et
`DELETE`. En cas de divergence entre les deux, c'est le ledger qui dit vrai —
d'où `reference_hash()`, qui va chercher l'empreinte de publication dans le
journal et non ici.
"""
import os
import sqlite3
import threading
from contextlib import contextmanager

DB_PATH = os.environ.get("SDOP_DB_PATH", "")

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    doc_id        TEXT PRIMARY KEY,
    tlp           TEXT NOT NULL,
    original_name TEXT NOT NULL,
    version_hash  TEXT NOT NULL,
    bytes         INTEGER NOT NULL,
    pages         INTEGER,
    published_by  TEXT NOT NULL,
    published_at  TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    -- 'actif' | 'expire' | 'scelle' | 'retire'
    state         TEXT NOT NULL DEFAULT 'actif'
);

-- Un destinataire est soit un compte du socle, soit une adresse porteuse d'un
-- lien. Les deux convergent vers la même identité de confiance, donc vers le
-- même marquage et le même journal.
CREATE TABLE IF NOT EXISTS recipients (
    doc_id    TEXT NOT NULL REFERENCES documents(doc_id) ON DELETE CASCADE,
    subject   TEXT NOT NULL,          -- compte ou adresse, normalisé en minuscules
    kind      TEXT NOT NULL,          -- 'compte' | 'adresse'
    added_by  TEXT NOT NULL,
    added_at  TEXT NOT NULL,
    PRIMARY KEY (doc_id, subject)
);

CREATE INDEX IF NOT EXISTS idx_recipients_subject ON recipients(subject);
CREATE INDEX IF NOT EXISTS idx_documents_expires  ON documents(expires_at, state);

-- Correspondants externes : personnes sans compte du socle, jointes par lien.
-- `totp_secret` n'est posé que pour le mode A (enrôlement une fois par
-- personne) ; en mode B le second facteur est un code dicté, propre au lien.
CREATE TABLE IF NOT EXISTS correspondents (
    subject     TEXT PRIMARY KEY,
    totp_secret TEXT,
    enrolled_at TEXT,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    -- Dernier pas TOTP accepté : un code ne sert qu'une fois (SEC-021).
    totp_last_step INTEGER
);

-- Liens nominatifs. Le jeton n'est JAMAIS stocké en clair : seul son condensat
-- l'est, comme un mot de passe. Qui lit la base ne peut pas fabriquer d'accès.
CREATE TABLE IF NOT EXISTS links (
    token_hash TEXT PRIMARY KEY,
    doc_id     TEXT NOT NULL REFERENCES documents(doc_id) ON DELETE CASCADE,
    subject    TEXT NOT NULL,
    mode       TEXT NOT NULL,          -- 'totp' | 'code'
    code_hash  TEXT,                   -- mode 'code' seulement
    expires_at TEXT NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    state      TEXT NOT NULL DEFAULT 'actif',   -- actif|utilise|verrouille|revoque
    issued_by  TEXT NOT NULL,
    issued_at  TEXT NOT NULL,
    used_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_links_doc ON links(doc_id);

-- Sessions ouvertes par un lien. Révocables une par une ou en masse : c'est le
-- seul niveau de kill switch que SDOP maîtrise entièrement (EX-4).
CREATE TABLE IF NOT EXISTS link_sessions (
    session_hash TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL REFERENCES links(token_hash) ON DELETE CASCADE,
    doc_id       TEXT NOT NULL,
    subject      TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_subject ON link_sessions(subject);

-- Alertes déjà émises sur un lien non abouti (scripts/sdop-alerte-liens.py).
-- Une ligne par (lien, type de constat) : le contrôle horaire ne répète pas ce
-- qu'il a déjà signalé. `sent_at` reste NULL tant qu'aucun courriel n'est parti ;
-- `attempts` borne les nouvelles tentatives.
CREATE TABLE IF NOT EXISTS link_alerts (
    token_hash    TEXT NOT NULL REFERENCES links(token_hash) ON DELETE CASCADE,
    kind          TEXT NOT NULL,
    last_event_at TEXT,                         -- dernier événement couvert
    attempts      INTEGER NOT NULL DEFAULT 0,   -- envois tentés sans succès
    sent_at       TEXT,
    message_id    TEXT,
    PRIMARY KEY (token_hash, kind)
);

-- Réglages d'exploitation. Une seule ligne compte aujourd'hui : le confinement,
-- qui coupe toute diffusion d'un coup (EX-4).
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    changed_by TEXT,
    changed_at TEXT
);
"""


def path() -> str:
    if DB_PATH:
        return DB_PATH
    import store
    return os.path.join(store.DOC_DIR, "sdop.sqlite")


def connect() -> sqlite3.Connection:
    """Connexion par fil d'exécution, en WAL.

    WAL parce que plusieurs workers gunicorn écrivent : sans lui, un lecteur
    bloque un écrivain et le service se fige sous charge légère.
    """
    cx = getattr(_local, "cx", None)
    if cx is not None:
        return cx
    os.makedirs(os.path.dirname(path()) or ".", exist_ok=True)
    cx = sqlite3.connect(path(), timeout=10, isolation_level=None)
    cx.row_factory = sqlite3.Row
    cx.execute("PRAGMA journal_mode=WAL")
    cx.execute("PRAGMA synchronous=FULL")      # métadonnées = ne pas perdre
    cx.execute("PRAGMA foreign_keys=ON")
    cx.executescript(SCHEMA)
    _migrer(cx)
    _local.cx = cx
    return cx


#: Colonnes ajoutées après la mise en production. `CREATE TABLE IF NOT EXISTS`
#: ne touche pas une table existante : sans ce rattrapage, la base de
#: production garderait l'ancien schéma et la première requête qui lit la
#: colonne échouerait.
_COLONNES_AJOUTEES = (
    ("correspondents", "totp_last_step", "INTEGER"),
)


def _migrer(cx: sqlite3.Connection) -> None:
    for table, colonne, type_sql in _COLONNES_AJOUTEES:
        presentes = {r[1] for r in cx.execute(f"PRAGMA table_info({table})")}
        if colonne in presentes:
            continue
        try:
            cx.execute(f"ALTER TABLE {table} ADD COLUMN {colonne} {type_sql}")
        except sqlite3.OperationalError as exc:
            # Deux workers démarrent ensemble : le second trouve la colonne
            # ajoutée par le premier entre sa lecture et son ALTER.
            if "duplicate column" not in str(exc):
                raise


@contextmanager
def transaction():
    """Écritures tout-ou-rien : BEGIN IMMEDIATE, COMMIT, ROLLBACK sur exception.

    IMMEDIATE prend le verrou d'écriture dès l'ouverture : deux workers qui
    lisent puis écrivent la même ligne (un lien consommé deux fois, un compteur
    d'essais) sont sérialisés au lieu de s'entrelacer (SEC-021). Une exception —
    y compris le 503 d'un journal indisponible — annule tout ce qui a été écrit
    depuis l'ouverture (SEC-024).

    Réentrant : à l'intérieur d'une transaction déjà ouverte, ne fait rien de
    plus — c'est la transaction englobante qui décide.
    """
    cx = connect()
    if cx.in_transaction:
        yield cx
        return
    cx.execute("BEGIN IMMEDIATE")
    try:
        yield cx
    except BaseException:
        # SQLite a pu annuler de lui-même (disque plein, E/S) : un ROLLBACK
        # inconditionnel lèverait « no transaction is active » et masquerait
        # l'erreur d'origine.
        if cx.in_transaction:
            cx.execute("ROLLBACK")
        raise
    try:
        cx.execute("COMMIT")
    except BaseException:
        # Un COMMIT refusé laisserait la connexion du fil dans la transaction :
        # chaque `transaction()` suivante passerait par la branche réentrante,
        # ne validerait plus rien et garderait le verrou d'écriture.
        if cx.in_transaction:
            cx.execute("ROLLBACK")
        raise


def rollback_if_open() -> bool:
    """Filet de fin de requête : annule une transaction restée ouverte."""
    cx = getattr(_local, "cx", None)
    if cx is not None and cx.in_transaction:
        cx.execute("ROLLBACK")
        return True
    return False


def reset_for_tests() -> None:
    cx = getattr(_local, "cx", None)
    if cx is not None:
        cx.close()
        _local.cx = None
