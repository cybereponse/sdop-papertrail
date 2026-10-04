import json
import os
from datetime import datetime, timezone

import pytest

import ledger


@pytest.fixture
def ledger_dir(tmp_path):
    return str(tmp_path)


def test_append_produces_chained_entry(ledger_dir):
    h1 = ledger.append({"event": "document_access", "actor": "alice"}, ledger_dir)
    path = ledger._segment_path(ledger_dir)
    with open(path) as f:
        entry = json.loads(f.readline())
    assert entry["prev_hash"] == ledger.GENESIS
    assert entry["entry_hash"] == h1
    assert entry["actor"] == "alice"


def test_second_entry_chains_to_first(ledger_dir):
    h1 = ledger.append({"event": "document_access", "actor": "alice"}, ledger_dir)
    ledger.append({"event": "document_visa", "actor": "bob"}, ledger_dir)
    path = ledger._segment_path(ledger_dir)
    with open(path) as f:
        lines = [json.loads(line) for line in f]
    assert lines[1]["prev_hash"] == h1


def test_verify_passes_on_intact_chain(ledger_dir):
    for i in range(5):
        ledger.append({"event": "document_access", "actor": f"user{i}"}, ledger_dir)
    path = ledger._segment_path(ledger_dir)
    assert ledger.verify(path) is True


def test_verify_fails_on_tampering(ledger_dir):
    ledger.append({"event": "document_access", "actor": "alice"}, ledger_dir)
    ledger.append({"event": "document_access", "actor": "bob"}, ledger_dir)
    path = ledger._segment_path(ledger_dir)

    with open(path) as f:
        lines = f.readlines()
    tampered = json.loads(lines[0])
    tampered["actor"] = "mallory"
    lines[0] = json.dumps(tampered, sort_keys=True, separators=(",", ":")) + "\n"
    with open(path, "w") as f:
        f.writelines(lines)

    assert ledger.verify(path) is False


def test_new_segment_starts_at_genesis(ledger_dir):
    ledger.append({"event": "document_access"}, ledger_dir)
    other_month = datetime(2020, 1, 15, tzinfo=timezone.utc)
    other_path = ledger._segment_path(ledger_dir, when=other_month)
    assert ledger._last_hash(other_path) == ledger.GENESIS


def test_segments_do_not_interfere(ledger_dir, monkeypatch):
    jan = datetime(2020, 1, 15, tzinfo=timezone.utc)
    feb = datetime(2020, 2, 15, tzinfo=timezone.utc)

    class FixedDatetime(datetime):
        _now = jan

        @classmethod
        def now(cls, tz=None):
            return cls._now

    monkeypatch.setattr(ledger, "datetime", FixedDatetime)
    FixedDatetime._now = jan
    ledger.append({"event": "document_access", "actor": "alice"}, ledger_dir)

    FixedDatetime._now = feb
    ledger.append({"event": "document_access", "actor": "bob"}, ledger_dir)

    jan_path = ledger._segment_path(ledger_dir, when=jan)
    feb_path = ledger._segment_path(ledger_dir, when=feb)
    assert jan_path != feb_path
    assert ledger.verify(jan_path) is True
    assert ledger.verify(feb_path) is True

    with open(jan_path) as f:
        assert json.loads(f.readline())["actor"] == "alice"
    with open(feb_path) as f:
        assert json.loads(f.readline())["actor"] == "bob"


# --- SEC-006 : verrou, bornes, champs réservés, troncature ----------------

def test_champs_reserves_refuses(ledger_dir):
    """L'applicatif ne peut pas poser timestamp/prev_hash/entry_hash.

    Avant, `**details` était étalé APRÈS ces champs : un appelant pouvait
    forger un horodatage ou rompre le chaînage, y compris par accident.
    """
    for champ in ledger.RESERVED:
        with pytest.raises(ledger.ReservedField):
            ledger.append({"event": "x", champ: "forge"}, ledger_dir)
    assert not os.path.exists(ledger._segment_path(ledger_dir))


def test_entree_trop_grande_refusee_sans_rien_ecrire(ledger_dir):
    ledger.append({"event": "premier"}, ledger_dir)
    path = ledger._segment_path(ledger_dir)
    avant = ledger.count(path)

    with pytest.raises(ledger.EntryTooLarge):
        ledger.append({"event": "x", "blob": "A" * ledger.MAX_ENTRY_BYTES},
                      ledger_dir)

    assert ledger.count(path) == avant
    assert ledger.verify(path) is True


def test_longue_ligne_ne_bloque_plus_l_ajout_suivant(ledger_dir):
    """Régression du défaut central de SEC-006.

    `_last_hash()` relisait une fenêtre fixe de 4096 octets : une entrée plus
    longue rendait DÉFINITIVEMENT impossible tout ajout ultérieur. Comme la
    journalisation applicative est fail-closed, cela éteignait le service.
    """
    ledger.append({"event": "long", "blob": "A" * 5000}, ledger_dir)
    path = ledger._segment_path(ledger_dir)
    assert os.path.getsize(path) > 4096

    ledger.append({"event": "suivant"}, ledger_dir)
    entrees = ledger.read(path)
    assert [e["event"] for e in entrees] == ["long", "suivant"]
    assert ledger.verify(path) is True


def test_segment_tronque_en_cours_de_ligne_detecte(ledger_dir):
    ledger.append({"event": "a"}, ledger_dir)
    ledger.append({"event": "b"}, ledger_dir)
    path = ledger._segment_path(ledger_dir)

    with open(path, "rb") as f:
        data = f.read()
    with open(path, "wb") as f:                      # coupe au milieu de la 2e
        f.write(data[: len(data) - 20])

    assert ledger.verify(path) is False
    with pytest.raises(ledger.TruncatedSegment):
        ledger.append({"event": "c"}, ledger_dir)


def test_troncature_propre_invisible_sans_ancrage(ledger_dir):
    """Ce que la chaîne seule NE PEUT PAS prouver, et ce que l'ancrage ajoute.

    Supprimer les dernières lignes laisse une chaîne valide : c'est une limite
    de structure, pas un bug. Le digest signé publie le nombre d'entrées et le
    dernier hash ; les exiger rend la troncature visible.
    """
    for i in range(5):
        ledger.append({"event": "acces", "n": i}, ledger_dir)
    path = ledger._segment_path(ledger_dir)
    attendu_n = ledger.count(path)
    attendu_h = ledger.last_hash(path)

    lignes = open(path, "rb").readlines()
    with open(path, "wb") as f:                      # supprime les 2 dernières
        f.writelines(lignes[:-2])

    assert ledger.verify(path) is True, "la chaîne restante est bien valide"
    assert ledger.verify(path, expected_count=attendu_n) is False
    assert ledger.verify(path, expected_last_hash=attendu_h) is False


def _ajoute_en_rafale(args):
    """Cible du test de concurrence — doit être importable par un sous-processus."""
    import ledger as mod
    ledger_dir, base, n = args
    for i in range(n):
        mod.append({"event": "acces", "actor": f"{base}-{i}"}, ledger_dir)
    return n


def test_appends_concurrents_ne_rompent_pas_la_chaine(ledger_dir):
    """Quatre processus écrivent en même temps : la chaîne doit tenir.

    Sans verrou, deux processus lisent le même prev_hash et scellent tous
    deux la même entrée précédente — la chaîne est rompue, donc la preuve est
    détruite. C'est pour cela que le service tournait avec un seul worker.
    """
    from concurrent.futures import ProcessPoolExecutor

    procs, par_proc = 4, 15
    with ProcessPoolExecutor(max_workers=procs) as ex:
        list(ex.map(_ajoute_en_rafale,
                    [(ledger_dir, f"p{p}", par_proc) for p in range(procs)]))

    path = ledger._segment_path(ledger_dir)
    assert ledger.count(path) == procs * par_proc
    assert ledger.verify(path, expected_count=procs * par_proc) is True
