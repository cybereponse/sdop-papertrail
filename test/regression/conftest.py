"""
Chemins et environnement des tests Palier 1.

Deux applications Flask coexistent dans ce dépôt et exposent toutes les deux un
module `app` : `placeholder/app.py` (Lot 1) et `watermark/app.py` (Lot 2). Pour
éviter que l'une masque l'autre dans sys.path, seul `placeholder/` est ajouté au
chemin d'import sous le nom `app` ; le service watermark est chargé
explicitement par chemin de fichier (voir test_watermark.py).

Les variables d'environnement SDOP_* sont posées ICI, avant tout import : les
modules du service lisent leur configuration au chargement (répertoire des
documents, du journal, mode de confiance), choix assumé pour qu'un service
démarré ne puisse pas voir sa configuration changer en cours de route.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

sys.path.insert(0, os.path.join(ROOT, "placeholder"))

# Bac à sable des tests watermark — jamais /documents ni /journal.
TEST_SANDBOX = tempfile.mkdtemp(prefix="sdop-test-")
os.environ.setdefault("SDOP_DOC_DIR", os.path.join(TEST_SANDBOX, "documents"))
os.environ.setdefault("SDOP_LEDGER_DIR", os.path.join(TEST_SANDBOX, "journal"))
# Mode de confiance réel (en-têtes posés par le proxy) : c'est le contrat à
# tester, pas le mode dev.
os.environ.setdefault("SDOP_TRUST_MODE", "proxy")
os.environ.setdefault("SDOP_TILE_SECRET", "secret-de-test")
# DPI réduit : les tests exercent la chaîne, pas la qualité d'impression.
os.environ.setdefault("SDOP_RENDER_DPI", "72")
