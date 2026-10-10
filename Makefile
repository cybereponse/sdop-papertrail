# Makefile — SDOP (Lot 1)
# Prérequis : docker, docker compose v2
# Prérequis service : le socle identité partagé (step-ca + Authentik + nginx)
# démarré — voir CORE_DIR ci-dessous. `cd $(CORE_DIR) && make bootstrap && make up`
# une fois, avant tout ce qui suit.

SHELL   := /bin/bash
COMPOSE := docker compose

# Le socle identité partagé (core/) est possédé par identity-stack,
# un dépôt séparé — pas dupliqué ici (voir README.md § Dépendance). Chemin par
# défaut : dépôts clonés en frères, sous le même répertoire parent. Surcharger
# si ce n'est pas le cas : `make CORE_DIR=/chemin/vers/core up`.
CORE_DIR ?= ../identity-stack/core

.PHONY: up down clean verify test scan-deps logs ps install-vhost install-blueprints run demo verify-ledger verifier-sceau alertes-liens \
	quickstart quickstart-down quickstart-renew quickstart-check quickstart-reset

## Démarre le backend placeholder (rejoint le réseau du core en external).
up:
	@$(COMPOSE) up -d --build
	@echo "==> SDOP démarré. Vérification : make verify"

## Arrête (données conservées — SDOP n'a pas de secret/donnée propre).
down:
	@$(COMPOSE) down

## Supprime les conteneurs (rien à wipe côté données — placeholder est stateless).
clean:
	@$(COMPOSE) down

## Rejoue les critères d'acceptation (exerce SDOP + le core partagé).
verify:
	@CORE_DIR=$(CORE_DIR) bash scripts/verify.sh

## Tests unitaires (ledger + Palier 1 régression app) — aucune dépendance à
## core/, aucun conteneur requis.
test:
	@python3 -m venv ledger/.venv --clear >/dev/null
	@ledger/.venv/bin/pip install -q --require-hashes -r ledger/requirements.txt
	@cd ledger && ../ledger/.venv/bin/pytest -q
	@python3 -m venv test/regression/.venv --clear >/dev/null
	@test/regression/.venv/bin/pip install -q --require-hashes -r test/regression/requirements.txt
	@test/regression/.venv/bin/pytest -q test/regression

## Contrôle des dépendances (Trivy, version et empreinte épinglées) : bloque sur
## toute vulnérabilité HIGH/CRITICAL corrigeable — même règle que le job CI
## `scan-deps` (.forgejo/workflows/deps.yml). Réseau requis (base de Trivy).
scan-deps:
	@bash .forgejo/scan-deps.sh

## Lance le service watermark en local, SANS le socle identité partagé
## (identité issue de l'environnement du processus — voir scripts/dev-run.sh).
## Démo et développement uniquement : ne jamais y déposer de document réel.
run:
	@bash scripts/dev-run.sh

## Démo de bout en bout, sans serveur ni conteneur : génère un PDF de test,
## le publie, rend la visionneuse et l'export filigrané dans var/demo/,
## puis vérifie la chaîne de hachage du journal produit.
demo:
	@bash scripts/demo.sh

## Contrôle des liens non aboutis, dans le conteneur : alerte courriel aux
## analystes (SDOP_ALERT_TO). Lancé par un timer horaire côté infra ; à la main :
## `make alertes-liens ARGS=--dry-run`.
alertes-liens:
	@$(COMPOSE) exec watermark python sdop-alerte-liens.py $(ARGS)

## Vérifie l'intégrité de la chaîne de hachage d'un journal local
## (par défaut var/journal, produit par `make run`/`make demo`).
verify-ledger:
	@LEDGER_DIR="$(or $(LEDGER_DIR),var/journal)" bash scripts/verify-ledger.sh

## Vérifie le sceau PAdES d'exemplaires exportés, hors conteneur (pyHanko épinglé
## du service, venv de dev-run.sh) : `make verifier-sceau PDF=exemplaire.pdf
## RACINE=<racine.crt>` (plusieurs : PDF="a.pdf b.pdf"). Ce qu'Acrobat dirait avec
## la racine installée ; Aperçu (macOS) n'affiche pas les signatures PDF.
## Codes : 0 OK · 1 non OK · 2 non scellé · 3 usage.
verifier-sceau:
	@test -n "$(PDF)" || { echo "usage : make verifier-sceau PDF=<exemplaire.pdf> RACINE=<racine.crt>"; exit 3; }
	@bash scripts/verifier-sceau.sh $(if $(RACINE),--racine "$(RACINE)") $(PDF)

## ── Démo autonome (demo/) ───────────────────────────────────────────────
## SANS le socle identité : nginx réel + FAUX fournisseur d'identité, sur la
## boucle locale. Aucune authentification réelle, documents fictifs uniquement.
## Indépendante des cibles ci-dessus (projet Compose `sdop-demo`). Voir
## demo/README.md.

## Démarre la démo (PKI et clés créées au premier appel, conservées ensuite).
quickstart:
	@bash demo/quickstart.sh up

## Arrête la démo — documents, journal, PKI et clés conservés.
quickstart-down:
	@bash demo/quickstart.sh down

## Réémet les certificats de démo (même CA) et redémarre nginx.
quickstart-renew:
	@bash demo/quickstart.sh renew

## Recette de la démo : scénarios de la chaîne, isolement, journal non vide.
quickstart-check:
	@bash demo/quickstart.sh check

## DÉTRUIT les données et la PKI de la démo (confirmation demandée).
quickstart-reset:
	@bash demo/quickstart.sh reset

## Logs live.
logs:
	@$(COMPOSE) logs -f --tail=50

## Statut des conteneurs.
ps:
	@$(COMPOSE) ps

## Copie nginx/conf.d/app.conf dans le proxy partagé ($(CORE_DIR)/proxy/nginx/conf.d/)
## — même pattern que les autres projets clients pour leur propre vhost. Un
## symlink ne marche pas ici : le dossier conf.d du core est bind-monté SEUL
## dans le conteneur nginx, un lien à cible absolue host (hors de ce dossier,
## et hors de ce dépôt) est introuvable depuis le mount namespace du
## conteneur. cp = pas de "live reload" automatique en cas d'édition —
## relancer install-vhost après modif.
## Le nom du conteneur nginx n'est PAS écrit ici : il est lu dans core/.env,
## qui est la source de vérité des noms du socle (même motif que le socle
## lui-même). Un nom de conteneur en dur dans ce dépôt est un nom faux dès
## qu'on change d'environnement.
## Le fragment sdop-trusted-headers.inc est copié avec app.conf : app.conf
## l'`include`, nginx refuse de démarrer s'il manque. Les deux partent toujours
## ensemble, jamais l'un sans l'autre.
install-vhost:
	@cp "$(PWD)/nginx/conf.d/"*.conf "$(CORE_DIR)/proxy/nginx/conf.d/"
	@cp "$(PWD)/nginx/conf.d/"*.inc  "$(CORE_DIR)/proxy/nginx/conf.d/"
	@echo "✔ Copiés : nginx/conf.d/*.{conf,inc} → $(CORE_DIR)/proxy/nginx/conf.d/"
	@nginx=$$(grep -E '^CN_NGINX=' "$(CORE_DIR)/.env" 2>/dev/null | cut -d= -f2); \
	if [[ -z "$$nginx" ]]; then \
		echo "⚠ CN_NGINX absent de $(CORE_DIR)/.env — reload manuel requis"; \
	elif docker exec "$$nginx" nginx -s reload 2>/dev/null; then \
		echo "✔ nginx ($$nginx) rechargé"; \
	else \
		echo "⚠ reload manuel requis ($$nginx pas démarré ?)"; \
	fi

## Copie les blueprints Authentik SDOP dans $(CORE_DIR)/authentik/blueprints/
## (le worker Authentik scanne ce dossier et applique les nouveaux/modifiés
## automatiquement — pas de reload explicite nécessaire, contrairement à nginx).
install-blueprints:
	@cp $(PWD)/authentik/blueprints/*.yaml "$(CORE_DIR)/authentik/blueprints/"
	@echo "✔ Copiés : authentik/blueprints/*.yaml → $(CORE_DIR)/authentik/blueprints/"
