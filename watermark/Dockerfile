# Contexte de build = racine du dépôt (voir docker-compose.yml) : le module
# ledger/ vit hors de watermark/ et doit entrer dans l'image.
# Image épinglée par DIGEST, pas par tag : un tag est mutable, et « la
# même image » peut changer sous les pieds entre deux builds (SEC-012).
# Mise à jour : résoudre le nouveau digest avec
#   docker buildx imagetools inspect <image>:<tag>
# puis remplacer la ligne ci-dessous — jamais un simple retag.
FROM python:3.12-slim@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d

WORKDIR /app

COPY watermark/requirements.txt .
# --require-hashes : pip refuse toute distribution dont l'empreinte n'est
# pas listée, y compris transitive. Une version épinglée dit quoi
# installer ; l'empreinte dit ce qu'on a reçu (SEC-012).
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY watermark/*.py ./
COPY watermark/templates/ ./templates/
# Ledger §7 — importé tel quel, jamais recopié/forké dans watermark/.
COPY ledger/ledger.py ./
# Balayage des échéances et scellement (tâche serveur, jamais une route HTTP).
COPY scripts/sdop-sceller.py ./
# Contrôle horaire des liens non aboutis, alerte aux analystes (même modèle).
COPY scripts/sdop-alerte-liens.py ./

# Points de montage créés AVANT la déclaration des volumes et possédés par
# `nobody` : Docker recopie les droits du répertoire de l'image dans un volume
# nommé vide à sa première utilisation. Sans cela, le volume appartiendrait à
# root et le processus non privilégié ne pourrait rien y écrire.
RUN mkdir -p /documents /journal && chown nobody:nogroup /documents /journal
VOLUME ["/documents", "/journal"]

EXPOSE 5000

# Exécuté sans privilèges.
USER nobody

# Deux workers : `ledger.append()` sérialise désormais lecture et écriture
# sous un verrou flock inter-processus (SEC-006), deux workers ne peuvent plus
# sceller la même entrée précédente. Régression couvrant ce point :
# ledger/test_ledger.py::test_appends_concurrents_ne_rompent_pas_la_chaine.
# Rasterisation CPU-bound et synchrone, d'où des workers sync et un timeout
# généreux pour un document volumineux.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", \
     "--timeout", "120", "--access-logfile", "-", "app:app"]
