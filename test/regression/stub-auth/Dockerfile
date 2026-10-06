# Image épinglée par DIGEST, pas par tag : un tag est mutable, et « la
# même image » peut changer sous les pieds entre deux builds (SEC-012).
# Mise à jour : résoudre le nouveau digest avec
#   docker buildx imagetools inspect <image>:<tag>
# puis remplacer la ligne ci-dessous — jamais un simple retag.
FROM python:3.12-slim@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d
WORKDIR /app
COPY requirements.txt .
# --require-hashes : pip refuse toute distribution dont l'empreinte n'est
# pas listée, y compris transitive. Une version épinglée dit quoi
# installer ; l'empreinte dit ce qu'on a reçu (SEC-012).
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY stub_auth.py .
EXPOSE 9000
USER nobody
CMD ["python", "stub_auth.py"]
