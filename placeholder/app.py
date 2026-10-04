"""
SDOP Placeholder — Lot 1
Affiche les headers de confiance reçus du reverse proxy.
Sert à prouver que la chaîne mTLS + forward-auth + strip fonctionne.
N'est PAS le viewer final (lots ultérieurs).
"""
from flask import Flask, request, jsonify

app = Flask(__name__)

TRUSTED_HEADERS = [
    "X-Authentik-Username",
    "X-Authentik-Groups",
    "X-Authentik-Email",
    "X-Authentik-Uid",
    "X-Client-Cert-CN",
    "X-Client-Cert",
    "X-Forwarded-For",
    "X-Real-IP",
]

# En-têtes dont le NOM même ne sort pas d'ici (SEC-002). Les autres n'ont que
# leur nom restitué ; ces deux-là portent des jetons de session réutilisables,
# et confirmer leur présence à qui interroge la sonde ne sert rien.
JAMAIS_RESTITUES = {"cookie", "authorization", "proxy-authorization"}


@app.get("/health")
def health():
    return "ok", 200


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    identite = {h: request.headers.get(h, "(absent)") for h in TRUSTED_HEADERS}

    # Vérification du strip, sans devenir un miroir de requête (SEC-002).
    #
    # Cette route restituait la VALEUR de tous les en-têtes reçus, Cookie et
    # Authorization compris : n'importe quelle requête qui atteignait la sonde
    # obtenait en retour le jeton de session de son propre porteur, et tout ce
    # qu'un intermédiaire avait pu ajouter. Rendre les NOMS suffit à ce que la
    # sonde sert : prouver qu'un en-tête forgé n'arrive pas jusqu'au backend.
    # Le critère du README (« X-Authentik-Meta-App absent ») se vérifie aussi
    # bien sur une liste de noms que sur un dictionnaire de valeurs.
    attendus = {h.lower() for h in TRUSTED_HEADERS}
    autres = sorted(
        h for h in request.headers.keys()
        if h.lower() not in attendus and h.lower() not in JAMAIS_RESTITUES
    )

    return jsonify({
        "sdop": "placeholder",
        "lot": 1,
        "path": f"/{path}",
        "identite_de_confiance": identite,
        # Noms seulement, jamais de valeur. Un en-tête forgé qui franchirait le
        # proxy apparaîtrait ici par son nom — c'est tout ce qu'il faut savoir.
        "autres_entetes_recus": autres,
    })


if __name__ == "__main__":
    # Développement seulement. Le conteneur démarre par gunicorn (Dockerfile) :
    # ce bloc n'est pas le chemin de production (SEC-011).
    app.run(host="127.0.0.1", port=8080, debug=False)
