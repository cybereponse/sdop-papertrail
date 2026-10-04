"""
Stub Authentik — simule UNIQUEMENT le contrat de l'outpost embedded réel :
répond 200 + en-têtes X-Authentik-* sur n'importe quelle route, comme le fait
l'outpost quand une session est déjà valide. Ne réimplémente ni MFA, ni TOTP,
ni mot de passe — ce n'est pas Authentik, juste sa promesse de sortie pour
tester le strip+inject de nginx (Palier 2, voir ../../README.md).

Également utilisé par la démo autonome (../../../demo/). Là, il reçoit
STUB_REQUIRED_HOST_SUFFIX : il ne « connecte » personne si le nom demandé
n'est pas celui de la démo (par défaut `.localhost`). Un garde-fou, PAS une
frontière — la frontière est l'isolement réseau de la démo (nginx seul publié,
sur la boucle locale). Il évite qu'une démo publiée par erreur derrière un vrai
nom serve une identité fictive à quiconque.
"""
import os

from flask import Flask, Response, request

app = Flask(__name__)

REQUIRED_HOST_SUFFIX = os.environ.get("STUB_REQUIRED_HOST_SUFFIX", "")


def _hote_autorise() -> bool:
    if not REQUIRED_HOST_SUFFIX:
        return True
    hote = (request.host or "").rsplit(":", 1)[0].lower()
    return hote.endswith(REQUIRED_HOST_SUFFIX.lower())


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def outpost(path):
    if not _hote_autorise():
        # 403 et non 401 : nginx (auth_request) le renvoie tel quel au client,
        # sans détour par la page de connexion.
        return Response("stub d'authentification de démo : nom d'hôte refusé\n",
                        status=403, mimetype="text/plain")
    resp = Response("", status=200)
    resp.headers["X-Authentik-Username"] = os.environ.get("STUB_USERNAME", "test-regression")
    resp.headers["X-Authentik-Groups"] = os.environ.get("STUB_GROUPS", "tlp-amber-emetteurs")
    resp.headers["X-Authentik-Email"] = os.environ.get(
        "STUB_EMAIL", "test-regression@example.internal")
    resp.headers["X-Authentik-Uid"] = os.environ.get("STUB_UID", "1")
    return resp


@app.get("/health")
def health():
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
