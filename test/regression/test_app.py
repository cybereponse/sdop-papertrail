"""
Palier 1 — régression de la logique applicative de `placeholder/app.py` seule.
Aucun conteneur : l'app Flask est importée directement (`app.test_client()`).
Simule ce que nginx (étapes 1-3) est censé injecter, sans le faire tourner.
"""
import json
import pytest
from app import app as flask_app

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


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.data == b"ok"


def test_trusted_headers_promoted(client):
    resp = client.get("/", headers={
        "X-Authentik-Username": "alice",
        "X-Client-Cert-CN": "alice-cert",
    })
    data = resp.get_json()
    assert data["identite_de_confiance"]["X-Authentik-Username"] == "alice"
    assert data["identite_de_confiance"]["X-Client-Cert-CN"] == "alice-cert"


def test_absent_trusted_headers_marked(client):
    resp = client.get("/")
    data = resp.get_json()
    for h in TRUSTED_HEADERS:
        assert data["identite_de_confiance"][h] == "(absent)"


def test_untrusted_header_not_promoted(client):
    resp = client.get("/", headers={"X-Injection-Test": "malicious"})
    data = resp.get_json()
    assert "X-Injection-Test" not in data["identite_de_confiance"]
    # La sonde rend le NOM de l'en-tête inattendu, jamais sa valeur (SEC-002).
    assert "X-Injection-Test" in data["autres_entetes_recus"]
    assert "malicious" not in json.dumps(data)


def test_sonde_ne_restitue_jamais_cookie_ni_authorization(client):
    """SEC-002 : la sonde n'est pas un miroir de requête.

    Elle rendait la valeur de tous les en-têtes reçus. Une requête portant un
    cookie de session se la voyait renvoyer en clair, et le nom seul ne doit
    pas sortir non plus : confirmer la présence d'un jeton ne sert à rien.
    """
    r = client.get(
        "/",
        headers={
            "Cookie": "authentik_session=jeton-tres-secret",
            "Authorization": "Bearer jeton-tres-secret",
        },
    )
    corps = json.dumps(r.get_json())
    assert "jeton-tres-secret" not in corps
    noms = {h.lower() for h in r.get_json()["autres_entetes_recus"]}
    assert "cookie" not in noms
    assert "authorization" not in noms


def test_catch_all_path(client):
    resp = client.get("/some/nested/path")
    data = resp.get_json()
    assert data["path"] == "/some/nested/path"
    assert data["sdop"] == "placeholder"
