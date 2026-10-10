# SDOP — Secure Document Orchestration Platform

A protected reading platform for sensitive documents classified under TLP 2.0 (RED /
AMBER+STRICT / AMBER), built by [CybeRéponse](https://cybereponse.net) (CSIRT) to share
incident-response reports with third parties. Not a vault that prevents copying — a system that
**attributes**: every view is nominative and watermarked, every export is signed, and every
action is written to a hash-chained ledger.

> **The backend never trusts the client for its identity.**
> Everything else — mTLS, identity provider, header stripping, ledger — exists to make that
> sentence true and checkable. It assumes that only the proxy can reach the service: a
> deployment requirement, detailed in the identity contract.

## Try it in five minutes

Requirements: Docker with Compose v2, `make`, `bash`; for the acceptance test, also `curl`,
`openssl` and `python3`.

```sh
git clone https://github.com/cybereponse/sdop-papertrail.git && cd sdop-papertrail
make quickstart          # then https://app.sdop.localhost:8443/
make quickstart-check    # end-to-end acceptance test
make quickstart-down     # stop, data kept
```

The demo runs the **real** nginx vhosts (mTLS + CRL, strip+inject of identity headers,
external vhost for link access) in front of a **fake** identity provider, on loopback only.
⚠ No real authentication: fictitious documents only. Client-certificate import, server trust
and what to try: [`demo/README.md`](demo/README.md).

Without Docker: `make demo` (publish, render and watermarked export into `var/demo/`, no
server) and `make run` (UI on `http://127.0.0.1:5000`, identity taken from the process
environment).

The user interface and code comments are in French; documentation for users and testers is in
English.

## What SDOP does

- **Publish** a PDF at a TLP level, to a nominative list of recipients.
- **Rasterised viewer**: the PDF never leaves the server; PNG tiles watermarked with the
  reader's name, short-lived signed URLs.
- **Watermarked export** with a signed manifest (Ed25519), verifiable offline.
- **Nominative links** for a recipient without an account: mandatory second factor (TOTP or a
  code read out by phone), session limited to that one document, never for TLP:RED.
- **Alert on links that do not complete** (`scripts/sdop-alerte-liens.py`, run by an hourly
  timer outside the application): mail never sent, factor refused, link locked, never opened,
  opened without a page served — one digest e-mail to the analysts (`SDOP_ALERT_TO`), each
  finding reported once, each alert itself recorded in the ledger.
- **Authorisation** = TLP clearance **and** recipient status.
- **Ledger**, hash-chained and fail-closed: an action that cannot be logged fails.
- **Per-document encryption at rest**, emergency containment, visibility deadline.

## Architecture

Threat model, authentication chain, watermarking, ledger, residual risks:
[`ARCHITECTURE.md`](ARCHITECTURE.md).

## Deploying with your own identity provider

SDOP authenticates nobody: a reverse proxy and an identity provider in front of it set trusted
headers. The contract — headers, stripping on every route, link path, network isolation — is in
[`docs/contrat-identite.md`](docs/contrat-identite.md). Reference implementation:
`nginx/conf.d/` (nginx + Authentik outpost in forward-auth, mTLS with an internal CA) and
`authentik/blueprints/`. `docker-compose.yml` is the reference integrated deployment; it joins
an external Docker network provided by the identity stack.

## Tests

```sh
make test                                # unit and regression tests, no container
bash test/regression/run-chain.sh        # real nginx chain + fake provider (Docker)
make quickstart-check                    # the same scenarios against the demo
```

## Verifying a sealed export

Every export carries a PAdES certification signature (`SceauSDOP`, "no changes allowed",
reason = `Exemplaire SDOP <view id>`). Outside any container, with the pinned pyHanko:

```sh
make verifier-sceau PDF=export.pdf RACINE=<root CA .crt>     # exit 0 = OK, 1 = not OK, 2 = unsealed
devbox run verifier-sceau -- --racine <root CA .crt> export.pdf
```

Acrobat Reader shows the same signature; macOS Preview does not display PDF signatures.

## Contributing, security, licence

[`CONTRIBUTING.md`](CONTRIBUTING.md) · vulnerabilities: [`SECURITY.md`](SECURITY.md) (no public
issue) · licence: [EUPL-1.2](LICENSE).

Third-party components keep their own licences. The rendering service depends on
**PyMuPDF (AGPL-3.0)**, a licence listed as compatible in the EUPL-1.2 appendix: when the service
is run with it, the AGPL obligations apply to the combined work, including making the source
available to its network users. Other direct dependencies (cryptography, Flask, gunicorn,
Pillow, ReportLab) are under permissive licences.
