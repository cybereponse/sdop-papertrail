# SDOP autonomous demo

Try SDOP on a workstation with **no infrastructure at all**: no identity provider, no PKI, no
shared proxy.

> ⚠ **No real authentication.** A fake identity provider "logs in" every request under a
> fictitious identity. Fictitious documents only. Never expose this stack beyond your machine.

## Requirements

Docker with Compose v2, `make`, `bash`. The demo PKI is generated inside a container — no
openssl needed on the host. The acceptance test (`make quickstart-check`) additionally needs
`curl`, `openssl` and `python3` on the host; `make quickstart-reset` needs `python3`.

## Commands

| Command | Effect |
|---|---|
| `make quickstart` | Builds, creates the PKI and keys on the **first** run, starts. Re-running only refreshes the CRL. |
| `make quickstart-down` | Stops. Documents, ledger, PKI and keys are **kept**. |
| `make quickstart-check` | Acceptance test: mTLS chain, header stripping, publish/view/export, link path, rate limiting, network isolation (by name and IP), non-empty intact ledger. Restarts nginx first so the rate limiter starts empty. |
| `make quickstart-renew` | Re-issues server and client certificates (same CA: nothing to redo for server trust). Does not revoke the old client, does not change the CA or the service keys. |
| `make quickstart-reset` | **Destroys** the demo's documents, ledger, PKI and keys. Shows the target project and everything it would remove (project containers, volumes they mount, volumes and networks named by the Compose model), asks you to type the project name, refuses if any of these resources lacks this demo's labels, if an interrupted PKI tool container remains or if the inventory fails, then checks nothing is left before reporting success. |

PKI and keys form a set: only the presence of the server certificate decides whether anything
is regenerated. A file lost from the volumes is not repaired — `make quickstart-renew`
re-issues the leaves, `make quickstart-reset` starts over.

Port: `SDOP_DEMO_PORT` (default `8443`, integer 1–65535), always bound to `127.0.0.1`.
Several instances: one project and one port each, e.g.
`COMPOSE_PROJECT_NAME=sdop-demo-2 SDOP_DEMO_PORT=8444 make quickstart` — otherwise they share
containers and volumes. Exported files go to `var/quickstart/<project>/`.

## Opening the application

`https://app.sdop.localhost:8443/`

Two **separate** browser settings — one does not cover the other:

1. **Client certificate (mTLS)** — the application refuses any connection without it. Import
   `var/quickstart/sdop-demo/sdop-demo-client.p12` (password `sdop-demo`):
   Firefox → Settings › Privacy & Security › Certificates › Your Certificates › Import;
   Chrome/Edge/Safari → the system certificate store (Keychain on macOS).
2. **Server certificate** — signed by the demo CA `var/quickstart/sdop-demo/ca.crt`. Accept the
   browser warning, or trust this CA **in a dedicated browser profile**. Do not install it in
   the system trust store: its key is protected by nothing.

Names served (certificate SANs): `app.sdop.localhost` (application, mTLS), `sdop.localhost`
(redirected to `app.` — the redirect drops the port, prefer the full name),
`ext.sdop.localhost` (link access, no client certificate). The link shown when you issue one
carries this external name and your port.

`*.localhost` means loopback, but not every resolver applies it (recent browsers and curl do;
some systems don't). If needed, add to `/etc/hosts`:
`127.0.0.1 app.sdop.localhost ext.sdop.localhost sdop.localhost`.

## What to try

1. Publish a fictitious PDF at TLP:AMBER (the default identity `demo` is an AMBER publisher).
2. Open it in the rasterised viewer: every tile is watermarked with your identity.
3. Export it: a watermarked PDF with a detached Ed25519 manifest, verifiable offline
   (`/api/pubkey`, `/api/evidence/<view_id>`).
4. Issue a link for a fictitious address, then open that link in a private window **without**
   the client certificate and enter the displayed code.
5. Try to publish at TLP:RED: refused for this identity — and TLP:RED is never shareable by link.

## Changing the fictitious identity

Default: `demo`, group `tlp-amber-emetteurs` (publishes and reads TLP:AMBER). Groups:
`tlp-<red|amber-strict|amber>-<lecteurs|relecteurs|emetteurs>` (read / review / publish),
separated by `|`.

```sh
STUB_USERNAME=alice STUB_GROUPS='tlp-red-emetteurs|tlp-amber-lecteurs' make quickstart
```

The acceptance test assumes the default identity.

## What the demo shows, and what it does not

Shown, with the repository's **real** nginx vhosts (only the domain name changes; the
enclosing `nginx.conf` is the harness's minimal one): mTLS and revocation (CRL), strip+inject
of identity headers, publication, rasterised viewer, signed watermarked export, encryption at
rest, nominative links with a second factor on the external vhost, rate limiting,
hash-chained ledger.

A "MODE DÉMO" banner is shown on every HTML page of the application (not on PNG, PDF, JSON or
default error pages). The user interface is in French.

Not shown: authentication itself (MFA, sessions, account revocation) — that is the operator's
identity provider's job. The contract expected from it:
[`docs/contrat-identite.md`](../docs/contrat-identite.md).

## Isolation

This is the demo's real boundary, not the banner: the service reads identity from headers, so
it must be reachable by nginx only. Only nginx is published, on `127.0.0.1`; no other service
has a host port; each service has its own network, shared with nginx only (the acceptance test
checks, by name and by IP address, that none reaches another — a probe that cannot run is an
error, never a "blocked"); volumes and Compose project belong to the demo and carry
`org.sdop.demo=1`; no SMTP, no SIEM export. Still inside the trust boundary: nginx, the Docker
engine and whoever administers the host. The fake provider also refuses any host name outside
`.localhost` — a guard rail, not a boundary.
