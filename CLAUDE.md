# SDOP — instructions for Claude Code sessions

SDOP (Secure Document Orchestration Platform) distributes sensitive incident-response
documents (TLP:AMBER / AMBER+STRICT / RED) with attribution: rasterized viewer, watermarked
signed exports, nominative links with a second factor, hash-chained audit log.
The user interface and code comments are in **French**; keep them in French. User and tester
documentation (README, `demo/README.md`, `docs/`, ARCHITECTURE, CONTRIBUTING, SECURITY) is in
**English**.

## What this repository is

- The **application only**: `watermark/` (Flask service), `ledger/`, `placeholder/`
  (identity probe), `nginx/conf.d/` (reference vhosts), `authentik/blueprints/` (reference
  IdP setup), `scripts/`, `test/`, `demo/`.
- Authentication is **not** done by SDOP. A reverse proxy + identity provider in front of it
  injects trusted headers. The contract is `docs/contrat-identite.md` — read it before
  touching anything identity- or header-related.
- `demo/` + `make quickstart` run the real nginx chain in front of a **fake** identity
  provider (`test/regression/stub-auth`), loopback only. No real authentication there.

## Mandatory workflow

- **Never commit to `main`. Never push to `main`.** Always create a branch
  (`feat/…`, `fix/…`, `docs/…`, `test/…`) and open a pull request against `main`.
- One pull request = one topic. Keep diffs focused; no drive-by reformatting.
- No force push, no deleting remote branches, no tags, no releases.
- Do not modify `LICENSE`, `.github/workflows/` or `SECURITY.md` unless the task is
  explicitly about them.

## Commits

- Commit messages in **English**. Imperative subject line, ≤ 72 characters
  (e.g. `Fix tile signature check on expired links`). Body explains *why*, wrapped at 72.
- The only trailer allowed is one `Co-Authored-By` line naming Claude, e.g.:

  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  ```

  Nothing else: no "Generated with" line, no session link, no other trailer — in commits
  and in pull request descriptions alike.

## Before opening a pull request

```sh
make test               # unit + regression tests (no container needed)
make quickstart         # if Docker is available
make quickstart-check   # end-to-end chain: mTLS, header stripping, links, isolation, ledger
make quickstart-down
```

All must pass. Say in the PR description what you ran and what you could not run.

## Security invariants — never weaken these

- Identity comes **only** from proxy-set headers (`SDOP_TRUST_MODE=proxy`) or, in dev mode,
  from the process environment. Never from the request body, URL, cookies (except the
  server-resolved link session) or client-chosen headers.
- Every nginx `location` that proxies to a backend includes the strip+inject fragment
  (`sdop-trusted-headers.inc` internal, `sdop-ext-headers.inc` external). The external
  vhost opens only the read routes; everything else is 404.
- Authorization = TLP clearance **and** being a recipient (`watermark/authz.py`). TLP:RED is
  never shareable by link.
- Backends (watermark, placeholder, stub) never get a host port in `docker-compose.yml` or
  `demo/compose.yml`. In the demo each backend shares a network with nginx only; in the
  reference deployment they join the identity stack's network, which must hold nothing
  untrusted. Only nginx is published, on loopback in the demo. SDOP does not authenticate
  its peer: anything that can reach the backend port can claim any identity (see
  `docs/contrat-identite.md` § 4).
- The ledger is fail-closed: an action that cannot be logged must fail.
- Never add secrets, real hostnames, IP addresses, real names or real documents. Test and
  demo data must be fictitious (`exemple.invalid`, `example.invalid`, `.localhost`).

## Out of scope

Real deployments, PKI, production identity provider configuration, infrastructure.
If a change needs one of these, open an issue describing it instead of implementing it.
