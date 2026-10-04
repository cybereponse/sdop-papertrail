# Identity contract — what SDOP expects from its proxy and identity provider

SDOP authenticates nobody itself. On the internal path it **trusts** headers set by a reverse
proxy placed in front of it (`SDOP_TRUST_MODE=proxy`, `watermark/identity.py`). This document
states what that proxy must guarantee. A reference implementation exists: nginx
(`nginx/conf.d/`) + an Authentik outpost in forward-auth mode. Another provider (Keycloak +
oauth2-proxy, Authelia…) is **an adapter to be validated** against this contract and against
the `test/regression/verify_chain.sh` acceptance scenarios — not a proven drop-in.

## 1. Two paths, two boundaries

| | Internal path (`app.*`) | Link path (`ext.*`) |
|---|---|---|
| Who | analysts and recipients with an account | recipient without an account (incident victim) |
| Proof | client certificate (mTLS) **and** identity-provider session | link token + second factor (TOTP or code read out by phone) |
| Identity | set by the proxy in the headers below | **resolved by SDOP** from an opaque session cookie (`sdop_lien`) |
| Identity headers | strip + inject | **all emptied**, none injected (`sdop-ext-headers.inc`) |
| Open routes | all | link page, viewer, tiles, export — anything else returns 404 (`sdop-ext-locations.inc`) |

A header list only describes the first path. The second receives **no** identity from the
proxy; if it did, a link holder could claim to be anyone.

## 2. Headers consumed (internal path)

| Header | Use | Requirement |
|---|---|---|
| `X-Authentik-Username` | subject identifier: attribution (watermark, ledger), publisher status, recipient lists | **mandatory** — missing or empty ⇒ 401. Stable, unique and **canonical** (constant case) over time: a rename breaks attribution and recipient lists. Recipient lists are compared case-insensitively, some publisher rights exactly. |
| `X-Authentik-Groups` | TLP clearances and administration | `\|` separator (comma also accepted). Empty = no clearance. |
| `X-Authentik-Email` | display, attribution | optional |
| `X-Client-Cert-CN` | CN of the mTLS client certificate — attribution | set by the proxy from the TLS handshake, never from the request |
| `X-Forwarded-For` | client address (first element): ledger, watermark | **replaced** by the proxy (`$remote_addr`), never appended to |
| `Host` | origin check on state-changing requests (with `Sec-Fetch-Site`/`Origin`) | public name of the vhost |

### Groups ↔ TLP roles (`watermark/authz.py`)

`<prefix><level>-<role>`, prefix `tlp-` (`SDOP_GROUP_PREFIX`), level `red`, `amber-strict`,
`amber`, role `lecteurs` (read), `relecteurs` (read and review), `emetteurs` (publish, read,
review). **No implicit hierarchy** between levels. `platform-admins` (`SDOP_ADMIN_GROUP`)
administers; that group **alone** grants no read access. A subject holding it plus a TLP group
and recipient status reads like any cleared recipient.

### Authorisation = clearance × recipient

A group is a **ceiling**, not a permission: opening a document requires clearance at its level
**and** being one of its recipients (or its publisher) (`resolve_and_authorize`). An identity
provider granting too broad a group therefore does not open every document of that level —
but it does open those the subject is a recipient of.

## 3. Proxy obligations

1. **Strip + inject on EVERY route** relayed to SDOP: each trusted header is either the
   verified value or an explicit empty string. Never the value sent by the client. With nginx,
   `proxy_set_header` is not inherited by a `location` that declares another one: hence a
   fragment included in every `location` (`sdop-trusted-headers.inc`).
2. **Also empty** provider headers SDOP does not read, so that a future read on SDOP's side
   does not become an injection. The reference implementation does this with an **explicit
   list**, not a pattern: `X-Authentik-Name`, `-Jwt`, `-Meta-*` (internal vhost) and
   `Authorization`. The external vhost empties identity headers but not `X-Authentik-Meta-*`,
   which no SDOP code reads today. Any new header read by SDOP must be added to both fragments.
3. **Link path**: empty every identity header, open only the read routes (§1).
4. **Expected refusals**: no client certificate or a revoked one ⇒ refused by the proxy before
   any relay (TLS handshake failure or HTTP 400 depending on the client); no session ⇒
   redirect to login, never a pass-through without headers; client-forged headers ⇒
   overwritten. `verify_chain.sh` checks missing/revoked certificates and forged headers; it
   does **not** simulate a missing session (its fake provider always logs in): that refusal
   must be checked against a real provider (`scripts/verify.sh`).
5. **Revocation**: CRL reloaded by the proxy (nginx keeps it in memory until reload).

## 4. Protection against direct access

The contract only holds if **nothing but the proxy** can reach SDOP: a client — or a
neighbouring container — that reaches the service port sets whatever headers it wants. Trusted
peers are, in fact: the proxy, the container runtime and the host's administrators. Require:

- no host port published for the service (only the proxy is exposed);
- a dedicated network between proxy and service holding nothing untrusted (the demo gives
  each backend its own network, shared with nginx only);
- proxy → service transport on that private network (plain HTTP in the reference
  implementation: the network is the boundary; proxy → service mTLS is possible, not
  required).

SDOP does not authenticate its peer (accepted risk): this requirement is part of the contract,
just like the headers.

## 5. Checking an implementation

The autonomous demo (`demo/`, `make quickstart-check`) and the regression harness
(`test/regression/run-chain.sh`) replay the same scenarios against a real chain: forged-header
stripping, mTLS and CRL, refusal of a TLP:RED publication by an AMBER publisher, link path,
closed routes on the external vhost, origin check, rate limiting. An adapter for another
provider must pass them identically.
