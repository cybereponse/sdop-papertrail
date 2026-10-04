# Contributing

Contributions go through **pull requests** on GitHub. The main working repository is hosted
elsewhere; an accepted pull request is integrated there and then republished here — GitHub may
therefore show it as merged shortly after integration.

## Before opening a pull request

```sh
make test
make quickstart && make quickstart-check && make quickstart-down   # if Docker is available
```

Read [`docs/contrat-identite.md`](docs/contrat-identite.md) before changing anything related to
identity, headers or nginx. The security invariants are listed in [`CLAUDE.md`](CLAUDE.md); a
pull request weakening one of them will be declined.

## Rules

- One pull request = one topic. Commit messages in English, imperative subject line.
- User and tester documentation in English; user interface and code comments in French, like
  the rest of the code.
- No real data: fictitious names, addresses, documents and test domains (`exemple.invalid`,
  `example.invalid`, `.localhost`).
- **DCO**: every commit carries `Signed-off-by: Name <address>` (`git commit -s`), certifying
  the [Developer Certificate of Origin](https://developercertificate.org/). Agent sessions
  started by maintainers follow `CLAUDE.md`; the maintainer integrating their pull request is
  accountable for it.

## Licence

By contributing, you agree that your contribution is distributed under [EUPL-1.2](LICENSE).
