# Reporting a vulnerability

Please do **not** open a public issue for a vulnerability.

Use GitHub's private vulnerability reporting (the **Security** tab of this repository), or
write to **cert@cybereponse.fr** with: affected version or commit, description, reproduction
steps, estimated impact. We aim to acknowledge within 5 working days; the fix and disclosure
date are agreed with the reporter.

In scope: the code in this repository (`watermark` service, ledger, reference nginx vhosts,
demo). Out of scope: using the demo as a deployment (it has **no** real authentication, as
documented), third-party identity providers.
