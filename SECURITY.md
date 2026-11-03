# Security Policy

## Reporting a problem

Use GitHub's private vulnerability reporting (Security tab, "Report a vulnerability") if it is
enabled; otherwise contact the maintainer, [@DakodaStemen](https://github.com/DakodaStemen),
directly. Do not open a public issue for a vulnerability or a leaked secret.

## What not to commit

- Secrets, tokens, passwords and API keys
- `.env` files, private keys and certificates
- Personal data

If you committed one by mistake, rotate the credential first and tell the maintainer. A new
commit alone does not help: the data stays in history.
