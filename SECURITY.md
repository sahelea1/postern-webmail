# Security

Postern handles mail passwords, so reports are welcome and taken seriously.

## Reporting a vulnerability

Please do not open a public issue with the details.

Use **Security → Report a vulnerability** on this repository (GitHub's private reporting). If that button is not there, open an issue that says only that you have a security report and how to reach you; no details.

Helpful in a report: the version (`postern version`), the protocol in use (IMAP or JMAP), what you did, what happened, and what you expected.

## Supported versions

The latest release only. The project is at 0.1 and has had no independent security review; see "What is tested and what is not" in the [README](README.md).

## In scope

- Reading or changing another user's mail or session
- Recovering a password from a cookie, a log line or the data directory alone
- Script execution or network requests caused by opening a message
- Getting past the cross-site request checks or the sign-in limit
- Reaching the admin console without a link from `postern admin-link`
- Making the gateway connect to a host that is not in `servers.toml`
- S/MIME: a signature shown as valid or trusted that is not, a message shown as encrypted that is not, recovering a private key from the sealed blob alone, decrypted content leaking into remote requests

## Known and accepted

- Whoever holds both `secret.key` and a user's cookie can recover that user's password. This is the price of speaking IMAP and SMTP with passwords; it is described in the README.
- The sign-out list is kept in memory. After a restart, a cookie stolen before sign-out works again until it expires.
- The sign-in limit and the sign-out list are per process, so they are weaker with several replicas.
- Whoever holds both `secret.key` and a browser's sealed S/MIME key blob can recover that private key, the same trade-off as for passwords.
- S/MIME revocation (CRL, OCSP) is not checked.
- RSA decryption uses the `rsa` crate, which is still affected by RUSTSEC-2023-0071 (timing). Decryption only happens when the signed-in user opens a message.
