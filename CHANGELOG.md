# Changelog

## 0.1.2

- Fixed: a first start on a full disk left an empty `secret.key` behind, and every later start refused it. The key is now written to a temporary file and renamed into place, and an empty key file is replaced.

## 0.1.1

- Added `POSTERN_SERVERS_SEED`: a starter server list that is copied into the data directory on the first start only.

## 0.1.0

- First version: IMAP + SMTP and JMAP backends, web client, admin console, Docker Compose file for Traefik, Helm chart.
