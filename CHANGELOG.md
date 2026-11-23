# Changelog

## 0.2.0

- S/MIME: sign, encrypt, or both; verify and decrypt incoming mail. Your key is imported from a .p12/.pfx file and kept sealed in the browser; certificates of other people are collected from verified signatures or imported by hand. Signatures are checked against Mozilla's roots for e-mail. Tested against OpenSSL in both directions.
- Columns: drag the edges of the folder list and the message list; arrow keys work too, a double click resets. The widths are kept per browser.
- Colour themes: eight to choose from, each in light and dark.
- Privacy: remote images ask, always or never, with a per-sender allow list; an option to prefer plain text over HTML. Decrypted mail always asks.
- Notifications: desktop notification and sound for new mail in the inbox, unread count in the tab title. The list now also refreshes while the tab is in the background.
- Settings are organised in tabs.
- Fixed: signing out took seconds. The sign-out response asked the browser to clear its cache and storage (`Clear-Site-Data`), which browsers do before going on, and which also erased the settings kept in the browser. The header is gone, the screen changes at once, and the IMAP connection is closed in the background.

## 0.1.2

- Fixed: a first start on a full disk left an empty `secret.key` behind, and every later start refused it. The key is now written to a temporary file and renamed into place, and an empty key file is replaced.

## 0.1.1

- Added `POSTERN_SERVERS_SEED`: a starter server list that is copied into the data directory on the first start only.

## 0.1.0

- First version: IMAP + SMTP and JMAP backends, web client, admin console, Docker Compose file for Traefik, Helm chart.
