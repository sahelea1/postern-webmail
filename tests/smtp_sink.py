"""Test SMTP server: requires AUTH, then files every accepted message into the
recipient's IMAP inbox. Lets the end-to-end tests send a message and read it back.

usage: smtp_sink.py <smtp-port> <imap-port> <user> <password> <log-file> [cert key]

With a certificate and key the server offers STARTTLS and refuses AUTH before it.
"""
import asyncio, imaplib, json, sys, time
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword

smtp_port, imap_port, user, password, log = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]

def authenticator(server, session, envelope, mechanism, auth_data):
    ok = isinstance(auth_data, LoginPassword) and auth_data.login == user.encode() and auth_data.password == password.encode()
    return AuthResult(success=ok)

class Handler:
    async def handle_DATA(self, server, session, envelope):
        with open(log, "a") as f:
            f.write(json.dumps({"from": envelope.mail_from, "rcpt": envelope.rcpt_tos, "size": len(envelope.content)}) + "\n")
        def deliver():
            im = imaplib.IMAP4("127.0.0.1", imap_port)
            im.login(user, password)
            im.append("INBOX", "", imaplib.Time2Internaldate(time.time()), envelope.content)
            im.logout()
        await asyncio.get_running_loop().run_in_executor(None, deliver)
        return "250 OK"

tls = None
if len(sys.argv) > 7:
    import ssl
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(sys.argv[6], sys.argv[7])
c = Controller(Handler(), hostname="127.0.0.1", port=smtp_port, authenticator=authenticator,
               auth_required=True, auth_require_tls=tls is not None, tls_context=tls, require_starttls=tls is not None)
c.start()
print("smtp sink on", smtp_port, flush=True)
while True:
    time.sleep(3600)
