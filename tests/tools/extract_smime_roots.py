"""Extracts the roots Mozilla trusts for e-mail (S/MIME) from NSS certdata.txt.

usage: extract.py certdata.txt out.pem NSS_COMMIT

A root is included when its trust object says
CKA_TRUST_EMAIL_PROTECTION CKT_NSS_TRUSTED_DELEGATOR and it carries no
e-mail distrust-after date. Matching is by issuer and serial number.
"""
import base64, sys

src, out, commit = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(src, encoding="utf-8").read().splitlines()

objects, cur, i = [], None, 0
while i < len(lines):
    line = lines[i]
    if line.startswith("CKA_CLASS"):
        cur = {"class": line.split()[-1]}
        objects.append(cur)
    elif cur is not None and line and not line.startswith("#"):
        parts = line.split(None, 2)
        if len(parts) >= 2 and parts[1] == "MULTILINE_OCTAL":
            data = bytearray()
            i += 1
            while lines[i] != "END":
                for tok in lines[i].split("\\")[1:]:
                    data.append(int(tok, 8))
                i += 1
            cur[parts[0]] = bytes(data)
        elif len(parts) >= 3:
            cur[parts[0]] = parts[2]
        elif len(parts) == 2:
            cur[parts[0]] = parts[1]
    i += 1

certs = {(o["CKA_ISSUER"], o["CKA_SERIAL_NUMBER"]): o for o in objects
         if o["class"] == "CKO_CERTIFICATE" and "CKA_VALUE" in o}
picked = []
for o in objects:
    if o["class"] != "CKO_NSS_TRUST":
        continue
    if not o.get("CKA_TRUST_EMAIL_PROTECTION", "").endswith("CKT_NSS_TRUSTED_DELEGATOR"):
        continue
    c = certs.get((o.get("CKA_ISSUER"), o.get("CKA_SERIAL_NUMBER")))
    if c is None:
        continue
    if isinstance(c.get("CKA_NSS_EMAIL_DISTRUST_AFTER"), bytes):
        continue  # distrusted for e-mail after some date: left out entirely
    label = c.get("CKA_LABEL", "").strip('"')
    picked.append((label, c["CKA_VALUE"]))

picked.sort(key=lambda x: x[0].lower())
with open(out, "w", encoding="utf-8") as f:
    f.write("# Root certificates Mozilla trusts for e-mail protection (S/MIME).\n")
    f.write(f"# Extracted from NSS lib/ckfw/builtins/certdata.txt at commit {commit}\n")
    f.write("# by tests/tools/extract_smime_roots.py. Licence of the data: MPL-2.0.\n")
    f.write(f"# {len(picked)} certificates.\n\n")
    for label, der in picked:
        b64 = base64.b64encode(der).decode()
        f.write(f"# {label}\n-----BEGIN CERTIFICATE-----\n")
        for k in range(0, len(b64), 64):
            f.write(b64[k:k + 64] + "\n")
        f.write("-----END CERTIFICATE-----\n\n")
print(len(picked), "roots")
