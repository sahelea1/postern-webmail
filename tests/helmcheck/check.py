"""Renders the Helm chart in several configurations and checks the result.
usage: check.py CHART_DIR"""
import copy, json, os, subprocess, sys, tempfile
import yaml

chart = os.path.abspath(sys.argv[1])
here = os.path.dirname(os.path.abspath(__file__))
base = yaml.safe_load(open(os.path.join(chart, "values.yaml")))
meta = yaml.safe_load(open(os.path.join(chart, "Chart.yaml")))


def render(overrides, release="demo", expect_fail=False):
    def merge(a, b):
        for k, v in b.items():
            if isinstance(v, dict) and isinstance(a.get(k), dict):
                merge(a[k], v)
            else:
                a[k] = v
        return a
    values = merge(copy.deepcopy(base), overrides)
    with tempfile.TemporaryDirectory() as d:
        json.dump(values, open(os.path.join(d, "values.json"), "w"))
        json.dump(meta, open(os.path.join(d, "chart.json"), "w"))
        r = subprocess.run(["go", "run", os.path.join(here, "main.go"), chart, os.path.join(d, "values.json"), release],
                           capture_output=True, text=True, cwd=here)
    if expect_fail:
        assert r.returncode != 0, "expected a render error"
        return r.stderr
    assert r.returncode == 0, r.stderr
    docs = [d for d in yaml.safe_load_all(r.stdout) if d]
    return {(d["kind"]): d for d in docs}, r.stderr


def container(docs):
    return docs["Deployment"]["spec"]["template"]["spec"]["containers"][0]


def env(docs):
    return {e["name"]: e.get("value", e.get("valueFrom")) for e in container(docs)["env"]}


# 1. defaults
docs, notes = render({})
assert set(docs) == {"ConfigMap", "Deployment", "Ingress", "Secret", "Service"}, set(docs)
dep, c = docs["Deployment"], container(docs)
assert c["image"] == "registry.example.com/postern:0.1.2", c["image"]
assert c["securityContext"] == {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
pod = dep["spec"]["template"]["spec"]
assert pod["securityContext"]["runAsNonRoot"] is True and pod["securityContext"]["runAsUser"] == 65532
assert pod["automountServiceAccountToken"] is False
e = env(docs)
assert e["POSTERN_ADMIN_LISTEN"] == "off" and e["POSTERN_SERVERS_FILE"] == "/config/servers.toml"
assert e["POSTERN_TRUST_PROXY"] == "1" and e["POSTERN_SESSION_HOURS"] == "168" and e["POSTERN_MAX_UPLOAD_MB"] == "25"
assert e["POSTERN_SECRET_KEY"] == {"secretKeyRef": {"name": "demo-postern-key", "key": "secret-key"}}
assert dep["spec"]["selector"]["matchLabels"] == docs["Service"]["spec"]["selector"]
assert dep["spec"]["strategy"]["type"] == "RollingUpdate"
assert {v["name"] for v in pod["volumes"]} == {"data", "servers"} and "emptyDir" in pod["volumes"][0]
assert c["resources"]["limits"]["memory"] == "512Mi"
toml_text = docs["ConfigMap"]["data"]["servers.toml"]
assert toml_text.strip().startswith("[[server]]") and 'imap_host = "mail.example.com"' in toml_text
import base64
key = base64.b64decode(docs["Secret"]["data"]["secret-key"]).decode()
assert len(key) == 64 and all(ch in "0123456789abcdef" for ch in key), key
assert docs["Secret"]["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
ing = docs["Ingress"]
assert ing["spec"]["rules"][0]["host"] == "webmail.example.com"
assert ing["spec"]["tls"][0] == {"hosts": ["webmail.example.com"], "secretName": "demo-postern-tls"}
assert ing["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"] == {"name": "demo-postern", "port": {"name": "http"}}
assert "ingressClassName" not in ing["spec"]
assert not ing["metadata"].get("annotations")
assert "No cert-manager issuer is set" in notes

# the generated ConfigMap content is a valid Postern server list
with tempfile.TemporaryDirectory() as d:
    open(os.path.join(d, "servers.toml"), "w").write(toml_text)
    binary = os.environ.get("POSTERN_BIN")
    if binary:
        r = subprocess.run([binary, "check"], env=dict(os.environ, POSTERN_SERVERS_FILE=os.path.join(d, "servers.toml")), capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        print("ok    servers.toml from the chart passes `postern check`")

# 2. existing ClusterIssuer, nginx class, custom annotations
docs, _ = render({"ingress": {"className": "nginx", "host": "mail.example.org", "annotations": {"a/b": "c"},
                              "tls": {"clusterIssuer": "letsencrypt-prod"}}, "maxUploadMb": 40})
ann = docs["Ingress"]["metadata"]["annotations"]
assert ann == {"cert-manager.io/cluster-issuer": "letsencrypt-prod", "nginx.ingress.kubernetes.io/proxy-body-size": "42m", "a/b": "c"}, ann
assert docs["Ingress"]["spec"]["ingressClassName"] == "nginx"

# 3. chart-created ACME issuer
docs, _ = render({"acme": {"createIssuer": True, "email": "ops@example.com"}, "ingress": {"className": "traefik"}})
iss = docs["Issuer"]
assert iss["apiVersion"] == "cert-manager.io/v1" and iss["spec"]["acme"]["email"] == "ops@example.com"
assert iss["spec"]["acme"]["solvers"][0]["http01"]["ingress"]["ingressClassName"] == "traefik"
assert iss["spec"]["acme"]["privateKeySecretRef"]["name"] == "demo-postern-acme-account"
assert docs["Ingress"]["metadata"]["annotations"] == {"cert-manager.io/issuer": "demo-postern-acme"}
err = render({"acme": {"createIssuer": True}}, expect_fail=True)
assert "acme.email is required" in err, err

# 4. admin console with persistence, no servers in values
docs, notes = render({"servers": "", "admin": {"enabled": True}, "persistence": {"enabled": True, "size": "1Gi"}})
assert "ConfigMap" not in docs and docs["PersistentVolumeClaim"]["spec"]["resources"]["requests"]["storage"] == "1Gi"
e = env(docs)
assert e["POSTERN_ADMIN_LISTEN"] == "127.0.0.1:8081" and "POSTERN_SERVERS_FILE" not in e
pod = docs["Deployment"]["spec"]["template"]["spec"]
assert pod["volumes"] == [{"name": "data", "persistentVolumeClaim": {"claimName": "demo-postern-data"}}], pod["volumes"]
assert docs["Deployment"]["spec"]["strategy"]["type"] == "Recreate"
assert "admin-link" in notes and "port-forward" in notes

# 5. existing secret, no ingress, release named like the chart, pod settings
docs, _ = render({"secretKey": {"existingSecret": "my-key"}, "ingress": {"enabled": False},
                  "nodeSelector": {"kubernetes.io/arch": "arm64"}, "tolerations": [{"key": "x", "operator": "Exists"}],
                  "imagePullSecrets": [{"name": "regcred"}], "image": {"tag": "1.2.3"}, "podAnnotations": {"p": "q"}},
                 release="postern")
assert "Secret" not in docs and "Ingress" not in docs
assert docs["Deployment"]["metadata"]["name"] == "postern"
assert env(docs)["POSTERN_SECRET_KEY"]["secretKeyRef"]["name"] == "my-key"
pod = docs["Deployment"]["spec"]["template"]["spec"]
assert pod["nodeSelector"] == {"kubernetes.io/arch": "arm64"} and pod["tolerations"][0]["key"] == "x"
assert pod["imagePullSecrets"] == [{"name": "regcred"}]
assert container(docs)["image"].endswith(":1.2.3")
assert docs["Deployment"]["spec"]["template"]["metadata"]["annotations"]["p"] == "q"

# 6. a key given in the values
docs, _ = render({"secretKey": {"value": "ab" * 32}})
assert base64.b64decode(docs["Secret"]["data"]["secret-key"]).decode() == "ab" * 32
print("HELM CHART CHECKS PASSED (6 configurations)")
