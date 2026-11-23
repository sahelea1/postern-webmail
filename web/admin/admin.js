// Postern admin console. Plain DOM calls only: no markup is ever built from strings.

const app = document.getElementById("app");
let state = null;
let servers = [];
let saved = "";
let message = null;
const results = new Map();

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, "");
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return el;
}

async function api(path, body) {
  const resp = await fetch(path, body === undefined ? {} : {
    method: "POST",
    headers: { "content-type": "application/json", "x-postern": "1" },
    body: JSON.stringify(body),
  });
  let data = null;
  try { data = await resp.json(); } catch { /* no body */ }
  if (!resp.ok) throw Object.assign(new Error(data?.message || `Request failed (${resp.status})`), { status: resp.status });
  return data;
}

const blank = () => ({
  id: "", name: "", domains: [], protocol: "imap", enabled: true, username: "email", tls_insecure: false,
  remote_images: "ask", imap_host: "", imap_port: 993, imap_security: "tls", smtp_host: "", smtp_port: 465,
  smtp_security: "tls", save_sent: true, jmap_url: "",
});

const dirty = () => JSON.stringify(servers) !== saved;

function field(label, cls, input, hint) {
  return h("label", { class: `f ${cls}` }, label, input, hint && h("small", null, hint));
}

function text(obj, key, opts = {}) {
  const el = h("input", { type: "text", spellcheck: "false", autocomplete: "off", placeholder: opts.placeholder || "", value: obj[key] ?? "" });
  el.value = obj[key] ?? "";
  el.addEventListener("input", () => { obj[key] = el.value; bar(); });
  return el;
}

function number(obj, key) {
  const el = h("input", { type: "number", min: "1", max: "65535" });
  el.value = obj[key];
  el.addEventListener("input", () => { obj[key] = Number(el.value) || 0; bar(); });
  return el;
}

function select(obj, key, options, rerender) {
  const el = h("select", null, options.map(([v, label]) => h("option", { value: v }, label)));
  el.value = obj[key];
  el.addEventListener("change", () => { obj[key] = el.value; rerender ? render() : bar(); });
  return el;
}

function toggle(obj, key, label) {
  const el = h("input", { type: "checkbox" });
  el.checked = !!obj[key];
  el.addEventListener("change", () => { obj[key] = el.checked; render(); });
  return h("label", { class: "t" }, el, label);
}

const SECURITY = [["tls", "TLS"], ["starttls", "STARTTLS"], ["none", "None (private network only)"]];

function card(s, index) {
  const domains = h("input", { type: "text", spellcheck: "false", autocomplete: "off", placeholder: "example.com, *.example.org" });
  domains.value = s.domains.join(", ");
  domains.addEventListener("input", () => {
    s.domains = domains.value.split(/[,\s]+/).map((d) => d.trim()).filter(Boolean);
    bar();
  });
  const res = results.get(s);
  return h("section", { class: `card ${s.enabled ? "" : "off"}` },
    h("div", { class: "row" },
      h("h2", null, s.name || s.id || "New server"),
      h("span", { class: "small" }, s.protocol.toUpperCase()),
      h("span", { class: "grow" }),
      h("button", { class: "quiet", onclick: () => test(s) }, "Test connection"),
      h("button", { class: "danger", onclick: () => { servers.splice(index, 1); render(); } }, "Remove"),
    ),
    h("div", { class: "grid" },
      field("Identifier", "c2", text(s, "id", { placeholder: "main" }), "Letters, digits, - and _"),
      field("Display name", "c2", text(s, "name", { placeholder: "Example Mail" })),
      field("Protocol", "c2", select(s, "protocol", [["imap", "IMAP + SMTP"], ["jmap", "JMAP"]], true)),
      field("Domains that may sign in", "c6", domains, "Comma separated. *.example.com matches subdomains, * matches every domain."),
      s.protocol === "imap" ? [
        field("IMAP host", "c2", text(s, "imap_host", { placeholder: "imap.example.com" })),
        field("Port", "c2", number(s, "imap_port")),
        field("Security", "c2", select(s, "imap_security", SECURITY)),
        field("SMTP host", "c2", text(s, "smtp_host", { placeholder: "smtp.example.com" })),
        field("Port", "c2", number(s, "smtp_port")),
        field("Security", "c2", select(s, "smtp_security", SECURITY)),
      ] : [
        field("JMAP server URL", "c6", text(s, "jmap_url", { placeholder: "https://mail.example.com" }), "The origin of the server. The session is discovered at /.well-known/jmap."),
      ],
      field("Mail server user name", "c3", select(s, "username", [["email", "Full address (ann@example.com)"], ["local", "Part before the @ (ann)"]])),
      field("Remote images in messages", "c3", select(s, "remote_images", [["ask", "Hidden until the reader asks"], ["never", "Never loaded"]])),
    ),
    h("div", { class: "toggles" },
      toggle(s, "enabled", "Enabled"),
      s.protocol === "imap" && toggle(s, "save_sent", "Store sent mail in the Sent folder"),
      toggle(s, "tls_insecure", "Accept invalid TLS certificates"),
    ),
    s.tls_insecure && h("div", { class: "result" }, h("div", { class: "note warn" }, "Certificates are not verified for this server. Anyone on the network path could read or change the traffic, passwords included.")),
    res && h("div", { class: "result" }, res.map((r) => h("div", { class: `note ${r.ok ? "ok" : "bad"}` }, `${r.what}: ${r.detail}`))),
  );
}

async function test(s) {
  results.set(s, [{ ok: true, what: "Test", detail: "running…" }]);
  render();
  try {
    const r = await api("/api/test", { ...s });
    results.set(s, r.checks);
  } catch (e) {
    results.set(s, [{ ok: false, what: "Test", detail: e.message }]);
  }
  render();
}

async function save() {
  try {
    await api("/api/servers", { servers });
    saved = JSON.stringify(servers);
    message = { ok: true, text: "Saved. Changes are live." };
  } catch (e) {
    message = { ok: false, text: e.message };
    if (e.status === 401) return load();
  }
  render();
}

let barEl = null;
function bar() {
  if (!barEl) return;
  barEl.replaceChildren(
    h("span", { class: message ? (message.ok ? "note ok" : "note bad") : "muted" }, message ? message.text : dirty() ? "Unsaved changes" : "No changes"),
    h("span", { class: "grow" }),
    h("button", { class: "quiet", disabled: !dirty(), onclick: () => { servers = JSON.parse(saved); message = null; results.clear(); render(); } }, "Discard"),
    h("button", { class: "primary", disabled: !dirty(), onclick: save }, "Save changes"),
  );
  message = null;
}

function gate() {
  const denied = new URLSearchParams(location.search).has("denied");
  app.replaceChildren(h("main", { class: "gate" },
    h("div", { class: "card" },
      h("h1", null, "Postern admin"),
      h("p", { class: "muted" }, "This console has no password. Create a single-use sign-in link on the host and open it in this browser."),
      denied && h("div", { class: "result" }, h("div", { class: "note bad" }, "That link is invalid, already used or older than 10 minutes.")),
      h("pre", null, "# Docker Compose\ndocker compose exec postern /postern admin-link\n\n# Kubernetes\nkubectl exec deploy/postern -- /postern admin-link\n\n# plain binary\npostern admin-link"),
      h("p", { class: "small" }, "The link is valid for 10 minutes and works once. The session lasts two hours."),
    ),
  ));
}

function render() {
  if (!state) return gate();
  const up = state.uptime_secs;
  const uptime = up > 86400 ? `${Math.floor(up / 86400)} d` : up > 3600 ? `${Math.floor(up / 3600)} h` : `${Math.max(1, Math.floor(up / 60))} min`;
  barEl = h("div", null);
  app.replaceChildren(
    h("main", null,
      h("div", { class: "top" },
        h("h1", null, `${state.brand} admin`),
        h("span", { class: "grow" }),
        h("button", { class: "quiet", onclick: async () => { await api("/api/logout", {}); state = null; render(); } }, "Sign out"),
      ),
      h("p", { class: "muted" }, "Mail servers and the domains allowed to sign in. Nothing else is stored: no accounts, no mail, no passwords."),
      h("div", { class: "chips" },
        h("span", { class: "chip" }, `Version ${state.version}`),
        h("span", { class: "chip" }, `Up ${uptime}`),
        h("span", { class: "chip" }, `Sessions last ${state.session_hours} h`),
        h("span", { class: "chip" }, `Attachments up to ${state.max_upload_mb} MB`),
        h("span", { class: `chip ${state.secure_cookies ? "" : "warn"}` }, state.secure_cookies ? "Secure cookies on" : "Insecure HTTP mode"),
        h("span", { class: `chip ${state.trust_proxy ? "" : "warn"}` }, state.trust_proxy ? "Client address from proxy header" : "Proxy header not trusted"),
      ),
      state.read_only && h("div", { class: "card" }, h("p", { class: "note warn" }, "The server list comes from a file set with POSTERN_SERVERS_FILE. It is shown here but cannot be changed in this console.")),
      servers.length === 0 && h("div", { class: "card" }, h("p", { class: "muted" }, "No mail server yet. Add one so that people can sign in.")),
      servers.map(card),
      h("button", { onclick: () => { servers.push(blank()); render(); } }, "Add mail server"),
    ),
    h("div", { class: "bar" }, barEl),
  );
  bar();
}

async function load() {
  try {
    state = await api("/api/state");
    servers = state.servers;
    saved = JSON.stringify(servers);
    if (location.search) history.replaceState(null, "", "/");
  } catch {
    state = null;
  }
  render();
}

load();
