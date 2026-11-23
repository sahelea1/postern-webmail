// Everything the interface knows, in one place: signals for state, functions
// for every action. Components read signals and call these functions.

import { computed, signal } from "@preact/signals";
import { setLanguage, t } from "./i18n";

// ---- types -----------------------------------------------------------------

export interface Addr {
  name: string | null;
  email: string;
}
export interface Mailbox {
  id: string;
  name: string;
  parent: string | null;
  role: string | null;
  total: number;
  unread: number;
  selectable: boolean;
}
export interface Summary {
  id: string;
  subject: string;
  from: Addr[];
  to: Addr[];
  date: string | null;
  size: number;
  seen: boolean;
  flagged: boolean;
  answered: boolean;
  draft: boolean;
  attachment: boolean;
  preview: string;
  security: "signed" | "encrypted" | null;
}
export interface AttachmentInfo {
  part: number;
  name: string;
  mime: string;
  size: number;
  inline: boolean;
}
export interface MessageView {
  subject: string;
  from: Addr[];
  to: Addr[];
  cc: Addr[];
  bcc: Addr[];
  reply_to: Addr[];
  date: string | null;
  message_id: string | null;
  references: string[];
  text: string;
  has_html: boolean;
  remote_images: boolean;
  can_load_images: boolean;
  attachments: AttachmentInfo[];
  size: number;
  security: Security;
  key_invalid: boolean;
}
export interface CertInfo {
  fingerprint: string;
  name: string;
  subject: string;
  issuer: string;
  emails: string[];
  not_before: string;
  not_after: string;
  key: string;
  can_encrypt: boolean;
  can_sign: boolean;
  trust: "trusted" | "expired" | "untrusted" | "invalid";
  trust_detail: string;
  der: string;
}
export interface SignatureReport {
  status: "valid" | "invalid" | "unsupported" | "error";
  detail: string;
  signer: CertInfo | null;
  signer_matches_from: boolean;
  trust: "trusted" | "expired" | "untrusted" | "invalid" | "";
  trust_detail: string;
  signed_at: string | null;
  weak: boolean;
}
export interface EncryptionReport {
  status: "decrypted" | "no_key" | "not_for_you" | "unsupported" | "failed";
  detail: string;
  algorithm: string;
}
export interface Security {
  signed: SignatureReport | null;
  encrypted: EncryptionReport | null;
}
/** A certificate of someone else, kept in this browser. */
export interface StoredCert extends CertInfo {
  source: "auto" | "manual";
  /** The user trusts it, whatever the server says about its issuer. */
  pinned: boolean;
  added: string;
}
/** The user's own key, sealed by the server; only the server can open it. */
export interface OwnKey {
  sealed: string;
  cert: CertInfo;
  canDecrypt: boolean;
  invalid?: boolean;
}
export interface Me {
  email: string;
  server: string;
  protocol: string;
  max_upload_mb: number;
  brand: string;
  version: string;
}
export type Palette = "indigo" | "ocean" | "forest" | "rose" | "amber" | "graphite" | "nord" | "paper";
export const PALETTES: { id: Palette; swatch: string }[] = [
  { id: "indigo", swatch: "#4f46e5" },
  { id: "ocean", swatch: "#0369a1" },
  { id: "forest", swatch: "#15803d" },
  { id: "rose", swatch: "#be185d" },
  { id: "amber", swatch: "#b45309" },
  { id: "graphite", swatch: "#3f3f46" },
  { id: "nord", swatch: "#4c6d96" },
  { id: "paper", swatch: "#a0522d" },
];
export type Sound = "off" | "chime" | "pop" | "bell";
export interface Prefs {
  name: string;
  signature: string;
  theme: "system" | "light" | "dark";
  palette: Palette;
  density: "comfortable" | "compact";
  language: "auto" | "en" | "de";
  images: "ask" | "always" | "never";
  imageSenders: string[];
  preferText: boolean;
  notify: boolean;
  notifyPreview: boolean;
  sound: Sound;
  signDefault: boolean;
}
export interface Draft {
  to: string;
  cc: string;
  bcc: string;
  subject: string;
  text: string;
  files: File[];
  showCc: boolean;
  inReplyTo?: string | null;
  references?: string[];
  answered?: { mailbox: string; id: string };
  replaceDraft?: { mailbox: string; id: string };
  forward?: { mailbox: string; id: string; parts: number[]; names: string[] };
  sign: boolean;
  encrypt: boolean;
}

// ---- api -------------------------------------------------------------------

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

/** Only these requests carry the user's sealed S/MIME key: reading one
 *  message (and its parts), sending, and the key check. Lists never do. */
const KEYED = /^\/api\/(message([/?]|$)|send$|smime\/status$)/;

function keyHeader(path: string): Record<string, string> {
  const k = ownKey.value;
  return k && !k.invalid && KEYED.test(path) ? { "x-postern-key": k.sealed } : {};
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let resp: Response;
  try {
    resp = await fetch(path, {
      credentials: "same-origin",
      ...init,
      headers: { "x-postern": "1", ...keyHeader(path), ...(init?.headers || {}) },
    });
  } catch {
    throw new ApiError(0, "offline", t("offline"));
  }
  if (resp.status === 401 && path !== "/api/login") {
    if (me.value) {
      notice.value = t("sessionEnded");
    }
    me.value = null;
  }
  let body: any = null;
  try {
    body = await resp.json();
  } catch {
    // not JSON
  }
  if (!resp.ok) {
    throw new ApiError(resp.status, body?.error || "error", body?.message || t("errorGeneric"));
  }
  return body as T;
}

const get = <T>(path: string, params?: Record<string, string | number | undefined>) => {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) {
    if (v !== undefined && v !== "") q.set(k, String(v));
  }
  const qs = q.toString();
  return request<T>(qs ? `${path}?${qs}` : path);
};

const post = <T>(path: string, body: unknown) =>
  request<T>(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });

export function messageUrl(kind: "html" | "part" | "raw", mailbox: string, id: string, extra: Record<string, string | number> = {}) {
  const q = new URLSearchParams({ mailbox, id });
  for (const [k, v] of Object.entries(extra)) q.set(k, String(v));
  return `/api/message/${kind}?${q}`;
}

// ---- state -----------------------------------------------------------------

const PREFS_KEY = "postern.prefs";
const LAYOUT_KEY = "postern.layout";
const KEYS_KEY = "postern.smime.keys";
const CERTS_KEY = "postern.smime.certs";
const defaultPrefs: Prefs = {
  name: "",
  signature: "",
  theme: "system",
  palette: "indigo",
  density: "comfortable",
  language: "auto",
  images: "ask",
  imageSenders: [],
  preferText: false,
  notify: false,
  notifyPreview: true,
  sound: "off",
  signDefault: true,
};

function loadJson<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return v ? (JSON.parse(v) as T) : fallback;
  } catch {
    return fallback;
  }
}

function saveJson(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // private mode or full: kept for this tab only
  }
}

function loadPrefs(): Prefs {
  return { ...defaultPrefs, ...loadJson<Partial<Prefs>>(PREFS_KEY, {}) };
}

export const brand = signal("Postern");
export const configured = signal(true);
/** undefined: not known yet. null: signed out. */
export const me = signal<Me | null | undefined>(undefined);
export const notice = signal("");
export const prefs = signal<Prefs>(loadPrefs());
export const mailboxes = signal<Mailbox[]>([]);
export const current = signal("");
export const query = signal("");
export const items = signal<Summary[]>([]);
export const total = signal(0);
export const listLoading = signal(false);
export const selected = signal<Set<string>>(new Set());
export const openId = signal<string | null>(null);
export const openView = signal<MessageView | null>(null);
export const openLoading = signal(false);
export const showImages = signal(false);
export const draft = signal<Draft | null>(null);
export const composerMin = signal(false);
export const sending = signal(false);
export const dialog = signal<null | { kind: "settings"; tab?: string } | { kind: "folder"; rename?: Mailbox } | { kind: "deleteFolder"; box: Mailbox } | { kind: "source"; text: string }>(null);
export const railOpen = signal(false);
/** Column widths the user dragged, in pixels; absent means the default. */
export const layout = signal<{ rail?: number; list?: number }>(loadJson(LAYOUT_KEY, {}));
export const ownKeys = signal<Record<string, OwnKey>>(loadJson(KEYS_KEY, {}));
export const ownKey = computed(() => {
  const m = me.value;
  return m ? (ownKeys.value[m.email.toLowerCase()] ?? null) : null;
});
export const certStore = signal<StoredCert[]>(loadJson(CERTS_KEY, []));
export const toasts = signal<{ id: number; text: string; error?: boolean }[]>([]);

export const byRole = (role: string) => mailboxes.value.find((m) => m.role === role);
export const currentBox = computed(() => mailboxes.value.find((m) => m.id === current.value));
export const openSummary = computed(() => items.value.find((m) => m.id === openId.value) || null);

let toastSeq = 0;
export function toast(text: string, error = false) {
  const id = ++toastSeq;
  toasts.value = [...toasts.value, { id, text, error }];
  setTimeout(() => {
    toasts.value = toasts.value.filter((x) => x.id !== id);
  }, error ? 7000 : 3500);
}

export function fail(e: unknown) {
  if (e instanceof ApiError && e.status === 401) return;
  toast(e instanceof Error ? e.message : t("errorGeneric"), true);
}

export function applyPrefs() {
  const p = prefs.value;
  setLanguage(p.language);
  const dark = p.theme === "dark" || (p.theme === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
  const root = document.documentElement;
  root.dataset.theme = dark ? "dark" : "light";
  root.dataset.palette = p.palette;
  root.dataset.density = p.density;
}

export function setPrefs(p: Prefs) {
  prefs.value = p;
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify(p));
  } catch {
    // private mode: preferences last for this tab only
  }
  applyPrefs();
}

// ---- session ---------------------------------------------------------------

export async function boot() {
  applyPrefs();
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", applyPrefs);
  let signedIn = false;
  try {
    const c = await get<{ brand: string; configured: boolean; signed_in: boolean }>("/api/config");
    brand.value = c.brand;
    configured.value = c.configured;
    signedIn = c.signed_in;
    document.title = c.brand;
  } catch {
    // shown as a sign-in error later
  }
  if (!signedIn) {
    me.value = null;
    return;
  }
  try {
    me.value = await get<Me>("/api/me");
    await enter();
  } catch (e) {
    if (me.value) fail(e);
    else me.value = null;
  }
}

// ---- layout ----------------------------------------------------------------

const LIMITS = { rail: [180, 420], list: [260, 900] } as const;

function paneWidth(which: "rail" | "list"): number {
  return layout.value[which] ?? document.querySelector(`.${which}`)?.getBoundingClientRect().width ?? 300;
}

/** Sets a column width, kept inside limits that leave the reader usable. */
export function resizePane(which: "rail" | "list", px: number, persist: boolean) {
  const [min, max] = LIMITS[which];
  let w = Math.round(Math.min(max, Math.max(min, px)));
  if (which === "list") w = Math.min(w, Math.max(min, window.innerWidth - paneWidth("rail") - 380));
  layout.value = { ...layout.value, [which]: w };
  if (persist) saveJson(LAYOUT_KEY, layout.value);
}

export function persistLayout() {
  saveJson(LAYOUT_KEY, layout.value);
}

export function resetLayout(which?: "rail" | "list") {
  const next = { ...layout.value };
  if (which) delete next[which];
  layout.value = which ? next : {};
  saveJson(LAYOUT_KEY, layout.value);
}

// ---- S/MIME store ------------------------------------------------------------

function saveKeys(v: Record<string, OwnKey>) {
  ownKeys.value = v;
  saveJson(KEYS_KEY, v);
}

function saveCerts(v: StoredCert[]) {
  certStore.value = v;
  saveJson(CERTS_KEY, v);
}

export async function importKey(file: File, password: string) {
  const form = new FormData();
  form.append("file", file, file.name);
  form.append("password", password);
  const r = await request<{ sealed: string; cert: CertInfo; email_match: boolean; can_decrypt: boolean }>("/api/smime/import", {
    method: "POST",
    body: form,
  });
  const email = me.value!.email.toLowerCase();
  saveKeys({ ...ownKeys.value, [email]: { sealed: r.sealed, cert: r.cert, canDecrypt: r.can_decrypt } });
  return r;
}

export function removeKey() {
  const email = me.value?.email.toLowerCase();
  if (!email) return;
  const next = { ...ownKeys.value };
  delete next[email];
  saveKeys(next);
}

function markKeyInvalid() {
  const email = me.value?.email.toLowerCase();
  const k = email ? ownKeys.value[email] : null;
  if (email && k && !k.invalid) saveKeys({ ...ownKeys.value, [email]: { ...k, invalid: true } });
}

/** Tells the user early when the server can no longer open the stored key. */
export async function checkKey() {
  if (!ownKey.value || ownKey.value.invalid) return;
  try {
    const r = await get<{ key: string }>("/api/smime/status");
    if (r.key === "invalid") {
      markKeyInvalid();
      toast(t("keyInvalid"), true);
    }
  } catch {
    // checked again next time
  }
}

export function addCerts(list: CertInfo[], source: "auto" | "manual"): number {
  const cur = [...certStore.value];
  let added = 0;
  for (const c of list) {
    const i = cur.findIndex((x) => x.fingerprint === c.fingerprint);
    if (i >= 0) {
      cur[i] = source === "manual" ? { ...cur[i], ...c, source: "manual", pinned: true } : { ...cur[i], ...c };
      continue;
    }
    cur.push({ ...c, source, pinned: source === "manual", added: new Date().toISOString() });
    added++;
  }
  saveCerts(cur);
  return added;
}

export function setPinned(fingerprint: string, pinned: boolean) {
  saveCerts(certStore.value.map((c) => (c.fingerprint === fingerprint ? { ...c, pinned } : c)));
}

export function removeCert(fingerprint: string) {
  saveCerts(certStore.value.filter((c) => c.fingerprint !== fingerprint));
}

function bytesToB64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

export async function importCertFile(file: File) {
  if (file.size > 512 * 1024) throw new ApiError(400, "bad_request", t("errorGeneric"));
  const r = await post<{ certs: CertInfo[] }>("/api/smime/certs", { data: bytesToB64(await file.arrayBuffer()) });
  const n = addCerts(r.certs, "manual");
  toast(t("certsImported", n));
}

function saveFile(name: string, data: BlobPart, type: string) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

export function exportCerts() {
  const pem = certStore.value
    .map((c) => `# ${c.name} <${c.emails.join(", ")}>\n-----BEGIN CERTIFICATE-----\n${c.der.replace(/(.{64})/g, "$1\n").trim()}\n-----END CERTIFICATE-----\n`)
    .join("\n");
  saveFile("postern-certificates.pem", pem, "application/x-pem-file");
}

const expired = (c: CertInfo) => new Date(c.not_after).getTime() < Date.now();

export function isTrusted(c: CertInfo): boolean {
  return c.trust === "trusted" || certStore.value.some((x) => x.fingerprint === c.fingerprint && x.pinned);
}

/** The certificate to encrypt to for an address: trusted before untrusted, newest first. */
export function certFor(email: string): StoredCert | null {
  const e = email.toLowerCase();
  const usable = certStore.value.filter((c) => c.emails.includes(e) && c.can_encrypt && !expired(c));
  usable.sort((a, b) => Number(isTrusted(b)) - Number(isTrusted(a)) || b.not_after.localeCompare(a.not_after));
  return usable[0] ?? null;
}

/** Addresses found in what was typed into To, Cc or Bcc. */
export function emailsIn(text: string): string[] {
  const found = text.match(/[^\s<>,;"'()]+@[^\s<>,;"'()]+/g) || [];
  return [...new Set(found.map((x) => x.toLowerCase()))];
}

export const canSign = computed(() => !!ownKey.value && !ownKey.value.invalid);

// ---- notifications -----------------------------------------------------------

let audio: AudioContext | null = null;

/** Short synthesized sounds: no audio files, nothing fetched. */
export function playSound(kind: Sound) {
  if (kind === "off") return;
  try {
    audio ??= new AudioContext();
    if (audio.state === "suspended") void audio.resume();
    const ctx = audio;
    const t0 = ctx.currentTime + 0.02;
    const tone = (freq: number, start: number, dur: number, gain = 0.12, type: OscillatorType = "sine", to?: number) => {
      const o = ctx.createOscillator();
      const g = ctx.createGain();
      o.type = type;
      o.frequency.setValueAtTime(freq, t0 + start);
      if (to) o.frequency.exponentialRampToValueAtTime(to, t0 + start + dur);
      g.gain.setValueAtTime(0.0001, t0 + start);
      g.gain.exponentialRampToValueAtTime(gain, t0 + start + 0.012);
      g.gain.exponentialRampToValueAtTime(0.0001, t0 + start + dur);
      o.connect(g).connect(ctx.destination);
      o.start(t0 + start);
      o.stop(t0 + start + dur + 0.05);
    };
    if (kind === "chime") {
      tone(880, 0, 0.32);
      tone(1318.5, 0.13, 0.55);
    } else if (kind === "pop") {
      tone(900, 0, 0.14, 0.16, "triangle", 320);
    } else {
      tone(1046.5, 0, 1.3, 0.1);
      tone(2093, 0, 0.7, 0.035);
      tone(3136, 0, 0.35, 0.02);
    }
  } catch {
    // no audio here
  }
}

export function notifySupported(): boolean {
  return typeof Notification !== "undefined";
}

function showNotification(title: string, body: string, onClick?: () => void): boolean {
  try {
    const n = new Notification(title, { body, icon: "/favicon.svg", tag: `postern-${title}-${body}` });
    n.onclick = () => {
      window.focus();
      n.close();
      onClick?.();
    };
    return true;
  } catch {
    // Some mobile browsers allow notifications only from a service worker.
    return false;
  }
}

/** Turns notifications on; the browser asks for permission once. */
export async function enableNotifications(): Promise<boolean> {
  if (!notifySupported()) return false;
  const perm = Notification.permission === "default" ? await Notification.requestPermission() : Notification.permission;
  return perm === "granted";
}

export function testNotification() {
  if (!showNotification(brand.value, t("notifyTestBody"))) toast(t("notifyUnsupported"), true);
}

let inboxKnown: Set<string> | null = null;
let inboxLast = { total: -1, unread: -1 };

/** Looks for new unread mail in the inbox and announces it. The first look only learns what is there. */
async function watchInbox() {
  const inbox = byRole("inbox");
  if (!inbox) return;
  const same = inbox.total === inboxLast.total && inbox.unread <= inboxLast.unread;
  inboxLast = { total: inbox.total, unread: inbox.unread };
  if (inboxKnown && same) return;
  let list: Summary[];
  if (current.value === inbox.id && !query.value) {
    list = items.value.slice(0, 40);
  } else {
    try {
      list = (await get<{ items: Summary[] }>("/api/messages", { mailbox: inbox.id, offset: 0, limit: 20 })).items;
    } catch {
      return;
    }
  }
  if (!inboxKnown) {
    inboxKnown = new Set(list.map((m) => m.id));
    return;
  }
  const fresh = list.filter((m) => !m.seen && !inboxKnown!.has(m.id));
  list.forEach((m) => inboxKnown!.add(m.id));
  if (fresh.length) announce(fresh, inbox.id);
}

function announce(fresh: Summary[], box: string) {
  const p = prefs.value;
  playSound(p.sound);
  if (!p.notify || !notifySupported() || Notification.permission !== "granted") return;
  if (document.visibilityState === "visible" && document.hasFocus()) return;
  const open = (id: string) => async () => {
    if (current.value !== box) await selectMailbox(box);
    await openMessage(id);
  };
  if (fresh.length > 3) {
    showNotification(t("newMails", fresh.length), p.notifyPreview ? fresh.slice(0, 3).map((m) => who(m.from, "?")).join(", ") : "");
    return;
  }
  for (const m of fresh) {
    const sender = m.from[0]?.name || m.from[0]?.email || "";
    if (p.notifyPreview) showNotification(sender || t("newMail"), m.subject || t("noSubject"), open(m.id));
    else showNotification(t("newMail"), "", open(m.id));
  }
}

export const inboxUnread = computed(() => byRole("inbox")?.unread ?? 0);

export async function login(email: string, password: string) {
  // A sign-out still on its way would otherwise clear the new cookie.
  if (pendingLogout) await pendingLogout;
  pendingLogout = null;
  await post("/api/login", { email, password });
  notice.value = "";
  me.value = await get<Me>("/api/me");
  await enter();
}

async function enter() {
  inboxKnown = null;
  inboxLast = { total: -1, unread: -1 };
  await loadMailboxes();
  const inbox = byRole("inbox") || mailboxes.value.find((m) => m.selectable);
  if (inbox) await selectMailbox(inbox.id);
  void watchInbox();
  void checkKey();
}

let pendingLogout: Promise<unknown> | null = null;

export function logout() {
  // The screen changes at once; the server is told in the background.
  pendingLogout = fetch("/api/logout", {
    method: "POST",
    credentials: "same-origin",
    keepalive: true,
    headers: { "x-postern": "1", "content-type": "application/json" },
    body: "{}",
  }).catch(() => undefined);
  me.value = null;
  inboxKnown = null;
  mailboxes.value = [];
  items.value = [];
  openId.value = null;
  openView.value = null;
  draft.value = null;
  selected.value = new Set();
}

// ---- folders ---------------------------------------------------------------

const ROLE_ORDER = ["inbox", "drafts", "sent", "archive", "junk", "trash"];

export async function loadMailboxes() {
  const r = await get<{ mailboxes: Mailbox[] }>("/api/mailboxes");
  mailboxes.value = r.mailboxes;
}

export const specialBoxes = computed(() =>
  ROLE_ORDER.map((r) => mailboxes.value.find((m) => m.role === r)).filter((m): m is Mailbox => !!m),
);

/** Other folders as a flat list with depth, parents before children, sorted by name. */
export const otherBoxes = computed(() => {
  const all = mailboxes.value;
  const special = new Set(specialBoxes.value.map((m) => m.id));
  const ids = new Set(all.map((m) => m.id));
  const out: { box: Mailbox; depth: number }[] = [];
  const walk = (parent: string | null, depth: number) => {
    all
      .filter((m) => (m.parent && ids.has(m.parent) ? m.parent : null) === parent)
      .sort((a, b) => a.name.localeCompare(b.name))
      .forEach((m) => {
        if (!special.has(m.id)) out.push({ box: m, depth });
        walk(m.id, special.has(m.id) ? depth : depth + 1);
      });
  };
  walk(null, 0);
  return out;
});

export async function selectMailbox(id: string) {
  current.value = id;
  query.value = "";
  railOpen.value = false;
  closeMessage();
  await loadList();
}

export async function saveFolder(name: string, rename?: Mailbox) {
  if (rename) await post("/api/mailboxes/rename", { id: rename.id, name });
  else await post("/api/mailboxes/create", { name });
  await loadMailboxes();
  if (rename && current.value === rename.id) {
    const moved = mailboxes.value.find((m) => m.name === name && m.parent === rename.parent);
    if (moved) current.value = moved.id;
  }
}

export async function deleteFolder(box: Mailbox) {
  await post("/api/mailboxes/delete", { id: box.id });
  await loadMailboxes();
  if (current.value === box.id) {
    const inbox = byRole("inbox");
    if (inbox) await selectMailbox(inbox.id);
  }
}

// ---- list ------------------------------------------------------------------

let listToken = 0;

export async function loadList(more = false) {
  const mailbox = current.value;
  if (!mailbox) return;
  const token = ++listToken;
  listLoading.value = true;
  try {
    const offset = more ? items.value.length : 0;
    const page = await get<{ total: number; items: Summary[] }>("/api/messages", {
      mailbox,
      offset,
      limit: 50,
      q: query.value || undefined,
    });
    if (token !== listToken) return;
    total.value = page.total;
    if (more) {
      const have = new Set(items.value.map((m) => m.id));
      items.value = [...items.value, ...page.items.filter((m) => !have.has(m.id))];
    } else {
      items.value = page.items;
      selected.value = new Set();
    }
  } catch (e) {
    if (token === listToken) fail(e);
  } finally {
    if (token === listToken) listLoading.value = false;
  }
}

/** Quiet refresh: new mail appears at the top without disturbing what is open. */
export async function refresh(quiet = false) {
  if (!me.value) return;
  try {
    await loadMailboxes();
    if (!current.value) {
      await watchInbox();
      return;
    }
    const token = listToken;
    const page = await get<{ total: number; items: Summary[] }>("/api/messages", {
      mailbox: current.value,
      offset: 0,
      limit: Math.max(50, Math.min(items.value.length, 100)),
      q: query.value || undefined,
    });
    if (token !== listToken) return;
    const fresh = new Map(page.items.map((m) => [m.id, m]));
    const tail = items.value.slice(page.items.length).filter((m) => !fresh.has(m.id));
    items.value = [...page.items, ...tail];
    total.value = page.total;
    await watchInbox();
  } catch (e) {
    if (!quiet) fail(e);
  }
}

export async function search(q: string) {
  query.value = q.trim();
  closeMessage();
  await loadList();
}

export function toggleSelect(id: string) {
  const s = new Set(selected.value);
  if (s.has(id)) s.delete(id);
  else s.add(id);
  selected.value = s;
}

// ---- reading ---------------------------------------------------------------

let openToken = 0;

export async function openMessage(id: string) {
  const token = ++openToken;
  openId.value = id;
  openView.value = null;
  showImages.value = false;
  openLoading.value = true;
  const mailbox = current.value;
  try {
    const v = await get<MessageView>("/api/message", { mailbox, id });
    if (token !== openToken) return;
    openView.value = v;
    showImages.value = autoImages(v);
    if (v.key_invalid) markKeyInvalid();
    const sig = v.security?.signed;
    // Certificates from verified signatures go into the address book by themselves.
    if (sig?.status === "valid" && sig.signer && sig.signer_matches_from && sig.trust === "trusted") addCerts([sig.signer], "auto");
    const row = items.value.find((m) => m.id === id);
    if (row && !row.seen) void setFlag([id], "seen", true);
  } catch (e) {
    if (token === openToken) {
      openId.value = null;
      fail(e);
    }
  } finally {
    if (token === openToken) openLoading.value = false;
  }
}

/** Whether remote images load without asking, by the user's settings. */
function autoImages(v: MessageView): boolean {
  if (!v.remote_images || !v.can_load_images) return false;
  // Decrypted mail never loads remote content by itself (EFAIL).
  if (v.security?.encrypted) return false;
  const p = prefs.value;
  if (p.images === "never") return false;
  if (p.images === "always") return true;
  const from = v.from[0]?.email.toLowerCase();
  return !!from && p.imageSenders.includes(from);
}

export function trustSender(email: string) {
  const list = [...new Set([...prefs.value.imageSenders, email.toLowerCase()])];
  setPrefs({ ...prefs.value, imageSenders: list });
  showImages.value = true;
}

/** Downloads an attachment with the key attached, for encrypted messages. */
export async function downloadPart(mailbox: string, id: string, a: AttachmentInfo) {
  try {
    const path = messageUrl("part", mailbox, id, { part: a.part });
    const resp = await fetch(path, { credentials: "same-origin", headers: keyHeader(path) });
    if (!resp.ok) throw new ApiError(resp.status, "error", t("errorGeneric"));
    saveFile(a.name, await resp.blob(), "application/octet-stream");
  } catch (e) {
    fail(e);
  }
}

export function closeMessage() {
  openToken++;
  openId.value = null;
  openView.value = null;
  openLoading.value = false;
}

export function step(delta: number) {
  const list = items.value;
  if (!list.length) return;
  const i = list.findIndex((m) => m.id === openId.value);
  const next = list[Math.max(0, Math.min(list.length - 1, i + delta))];
  if (next && next.id !== openId.value) void openMessage(next.id);
}

// ---- actions on messages ---------------------------------------------------

function patch(ids: string[], change: Partial<Summary>) {
  const set = new Set(ids);
  items.value = items.value.map((m) => (set.has(m.id) ? { ...m, ...change } : m));
}

export async function setFlag(ids: string[], flag: "seen" | "flagged", on: boolean) {
  if (!ids.length) return;
  const before = items.value;
  patch(ids, { [flag]: on } as Partial<Summary>);
  if (flag === "seen") {
    const changed = before.filter((m) => ids.includes(m.id) && m.seen !== on).length;
    mailboxes.value = mailboxes.value.map((b) =>
      b.id === current.value ? { ...b, unread: Math.max(0, b.unread + (on ? -changed : changed)) } : b,
    );
  }
  try {
    await post("/api/flags", { mailbox: current.value, ids, flag, on });
  } catch (e) {
    items.value = before;
    fail(e);
    void loadMailboxes();
  }
}

function removeLocally(ids: string[]) {
  const set = new Set(ids);
  const list = items.value;
  // Keep the reader on a neighbour of what was removed.
  if (openId.value && set.has(openId.value)) {
    const i = list.findIndex((m) => m.id === openId.value);
    const next = list.slice(i + 1).find((m) => !set.has(m.id)) || [...list.slice(0, i)].reverse().find((m) => !set.has(m.id));
    if (next && matchMedia("(min-width: 900px)").matches) void openMessage(next.id);
    else closeMessage();
  }
  items.value = list.filter((m) => !set.has(m.id));
  total.value = Math.max(0, total.value - ids.length);
  selected.value = new Set();
}

export async function moveTo(ids: string[], dest: Mailbox) {
  if (!ids.length || dest.id === current.value) return;
  const before = { items: items.value, total: total.value };
  const mailbox = current.value;
  removeLocally(ids);
  try {
    await post("/api/move", { mailbox, ids, dest: dest.id });
    toast(t("movedToast", displayName(dest)));
    void loadMailboxes();
  } catch (e) {
    items.value = before.items;
    total.value = before.total;
    fail(e);
  }
}

export async function remove(ids: string[]) {
  if (!ids.length) return;
  const before = { items: items.value, total: total.value };
  const mailbox = current.value;
  const trash = byRole("trash");
  removeLocally(ids);
  try {
    const r = await post<{ permanent: boolean }>("/api/delete", { mailbox, ids, trash: trash?.id ?? null });
    toast(r.permanent ? t("deletedForever") : t("deletedToast"));
    void loadMailboxes();
  } catch (e) {
    items.value = before.items;
    total.value = before.total;
    fail(e);
  }
}

export function archive(ids: string[]) {
  const box = byRole("archive");
  if (box) void moveTo(ids, box);
}

export async function viewSource(id: string) {
  try {
    const resp = await fetch(messageUrl("raw", current.value, id, { view: 1 }), { credentials: "same-origin" });
    if (!resp.ok) throw new ApiError(resp.status, "error", t("errorGeneric"));
    const text = await resp.text();
    dialog.value = { kind: "source", text: text.length > 400_000 ? text.slice(0, 400_000) + "\n…" : text };
  } catch (e) {
    fail(e);
  }
}

// ---- composing -------------------------------------------------------------

export function displayName(box: Mailbox): string {
  const key = box.role as "inbox" | "drafts" | "sent" | "archive" | "junk" | "trash" | null;
  return key ? t(key) : box.name;
}

export function fmtAddr(a: Addr): string {
  if (!a.name) return a.email;
  const needsQuotes = /[",;<>@()]/.test(a.name);
  return `${needsQuotes ? `"${a.name.replace(/["\\]/g, "")}"` : a.name} <${a.email}>`;
}

export function fmtDateLong(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function signatureBlock(): string {
  const s = prefs.value.signature.trim();
  return s ? `\n\n-- \n${s}` : "";
}

function quote(text: string): string {
  return text
    .replace(/\r\n/g, "\n")
    .trimEnd()
    .split("\n")
    .map((l) => (l.startsWith(">") ? `>${l}` : `> ${l}`))
    .join("\n");
}

const prefixed = (prefix: string, subject: string) =>
  new RegExp(`^${prefix}:`, "i").test(subject.trim()) ? subject : `${prefix}: ${subject}`;

export function newMessage(to = "") {
  if (draft.value) {
    composerMin.value = false;
    return;
  }
  draft.value = { to, cc: "", bcc: "", subject: "", text: signatureBlock(), files: [], showCc: false, sign: signDefault(), encrypt: false };
  composerMin.value = false;
}

function signDefault(): boolean {
  return canSign.value && prefs.value.signDefault;
}

/** Replies to encrypted mail start encrypted, to signed mail signed. */
function protectLike(v: MessageView): { sign: boolean; encrypt: boolean } {
  const wasEncrypted = v.security?.encrypted?.status === "decrypted";
  return {
    sign: signDefault() || (canSign.value && !!v.security?.signed),
    encrypt: canSign.value && wasEncrypted,
  };
}

export function replyTo(all: boolean) {
  const v = openView.value;
  const id = openId.value;
  if (!v || !id || !me.value) return;
  const mine = me.value.email.toLowerCase();
  const target = v.reply_to.length ? v.reply_to : v.from;
  const others = all
    ? [...v.to, ...v.cc].filter((a) => a.email.toLowerCase() !== mine && !target.some((x) => x.email.toLowerCase() === a.email.toLowerCase()))
    : [];
  const who = v.from[0] ? v.from[0].name || v.from[0].email : "";
  draft.value = {
    to: target.map(fmtAddr).join(", "),
    cc: others.map(fmtAddr).join(", "),
    bcc: "",
    subject: prefixed("Re", v.subject),
    text: `${signatureBlock()}\n\n${t("wroteOn", fmtDateLong(v.date), who)}\n${quote(v.text)}\n`,
    files: [],
    showCc: others.length > 0,
    inReplyTo: v.message_id,
    references: v.message_id ? [...v.references.filter((r) => r !== v.message_id), v.message_id] : v.references,
    answered: { mailbox: current.value, id },
    ...protectLike(v),
  };
  composerMin.value = false;
}

export function forwardOpen() {
  const v = openView.value;
  const id = openId.value;
  if (!v || !id) return;
  const keep = v.attachments.filter((a) => !a.inline);
  const head = [
    t("forwarded"),
    `${t("from")}: ${v.from.map(fmtAddr).join(", ")}`,
    `${t("date")}: ${fmtDateLong(v.date)}`,
    `${t("subject")}: ${v.subject}`,
    `${t("to")}: ${v.to.map(fmtAddr).join(", ")}`,
  ].join("\n");
  draft.value = {
    to: "",
    cc: "",
    bcc: "",
    subject: prefixed("Fwd", v.subject),
    text: `${signatureBlock()}\n\n${head}\n\n${v.text.replace(/\r\n/g, "\n").trimEnd()}\n`,
    files: [],
    showCc: false,
    forward: keep.length ? { mailbox: current.value, id, parts: keep.map((a) => a.part), names: keep.map((a) => a.name) } : undefined,
    ...protectLike(v),
  };
  composerMin.value = false;
}

export function editDraft() {
  const v = openView.value;
  const id = openId.value;
  if (!v || !id) return;
  const keep = v.attachments.filter((a) => !a.inline);
  draft.value = {
    to: v.to.map(fmtAddr).join(", "),
    cc: v.cc.map(fmtAddr).join(", "),
    bcc: v.bcc.map(fmtAddr).join(", "),
    subject: v.subject,
    text: v.text.replace(/\r\n/g, "\n"),
    files: [],
    showCc: v.cc.length + v.bcc.length > 0,
    replaceDraft: { mailbox: current.value, id },
    forward: keep.length ? { mailbox: current.value, id, parts: keep.map((a) => a.part), names: keep.map((a) => a.name) } : undefined,
    sign: signDefault(),
    encrypt: canSign.value && v.security?.encrypted?.status === "decrypted",
  };
  composerMin.value = false;
}

export async function submitDraft(asDraft: boolean): Promise<boolean> {
  const d = draft.value;
  if (!d || !me.value || sending.value) return false;
  if (!asDraft && !(d.to + d.cc + d.bcc).trim()) {
    toast(t("needRecipient"), true);
    return false;
  }
  const size = d.files.reduce((n, f) => n + f.size, 0);
  if (size > me.value.max_upload_mb * 1024 * 1024) {
    toast(t("tooBig", me.value.max_upload_mb), true);
    return false;
  }
  if ((d.sign || d.encrypt) && !canSign.value) {
    toast(ownKey.value?.invalid ? t("keyInvalid") : t("needKey"), true);
    return false;
  }
  const recipients = emailsIn(`${d.to},${d.cc}`);
  if (d.encrypt && !asDraft) {
    const missing = recipients.filter((e) => !certFor(e));
    if (missing.length) {
      toast(t("missingCerts", missing.join(", ")), true);
      return false;
    }
    if (d.bcc.trim()) {
      toast(t("bccEncrypt"), true);
      return false;
    }
  }
  const meta = {
    from_name: prefs.value.name.trim() || null,
    to: d.to,
    cc: d.cc,
    bcc: d.bcc,
    subject: d.subject,
    text: d.text,
    in_reply_to: d.inReplyTo ?? null,
    references: d.references ?? [],
    draft: asDraft,
    sent_mailbox: byRole("sent")?.id ?? null,
    drafts_mailbox: byRole("drafts")?.id ?? null,
    replace_draft: d.replaceDraft ?? null,
    answered: asDraft ? null : (d.answered ?? null),
    forward: d.forward ? { mailbox: d.forward.mailbox, id: d.forward.id, parts: d.forward.parts } : null,
    smime: {
      sign: d.sign && !asDraft,
      encrypt: d.encrypt,
      certs: d.encrypt ? recipients.map((e) => certFor(e)?.der).filter((x): x is string => !!x) : [],
    },
  };
  const form = new FormData();
  form.append("meta", JSON.stringify(meta));
  for (const f of d.files) form.append("file", f, f.name);
  sending.value = true;
  try {
    await request("/api/send", { method: "POST", body: form });
    const answered = d.answered;
    draft.value = null;
    toast(asDraft ? t("draftSaved") : t("sentToast"));
    if (!asDraft && answered && answered.mailbox === current.value) patch([answered.id], { answered: true });
    void refresh(true);
    return true;
  } catch (e) {
    fail(e);
    return false;
  } finally {
    sending.value = false;
  }
}

export function discardDraft() {
  draft.value = null;
}

// ---- formatting helpers ----------------------------------------------------

export function fmtDateShort(iso: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  const now = new Date();
  if (d.toDateString() === now.toDateString()) {
    return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }
  if (d.getFullYear() === now.getFullYear()) {
    return d.toLocaleDateString(undefined, { day: "numeric", month: "short" });
  }
  return d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

export function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function who(list: Addr[], fallback = ""): string {
  if (!list.length) return fallback;
  const mine = me.value?.email.toLowerCase();
  return list
    .map((a) => (a.email.toLowerCase() === mine ? t("me") : a.name || a.email.split("@")[0]))
    .join(", ");
}
