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
}
export interface Me {
  email: string;
  server: string;
  protocol: string;
  max_upload_mb: number;
  brand: string;
  version: string;
}
export interface Prefs {
  name: string;
  signature: string;
  theme: "system" | "light" | "dark";
  density: "comfortable" | "compact";
  language: "auto" | "en" | "de";
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

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let resp: Response;
  try {
    resp = await fetch(path, {
      credentials: "same-origin",
      ...init,
      headers: { "x-postern": "1", ...(init?.headers || {}) },
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
const defaultPrefs: Prefs = { name: "", signature: "", theme: "system", density: "comfortable", language: "auto" };

function loadPrefs(): Prefs {
  try {
    return { ...defaultPrefs, ...JSON.parse(localStorage.getItem(PREFS_KEY) || "{}") };
  } catch {
    return defaultPrefs;
  }
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
export const dialog = signal<null | { kind: "settings" } | { kind: "folder"; rename?: Mailbox } | { kind: "deleteFolder"; box: Mailbox } | { kind: "source"; text: string }>(null);
export const railOpen = signal(false);
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
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  document.documentElement.dataset.density = p.density;
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

export async function login(email: string, password: string) {
  await post("/api/login", { email, password });
  notice.value = "";
  me.value = await get<Me>("/api/me");
  await enter();
}

async function enter() {
  await loadMailboxes();
  const inbox = byRole("inbox") || mailboxes.value.find((m) => m.selectable);
  if (inbox) await selectMailbox(inbox.id);
}

export async function logout() {
  try {
    await post("/api/logout", {});
  } catch {
    // signed out locally either way
  }
  me.value = null;
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
    if (!current.value) return;
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
  draft.value = { to, cc: "", bcc: "", subject: "", text: signatureBlock(), files: [], showCc: false };
  composerMin.value = false;
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
