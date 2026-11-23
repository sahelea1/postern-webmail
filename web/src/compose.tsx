// The composer and the dialogs.

import { useEffect, useRef, useState } from "preact/hooks";
import { t } from "./i18n";
import * as S from "./state";
import { Dialog, Icon, IconButton, Switch } from "./ui";

export function Composer() {
  const d = S.draft.value;
  const [full, setFull] = useState(false);
  const [dragging, setDragging] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const bodyRef = useRef<HTMLTextAreaElement>(null);
  const toRef = useRef<HTMLInputElement>(null);
  const isNew = useRef(true);

  useEffect(() => {
    if (!d || S.composerMin.value || !isNew.current) return;
    isNew.current = false;
    // Replies start in the body with the cursor above the quote; new messages start at "To".
    if (d.to) {
      const el = bodyRef.current;
      if (el) {
        el.focus();
        el.setSelectionRange(0, 0);
        el.scrollTop = 0;
      }
    } else {
      toRef.current?.focus();
    }
  }, [d, S.composerMin.value]);
  useEffect(() => {
    if (!d) isNew.current = true;
  }, [d]);

  if (!d) return null;
  const set = (change: Partial<S.Draft>) => (S.draft.value = { ...d, ...change });
  const addFiles = (list: FileList | null) => {
    if (list?.length) set({ files: [...d.files, ...Array.from(list)] });
  };
  const title = d.subject.trim() || t("compose");

  if (S.composerMin.value) {
    return (
      <div class="composer min">
        <button type="button" class="composer-title" onClick={() => (S.composerMin.value = false)}>
          <Icon name="pencil" size={15} />
          <span>{title}</span>
        </button>
        <IconButton icon="expand" label={t("expand")} onClick={() => (S.composerMin.value = false)} />
        <IconButton icon="x" label={t("discard")} onClick={() => S.discardDraft()} />
      </div>
    );
  }

  return (
    <form
      class={`composer ${full ? "full" : ""} ${dragging ? "dragging" : ""}`}
      aria-label={t("compose")}
      onSubmit={(e) => {
        e.preventDefault();
        void S.submitDraft(false);
      }}
      onKeyDown={(e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
          e.preventDefault();
          void S.submitDraft(false);
        }
      }}
      onDragOver={(e) => {
        if (e.dataTransfer?.types.includes("Files")) {
          e.preventDefault();
          setDragging(true);
        }
      }}
      onDragLeave={(e) => {
        if (e.currentTarget === e.target) setDragging(false);
      }}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        addFiles(e.dataTransfer?.files || null);
      }}
    >
      <header class="composer-head">
        <span class="composer-title">{title}</span>
        <IconButton icon="minus" label={t("minimize")} onClick={() => (S.composerMin.value = true)} />
        <IconButton icon="expand" label={t("expand")} class="hide-narrow" active={full} onClick={() => setFull(!full)} />
      </header>
      <div class="field">
        <label for="c-to">{t("to")}</label>
        <input ref={toRef} id="c-to" type="text" autocomplete="off" spellcheck={false} value={d.to} onInput={(e) => set({ to: (e.target as HTMLInputElement).value })} />
        {!d.showCc && (
          <button type="button" class="link" onClick={() => set({ showCc: true })}>
            {t("addCcBcc")}
          </button>
        )}
      </div>
      {d.showCc && (
        <>
          <div class="field">
            <label for="c-cc">{t("cc")}</label>
            <input id="c-cc" type="text" autocomplete="off" spellcheck={false} value={d.cc} onInput={(e) => set({ cc: (e.target as HTMLInputElement).value })} />
          </div>
          <div class="field">
            <label for="c-bcc">{t("bcc")}</label>
            <input id="c-bcc" type="text" autocomplete="off" spellcheck={false} value={d.bcc} onInput={(e) => set({ bcc: (e.target as HTMLInputElement).value })} />
          </div>
        </>
      )}
      <div class="field">
        <label for="c-subject">{t("subject")}</label>
        <input id="c-subject" type="text" autocomplete="off" value={d.subject} onInput={(e) => set({ subject: (e.target as HTMLInputElement).value })} />
      </div>
      <textarea ref={bodyRef} class="composer-body" aria-label={t("writeHere")} placeholder={t("writeHere")} value={d.text} onInput={(e) => set({ text: (e.target as HTMLTextAreaElement).value })} />
      {(d.files.length > 0 || d.forward) && (
        <div class="composer-files">
          {d.forward?.names.map((name, i) => (
            <span key={`f${i}`} class="filechip">
              <Icon name="clip" size={13} />
              <span>{name}</span>
              <button
                type="button"
                aria-label={t("discard")}
                onClick={() => {
                  const f = d.forward!;
                  const parts = f.parts.filter((_, j) => j !== i);
                  const names = f.names.filter((_, j) => j !== i);
                  set({ forward: parts.length ? { ...f, parts, names } : undefined });
                }}
              >
                <Icon name="x" size={12} />
              </button>
            </span>
          ))}
          {d.files.map((f, i) => (
            <span key={`u${i}`} class="filechip">
              <Icon name="clip" size={13} />
              <span>{f.name}</span>
              <small>{S.fmtSize(f.size)}</small>
              <button type="button" aria-label={t("discard")} onClick={() => set({ files: d.files.filter((_, j) => j !== i) })}>
                <Icon name="x" size={12} />
              </button>
            </span>
          ))}
        </div>
      )}
      <ProtectionNote d={d} />
      <footer class="composer-foot">
        <button type="submit" class="primary" disabled={S.sending.value}>
          <Icon name="sent" size={15} />
          {S.sending.value ? t("sending") : t("send")}
        </button>
        <IconButton icon="clip" label={t("attach")} onClick={() => fileInput.current?.click()} />
        <button
          type="button"
          class={`toggle ${d.sign ? "on" : ""}`}
          aria-pressed={d.sign}
          disabled={!S.canSign.value}
          title={S.canSign.value ? t("sign") : t("needKey")}
          onClick={() => set({ sign: !d.sign })}
        >
          <Icon name="seal" size={15} />
          <span class="btn-label">{t("sign")}</span>
        </button>
        <button
          type="button"
          class={`toggle ${d.encrypt ? "on" : ""}`}
          aria-pressed={d.encrypt}
          disabled={!S.canSign.value}
          title={S.canSign.value ? t("encrypt") : t("needKey")}
          onClick={() => set({ encrypt: !d.encrypt })}
        >
          <Icon name={d.encrypt ? "lock" : "unlock"} size={15} />
          <span class="btn-label">{t("encrypt")}</span>
        </button>
        <input
          ref={fileInput}
          type="file"
          multiple
          hidden
          onChange={(e) => {
            const el = e.target as HTMLInputElement;
            addFiles(el.files);
            el.value = "";
          }}
        />
        <span class="grow" />
        {S.byRole("drafts") && (
          <button type="button" class="ghost" disabled={S.sending.value} onClick={() => void S.submitDraft(true)}>
            {t("saveDraft")}
          </button>
        )}
        <IconButton icon="trash" label={t("discard")} onClick={() => S.discardDraft()} />
      </footer>
      {dragging && <div class="dropzone">{t("dropFiles")}</div>}
    </form>
  );
}

/** Says before sending what encryption cannot do for these recipients. */
function ProtectionNote({ d }: { d: S.Draft }) {
  if (!d.encrypt) return null;
  const rec = S.emailsIn(`${d.to},${d.cc}`);
  const missing = rec.filter((e) => !S.certFor(e));
  const untrusted = rec.filter((e) => {
    const c = S.certFor(e);
    return c && !S.isTrusted(c);
  });
  const lines: string[] = [];
  if (missing.length) lines.push(t("missingCerts", missing.join(", ")));
  if (untrusted.length) lines.push(t("untrustedCerts", untrusted.join(", ")));
  if (d.bcc.trim()) lines.push(t("bccEncrypt"));
  if (!lines.length) return null;
  return (
    <div class={`composer-note ${missing.length || d.bcc.trim() ? "bad" : ""}`} role="status">
      <Icon name="alert" size={15} />
      <span>{lines.join(" · ")}</span>
      {missing.length > 0 && (
        <button type="button" class="link" onClick={() => (S.dialog.value = { kind: "settings", tab: "security" })}>
          {t("importCert")}
        </button>
      )}
    </div>
  );
}

function FolderDialog({ rename }: { rename?: S.Mailbox }) {
  const [name, setName] = useState(rename?.name || "");
  const [busy, setBusy] = useState(false);
  const close = () => (S.dialog.value = null);
  return (
    <Dialog title={rename ? t("rename") : t("newFolder")} onClose={close}>
      <form
        class="dialog-body"
        onSubmit={async (e) => {
          e.preventDefault();
          if (!name.trim() || busy) return;
          setBusy(true);
          try {
            await S.saveFolder(name.trim(), rename);
            close();
          } catch (err) {
            S.fail(err);
          } finally {
            setBusy(false);
          }
        }}
      >
        <label class="stack">
          <span>{t("folderName")}</span>
          <input type="text" maxLength={100} value={name} onInput={(e) => setName((e.target as HTMLInputElement).value)} />
        </label>
        <div class="dialog-actions">
          <button type="button" class="ghost" onClick={close}>
            {t("cancel")}
          </button>
          <button type="submit" class="primary" disabled={!name.trim() || busy}>
            {rename ? t("save") : t("create")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function DeleteFolderDialog({ box }: { box: S.Mailbox }) {
  const [busy, setBusy] = useState(false);
  const close = () => (S.dialog.value = null);
  return (
    <Dialog title={t("delete")} onClose={close}>
      <div class="dialog-body">
        <p>{t("deleteFolderQ", box.name)}</p>
        <div class="dialog-actions">
          <button type="button" class="ghost" onClick={close}>
            {t("cancel")}
          </button>
          <button
            type="button"
            class="primary danger"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await S.deleteFolder(box);
                close();
              } catch (err) {
                S.fail(err);
              } finally {
                setBusy(false);
              }
            }}
          >
            {t("delete")}
          </button>
        </div>
      </div>
    </Dialog>
  );
}

type Tab = "general" | "appearance" | "privacy" | "notifications" | "security" | "shortcuts";

const TABS: { id: Tab; icon: string; label: () => string }[] = [
  { id: "general", icon: "user", label: () => t("tabGeneral") },
  { id: "appearance", icon: "droplet", label: () => t("tabAppearance") },
  { id: "privacy", icon: "eyeOff", label: () => t("tabPrivacy") },
  { id: "notifications", icon: "bell", label: () => t("tabNotifications") },
  { id: "security", icon: "key", label: () => t("tabSecurity") },
  { id: "shortcuts", icon: "keyboard", label: () => t("shortcuts") },
];

function usePrefs() {
  const p = S.prefs.value;
  const pick = <K extends keyof S.Prefs>(k: K, v: S.Prefs[K]) => S.setPrefs({ ...S.prefs.value, [k]: v });
  return { p, pick };
}

function GeneralTab() {
  const me = S.me.value!;
  const { p, pick } = usePrefs();
  return (
    <>
      <label class="stack">
        <span>{t("yourName")}</span>
        <input type="text" maxLength={100} value={p.name} onInput={(e) => pick("name", (e.target as HTMLInputElement).value)} />
        <small>{t("yourNameHint")}</small>
      </label>
      <label class="stack">
        <span>{t("signature")}</span>
        <textarea rows={3} maxLength={2000} value={p.signature} onInput={(e) => pick("signature", (e.target as HTMLTextAreaElement).value)} />
      </label>
      <label class="stack">
        <span>{t("language")}</span>
        <select value={p.language} onChange={(e) => pick("language", (e.target as HTMLSelectElement).value as S.Prefs["language"])}>
          <option value="auto">{t("langAuto")}</option>
          <option value="en">English</option>
          <option value="de">Deutsch</option>
        </select>
      </label>
      <small class="muted">{t("storedHere")}</small>
      <h3>{t("account")}</h3>
      <p class="muted">{t("signedInAs", me.email, me.server, me.protocol.toUpperCase())}</p>
      <p class="muted">{t("version", me.version)}</p>
    </>
  );
}

function AppearanceTab() {
  const { p, pick } = usePrefs();
  const names: Record<S.Palette, () => string> = {
    indigo: () => t("paletteIndigo"),
    ocean: () => t("paletteOcean"),
    forest: () => t("paletteForest"),
    rose: () => t("paletteRose"),
    amber: () => t("paletteAmber"),
    graphite: () => t("paletteGraphite"),
    nord: () => t("paletteNord"),
    paper: () => t("palettePaper"),
  };
  return (
    <>
      <div class="stack">
        <span>{t("mode")}</span>
        <div class="segmented" role="radiogroup" aria-label={t("mode")}>
          {(["system", "light", "dark"] as const).map((m) => (
            <button type="button" role="radio" aria-checked={p.theme === m} class={p.theme === m ? "on" : ""} onClick={() => pick("theme", m)}>
              {m === "system" ? t("themeSystem") : m === "light" ? t("themeLight") : t("themeDark")}
            </button>
          ))}
        </div>
      </div>
      <div class="stack">
        <span>{t("colorTheme")}</span>
        <div class="swatches" role="radiogroup" aria-label={t("colorTheme")}>
          {S.PALETTES.map((x) => (
            <button type="button" role="radio" aria-checked={p.palette === x.id} class={`swatch ${p.palette === x.id ? "on" : ""}`} onClick={() => pick("palette", x.id)}>
              <span class="swatch-dot" style={{ background: x.swatch }} />
              <span>{names[x.id]()}</span>
            </button>
          ))}
        </div>
      </div>
      <div class="stack">
        <span>{t("density")}</span>
        <div class="segmented" role="radiogroup" aria-label={t("density")}>
          {(["comfortable", "compact"] as const).map((d) => (
            <button type="button" role="radio" aria-checked={p.density === d} class={p.density === d ? "on" : ""} onClick={() => pick("density", d)}>
              {d === "comfortable" ? t("comfortable") : t("compact")}
            </button>
          ))}
        </div>
      </div>
      {(S.layout.value.rail || S.layout.value.list) && (
        <div>
          <button type="button" class="ghost" onClick={() => S.resetLayout()}>
            {t("resetLayout")}
          </button>
        </div>
      )}
    </>
  );
}

function PrivacyTab() {
  const { p, pick } = usePrefs();
  return (
    <>
      <div class="stack">
        <span>{t("remoteImages")}</span>
        <div class="segmented" role="radiogroup" aria-label={t("remoteImages")}>
          {(["ask", "always", "never"] as const).map((m) => (
            <button type="button" role="radio" aria-checked={p.images === m} class={p.images === m ? "on" : ""} onClick={() => pick("images", m)}>
              {m === "ask" ? t("imagesAsk") : m === "always" ? t("imagesAlways") : t("imagesNever")}
            </button>
          ))}
        </div>
        <small>{t("remoteImagesHint")}</small>
      </div>
      <Switch label={t("preferText")} checked={p.preferText} onChange={(on) => pick("preferText", on)} />
      {p.images === "ask" && (
        <div class="stack">
          <span>{t("trustedSenders")}</span>
          {p.imageSenders.length === 0 ? (
            <small>{t("noTrustedSenders")}</small>
          ) : (
            <ul class="plainlist">
              {p.imageSenders.map((e) => (
                <li>
                  <span>{e}</span>
                  <button type="button" class="link" onClick={() => pick("imageSenders", p.imageSenders.filter((x) => x !== e))}>
                    {t("remove")}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </>
  );
}

function NotificationsTab() {
  const { p, pick } = usePrefs();
  const supported = S.notifySupported();
  const denied = supported && Notification.permission === "denied";
  return (
    <>
      <Switch
        label={t("notifyNew")}
        hint={!supported ? t("notifyUnsupported") : denied ? t("notifyDenied") : t("notifyHint")}
        checked={p.notify && supported && !denied}
        disabled={!supported || denied}
        onChange={async (on) => {
          if (!on) return pick("notify", false);
          const ok = await S.enableNotifications();
          pick("notify", ok);
          if (!ok) S.toast(t("notifyDenied"), true);
        }}
      />
      <Switch label={t("notifyPreview")} checked={p.notifyPreview} disabled={!p.notify} onChange={(on) => pick("notifyPreview", on)} />
      {p.notify && (
        <div>
          <button type="button" class="ghost" onClick={() => S.testNotification()}>
            <Icon name="bell" size={15} />
            {t("testNotification")}
          </button>
        </div>
      )}
      <div class="stack">
        <span>{t("sound")}</span>
        <div class="row-controls">
          <select value={p.sound} onChange={(e) => {
            const v = (e.target as HTMLSelectElement).value as S.Sound;
            pick("sound", v);
            S.playSound(v);
          }}>
            <option value="off">{t("soundOff")}</option>
            <option value="chime">{t("soundChime")}</option>
            <option value="pop">{t("soundPop")}</option>
            <option value="bell">{t("soundBell")}</option>
          </select>
          <button type="button" class="ghost" disabled={p.sound === "off"} onClick={() => S.playSound(p.sound)}>
            <Icon name="volume" size={15} />
            {t("testSound")}
          </button>
        </div>
      </div>
    </>
  );
}

function TrustBadge({ c }: { c: S.CertInfo | S.StoredCert }) {
  const pinned = "pinned" in c && c.pinned;
  const expired = new Date(c.not_after).getTime() < Date.now();
  const [tone, text] = expired
    ? ["warn", t("trustExpired")]
    : c.trust === "trusted"
      ? ["ok", t("trustCa")]
      : pinned
        ? ["ok", t("trustYou")]
        : ["warn", t("trustNone")];
  return <span class={`badge-trust ${tone}`}>{text}</span>;
}

function KeyImport() {
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <form
      class="key-import"
      onSubmit={async (e) => {
        e.preventDefault();
        if (!file || busy) return;
        setBusy(true);
        try {
          const r = await S.importKey(file, password);
          setPassword("");
          setFile(null);
          S.toast(t("keyImported"));
          if (!r.email_match) S.toast(t("keyMismatch", r.cert.emails.join(", ") || r.cert.name), true);
        } catch (err) {
          S.fail(err);
        } finally {
          setBusy(false);
        }
      }}
    >
      <label class="stack">
        <span>{t("keyFile")}</span>
        <input type="file" accept=".p12,.pfx,application/x-pkcs12" onChange={(e) => setFile((e.target as HTMLInputElement).files?.[0] ?? null)} />
      </label>
      <label class="stack">
        <span>{t("keyPassword")}</span>
        <input type="password" autocomplete="off" value={password} onInput={(e) => setPassword((e.target as HTMLInputElement).value)} />
      </label>
      <div>
        <button type="submit" class="primary" disabled={!file || busy}>
          <Icon name="upload" size={15} />
          {busy ? t("importing") : t("importKey")}
        </button>
      </div>
    </form>
  );
}

function SecurityTab() {
  const { p, pick } = usePrefs();
  const k = S.ownKey.value;
  const me = S.me.value!;
  const certInput = useRef<HTMLInputElement>(null);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const certs = [...S.certStore.value].sort((a, b) => (a.emails[0] || a.name).localeCompare(b.emails[0] || b.name));
  return (
    <>
      <p class="muted">{t("smimeIntro")}</p>
      <h3>{t("yourKey")}</h3>
      {k ? (
        <div class="certcard">
          <div class="certcard-head">
            <Icon name="key" size={18} />
            <strong>{k.cert.name}</strong>
            <TrustBadge c={k.cert} />
          </div>
          <div class="muted small">
            {k.cert.emails.join(", ")} · {t("issuedBy", k.cert.issuer)} · {t("validUntil", S.fmtDateLong(k.cert.not_after))} · {k.cert.key}
          </div>
          {k.invalid && <div class="banner error">{t("keyInvalid")}</div>}
          {!k.cert.emails.includes(me.email.toLowerCase()) && <div class="banner warn">{t("keyMismatch", k.cert.emails.join(", ") || k.cert.name)}</div>}
          {!k.canDecrypt && <div class="banner warn">{t("keyNoDecrypt")}</div>}
          <div class="sec-actions">
            {confirmRemove ? (
              <>
                <span class="small">{t("removeKeyQ")}</span>
                <button type="button" class="ghost small" onClick={() => setConfirmRemove(false)}>
                  {t("cancel")}
                </button>
                <button
                  type="button"
                  class="primary danger small"
                  onClick={() => {
                    S.removeKey();
                    setConfirmRemove(false);
                  }}
                >
                  {t("remove")}
                </button>
              </>
            ) : (
              <button type="button" class="ghost small danger-text" onClick={() => setConfirmRemove(true)}>
                {t("removeKey")}
              </button>
            )}
          </div>
        </div>
      ) : (
        <p class="muted">{t("noKey")}</p>
      )}
      {(!k || k.invalid) && <KeyImport />}
      <small class="muted">{t("keyHint")}</small>
      <Switch label={t("signDefault")} checked={p.signDefault} disabled={!k || k.invalid} onChange={(on) => pick("signDefault", on)} />

      <h3>{t("certificates")}</h3>
      <small class="muted">{t("certsHint")}</small>
      <div class="row-controls">
        <button type="button" class="ghost" onClick={() => certInput.current?.click()}>
          <Icon name="upload" size={15} />
          {t("importCert")}
        </button>
        {certs.length > 0 && (
          <button type="button" class="ghost" onClick={() => S.exportCerts()}>
            <Icon name="download" size={15} />
            {t("exportCerts")}
          </button>
        )}
        <input
          ref={certInput}
          type="file"
          hidden
          accept=".pem,.crt,.cer,.der,.p7c,.p7b"
          onChange={async (e) => {
            const el = e.target as HTMLInputElement;
            const f = el.files?.[0];
            el.value = "";
            if (!f) return;
            try {
              await S.importCertFile(f);
            } catch (err) {
              S.fail(err);
            }
          }}
        />
      </div>
      {certs.length === 0 ? (
        <p class="muted">{t("noCerts")}</p>
      ) : (
        <ul class="certlist">
          {certs.map((c) => (
            <li key={c.fingerprint}>
              <div class="certlist-main">
                <strong>{c.emails.join(", ") || c.name}</strong>
                <TrustBadge c={c} />
                <span class="muted small">
                  {c.name !== c.emails[0] ? `${c.name} · ` : ""}
                  {t("issuedBy", c.issuer)} · {t("validUntil", S.fmtDateLong(c.not_after))} · {c.source === "auto" ? t("sourceAuto") : t("sourceManual")}
                </span>
              </div>
              <div class="certlist-actions">
                {c.trust !== "trusted" && (
                  <button type="button" class="link" onClick={() => S.setPinned(c.fingerprint, !c.pinned)}>
                    {c.pinned ? t("untrustThis") : t("trustThis")}
                  </button>
                )}
                <IconButton icon="trash" label={t("remove")} onClick={() => S.removeCert(c.fingerprint)} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

function ShortcutsTab() {
  const keys: [string, string][] = [
    ["j  k", t("scNav")],
    ["Enter  u", t("scOpen")],
    ["c", t("scCompose")],
    ["r  a  f", t("scReply")],
    ["e  #", t("scArchive")],
    ["s  m", t("scStar")],
    ["/", t("scSearch")],
    ["Ctrl + Enter", t("scSend")],
  ];
  return (
    <dl class="keys">
      {keys.map(([k, label]) => (
        <>
          <dt>
            <kbd>{k}</kbd>
          </dt>
          <dd>{label}</dd>
        </>
      ))}
    </dl>
  );
}

function SettingsDialog({ tab: initial }: { tab?: string }) {
  const [tab, setTab] = useState<Tab>((TABS.find((x) => x.id === initial)?.id ?? "general") as Tab);
  const close = () => (S.dialog.value = null);
  return (
    <Dialog title={t("settings")} onClose={close} wide>
      <div class="settings-wrap">
        <nav class="settings-tabs" role="tablist" aria-label={t("settings")}>
          {TABS.map((x) => (
            <button type="button" role="tab" aria-selected={tab === x.id} class={tab === x.id ? "on" : ""} onClick={() => setTab(x.id)}>
              <Icon name={x.icon} size={16} />
              <span>{x.label()}</span>
            </button>
          ))}
        </nav>
        <div class="dialog-body settings" role="tabpanel">
          {tab === "general" && <GeneralTab />}
          {tab === "appearance" && <AppearanceTab />}
          {tab === "privacy" && <PrivacyTab />}
          {tab === "notifications" && <NotificationsTab />}
          {tab === "security" && <SecurityTab />}
          {tab === "shortcuts" && <ShortcutsTab />}
        </div>
      </div>
    </Dialog>
  );
}

function SourceDialog({ text }: { text: string }) {
  return (
    <Dialog title={t("viewSource")} onClose={() => (S.dialog.value = null)} wide>
      <pre class="source">{text}</pre>
    </Dialog>
  );
}

export function Dialogs() {
  const d = S.dialog.value;
  if (!d) return null;
  switch (d.kind) {
    case "settings":
      return <SettingsDialog tab={d.tab} />;
    case "folder":
      return <FolderDialog rename={d.rename} />;
    case "deleteFolder":
      return <DeleteFolderDialog box={d.box} />;
    case "source":
      return <SourceDialog text={d.text} />;
  }
}
