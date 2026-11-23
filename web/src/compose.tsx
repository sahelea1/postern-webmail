// The composer and the dialogs.

import { useEffect, useRef, useState } from "preact/hooks";
import { t } from "./i18n";
import * as S from "./state";
import { Dialog, Icon, IconButton } from "./ui";

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
      <footer class="composer-foot">
        <button type="submit" class="primary" disabled={S.sending.value}>
          <Icon name="sent" size={15} />
          {S.sending.value ? t("sending") : t("send")}
        </button>
        <IconButton icon="clip" label={t("attach")} onClick={() => fileInput.current?.click()} />
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

function SettingsDialog() {
  const me = S.me.value!;
  const [p, setP] = useState<S.Prefs>(S.prefs.value);
  const close = () => (S.dialog.value = null);
  const pick = <K extends keyof S.Prefs>(k: K, v: S.Prefs[K]) => {
    const next = { ...p, [k]: v };
    setP(next);
    S.setPrefs(next);
  };
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
    <Dialog title={t("settings")} onClose={close} wide>
      <div class="dialog-body settings">
        <label class="stack">
          <span>{t("yourName")}</span>
          <input type="text" maxLength={100} value={p.name} onInput={(e) => pick("name", (e.target as HTMLInputElement).value)} />
          <small>{t("yourNameHint")}</small>
        </label>
        <label class="stack">
          <span>{t("signature")}</span>
          <textarea rows={3} maxLength={2000} value={p.signature} onInput={(e) => pick("signature", (e.target as HTMLTextAreaElement).value)} />
        </label>
        <div class="grid3">
          <label class="stack">
            <span>{t("theme")}</span>
            <select value={p.theme} onChange={(e) => pick("theme", (e.target as HTMLSelectElement).value as S.Prefs["theme"])}>
              <option value="system">{t("themeSystem")}</option>
              <option value="light">{t("themeLight")}</option>
              <option value="dark">{t("themeDark")}</option>
            </select>
          </label>
          <label class="stack">
            <span>{t("density")}</span>
            <select value={p.density} onChange={(e) => pick("density", (e.target as HTMLSelectElement).value as S.Prefs["density"])}>
              <option value="comfortable">{t("comfortable")}</option>
              <option value="compact">{t("compact")}</option>
            </select>
          </label>
          <label class="stack">
            <span>{t("language")}</span>
            <select value={p.language} onChange={(e) => pick("language", (e.target as HTMLSelectElement).value as S.Prefs["language"])}>
              <option value="auto">{t("langAuto")}</option>
              <option value="en">English</option>
              <option value="de">Deutsch</option>
            </select>
          </label>
        </div>
        <small>{t("storedHere")}</small>
        <h3>{t("shortcuts")}</h3>
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
        <h3>{t("account")}</h3>
        <p class="muted">{t("signedInAs", me.email, me.server, me.protocol.toUpperCase())}</p>
        <p class="muted">{t("version", me.version)}</p>
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
      return <SettingsDialog />;
    case "folder":
      return <FolderDialog rename={d.rename} />;
    case "deleteFolder":
      return <DeleteFolderDialog box={d.box} />;
    case "source":
      return <SourceDialog text={d.text} />;
  }
}
