// The three panes: folder rail, message list, reader.

import { useEffect, useRef, useState } from "preact/hooks";
import { t } from "./i18n";
import * as S from "./state";
import { Avatar, Icon, IconButton, Menu, MenuItem, Resizer, Spinner } from "./ui";

const ROLE_ICON: Record<string, string> = { inbox: "inbox", drafts: "drafts", sent: "sent", archive: "archive", junk: "junk", trash: "trash" };

function FolderRow({ box, depth = 0 }: { box: S.Mailbox; depth?: number }) {
  const active = S.current.value === box.id;
  const custom = !box.role;
  return (
    <div class={`folder ${active ? "active" : ""} ${box.selectable ? "" : "disabled"}`} style={{ paddingLeft: `${10 + depth * 16}px` }}>
      <button type="button" class="folder-main" disabled={!box.selectable} onClick={() => void S.selectMailbox(box.id)} aria-current={active ? "page" : undefined}>
        <Icon name={ROLE_ICON[box.role || ""] || "folder"} size={17} />
        <span class="folder-name">{S.displayName(box)}</span>
        {box.unread > 0 && <span class="badge">{box.unread > 999 ? "999+" : box.unread}</span>}
      </button>
      {custom && (
        <Menu icon="more" label={t("more")}>
          {(close) => (
            <>
              <MenuItem
                icon="pencil"
                label={t("rename")}
                onClick={() => {
                  close();
                  S.dialog.value = { kind: "folder", rename: box };
                }}
              />
              <MenuItem
                icon="trash"
                label={t("delete")}
                danger
                onClick={() => {
                  close();
                  S.dialog.value = { kind: "deleteFolder", box };
                }}
              />
            </>
          )}
        </Menu>
      )}
    </div>
  );
}

export function Rail() {
  const me = S.me.value!;
  return (
    <nav class={`rail ${S.railOpen.value ? "open" : ""}`} aria-label={t("folders")}>
      <div class="brand">
        <span class="logo" aria-hidden="true">
          <Icon name="mail" size={18} />
        </span>
        <span class="brand-name">{S.brand.value}</span>
      </div>
      <button type="button" class="primary compose-btn" onClick={() => S.newMessage()}>
        <Icon name="pencil" size={17} />
        {t("compose")}
      </button>
      <div class="folders">
        {S.specialBoxes.value.map((b) => (
          <FolderRow key={b.id} box={b} />
        ))}
        <div class="section">
          <span>{t("folders")}</span>
          <IconButton icon="plus" label={t("newFolder")} onClick={() => (S.dialog.value = { kind: "folder" })} />
        </div>
        {S.otherBoxes.value.map(({ box, depth }) => (
          <FolderRow key={box.id} box={box} depth={depth} />
        ))}
      </div>
      <div class="rail-foot">
        <div class="who" title={me.email}>
          <Avatar name={S.prefs.value.name} email={me.email} size={30} />
          <span class="who-mail">{me.email}</span>
        </div>
        <IconButton icon="settings" label={t("settings")} onClick={() => (S.dialog.value = { kind: "settings" })} />
        <IconButton icon="logout" label={t("signOut")} onClick={() => S.logout()} />
      </div>
      <Resizer which="rail" label={t("resizeRail")} />
    </nav>
  );
}

function MoveMenu({ ids, icon = "move" }: { ids: () => string[]; icon?: string }) {
  const targets = [...S.specialBoxes.value, ...S.otherBoxes.value.map((x) => x.box)].filter(
    (b) => b.selectable && b.id !== S.current.value && b.role !== "drafts" && b.role !== "sent",
  );
  return (
    <Menu icon={icon} label={t("moveTo")}>
      {(close) =>
        targets.map((b) => (
          <MenuItem
            key={b.id}
            icon={ROLE_ICON[b.role || ""] || "folder"}
            label={S.displayName(b)}
            onClick={() => {
              close();
              void S.moveTo(ids(), b);
            }}
          />
        ))
      }
    </Menu>
  );
}

function Row({ m }: { m: S.Summary }) {
  const sentLike = ["sent", "drafts"].includes(S.currentBox.value?.role || "");
  const people = sentLike ? S.who(m.to, "—") : S.who(m.from, "—");
  const isOpen = S.openId.value === m.id;
  const isSel = S.selected.value.has(m.id);
  return (
    <li class={`row ${m.seen ? "" : "unread"} ${isOpen ? "open" : ""} ${isSel ? "sel" : ""}`}>
      <label class="check" title={t("nSelected", S.selected.value.size + (isSel ? 0 : 1))}>
        <input type="checkbox" checked={isSel} onChange={() => S.toggleSelect(m.id)} />
        <span class="dot" />
      </label>
      <button type="button" class="row-main" onClick={() => void S.openMessage(m.id)}>
        <span class="row-top">
          <span class="row-from">{people}</span>
          <span class="row-marks">
            {m.security === "encrypted" && (
              <span title={t("encryptedMark")}>
                <Icon name="lock" size={13} />
              </span>
            )}
            {m.security === "signed" && (
              <span title={t("signedMark")}>
                <Icon name="seal" size={13} />
              </span>
            )}
            {m.answered && <Icon name="reply" size={13} />}
            {m.attachment && <Icon name="clip" size={13} />}
          </span>
          <time class="row-date">{S.fmtDateShort(m.date)}</time>
        </span>
        <span class="row-subject">{m.subject || t("noSubject")}</span>
        <span class={`row-preview ${m.security === "encrypted" && !m.preview ? "muted-preview" : ""}`}>
          {m.security === "encrypted" && !m.preview ? t("encryptedPreview") : m.preview}
        </span>
      </button>
      <button
        type="button"
        class={`row-star ${m.flagged ? "on" : ""}`}
        title={m.flagged ? t("unstar") : t("star")}
        aria-label={m.flagged ? t("unstar") : t("star")}
        aria-pressed={m.flagged}
        onClick={() => void S.setFlag([m.id], "flagged", !m.flagged)}
      >
        <Icon name="star" size={15} fill={m.flagged} />
      </button>
    </li>
  );
}

export function MessageList() {
  const box = S.currentBox.value;
  const sel = [...S.selected.value];
  const [q, setQ] = useState("");
  const sentinel = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  useEffect(() => setQ(S.query.value), [S.query.value, S.current.value]);
  useEffect(() => {
    const el = sentinel.current;
    if (!el) return;
    const io = new IntersectionObserver((entries) => {
      if (entries[0].isIntersecting && !S.listLoading.value && S.items.value.length < S.total.value) void S.loadList(true);
    });
    io.observe(el);
    return () => io.disconnect();
  }, [S.current.value, S.query.value]);
  const allRead = sel.length > 0 && sel.every((id) => S.items.value.find((m) => m.id === id)?.seen);
  return (
    <section class={`list ${sel.length ? "selecting" : ""}`} aria-label={box ? S.displayName(box) : ""}>
      <header class="list-head">
        {sel.length ? (
          <div class="bulk">
            <IconButton icon="x" label={t("cancel")} onClick={() => (S.selected.value = new Set())} />
            <span class="bulk-count">{t("nSelected", sel.length)}</span>
            <span class="grow" />
            <IconButton icon={allRead ? "mail" : "mailOpen"} label={allRead ? t("markUnread") : t("markRead")} onClick={() => void S.setFlag(sel, "seen", !allRead)} />
            {S.byRole("archive") && box?.role !== "archive" && <IconButton icon="archive" label={t("archive")} onClick={() => S.archive(sel)} />}
            <MoveMenu ids={() => sel} />
            <IconButton icon="trash" label={t("delete")} onClick={() => void S.remove(sel)} />
          </div>
        ) : (
          <>
            <div class="list-title">
              <IconButton icon="menu" label={t("menu")} class="only-narrow" onClick={() => (S.railOpen.value = true)} />
              <h1>{box ? S.displayName(box) : ""}</h1>
              <span class="count">{S.total.value > 0 ? S.total.value.toLocaleString() : ""}</span>
              <span class="grow" />
              <IconButton icon="refresh" label={t("refresh")} class={S.listLoading.value ? "spin" : ""} onClick={() => void S.refresh()} />
            </div>
            <form
              class="searchbox"
              role="search"
              onSubmit={(e) => {
                e.preventDefault();
                void S.search(q);
              }}
            >
              <Icon name="search" size={16} />
              <input
                ref={searchRef}
                id="search"
                type="search"
                placeholder={t("search")}
                aria-label={t("search")}
                value={q}
                onInput={(e) => setQ((e.target as HTMLInputElement).value)}
                onKeyDown={(e) => {
                  if (e.key === "Escape") {
                    setQ("");
                    if (S.query.value) void S.search("");
                    (e.target as HTMLInputElement).blur();
                  }
                }}
              />
              {S.query.value && (
                <IconButton
                  icon="x"
                  label={t("cancel")}
                  onClick={() => {
                    setQ("");
                    void S.search("");
                  }}
                />
              )}
            </form>
          </>
        )}
      </header>
      <div class="list-scroll">
        {S.query.value && <div class="list-note">{t("searching", S.query.value)}</div>}
        <ul class="rows">
          {S.items.value.map((m) => (
            <Row key={m.id} m={m} />
          ))}
        </ul>
        {!S.items.value.length && !S.listLoading.value && (
          <div class="empty">
            <Icon name={S.query.value ? "search" : "inbox"} size={34} />
            <strong>{t("empty")}</strong>
            <span>{S.query.value ? t("noResults") : t("emptyHint")}</span>
          </div>
        )}
        {S.listLoading.value && (
          <div class="list-loading">
            <Spinner />
          </div>
        )}
        <div ref={sentinel} class="sentinel" />
      </div>
      <Resizer which="list" label={t("resizeList")} />
    </section>
  );
}

/** Shows message HTML inside a frame that cannot run script. The document it
 *  loads is cleaned on the server and carries its own content policy. */
function MailFrame({ src }: { src: string }) {
  const ref = useRef<HTMLIFrameElement>(null);
  const [height, setHeight] = useState(160);
  useEffect(() => {
    const frame = ref.current;
    if (!frame) return;
    let ro: ResizeObserver | undefined;
    const measure = () => {
      try {
        const doc = frame.contentDocument;
        if (doc?.body) setHeight(Math.max(120, doc.body.scrollHeight + 2));
      } catch {
        // not readable: keep the current height
      }
    };
    const onLoad = () => {
      measure();
      try {
        const body = frame.contentDocument?.body;
        if (body) {
          ro = new ResizeObserver(measure);
          ro.observe(body);
        }
      } catch {
        // ignore
      }
    };
    frame.addEventListener("load", onLoad);
    return () => {
      frame.removeEventListener("load", onLoad);
      ro?.disconnect();
    };
  }, [src]);
  return (
    <iframe
      ref={ref}
      class="mailframe"
      title="message"
      src={src}
      sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox"
      referrerpolicy="no-referrer"
      style={{ height: `${height}px` }}
    />
  );
}

const URL_RE = /(https?:\/\/[^\s<>"')\]]+)/g;

function PlainText({ text }: { text: string }) {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  return (
    <div class="plain">
      {lines.map((line, i) => (
        <div key={i} class={line.startsWith(">") ? "quoted" : ""}>
          {line === ""
            ? " "
            : line.split(URL_RE).map((part, j) =>
                j % 2 === 1 ? (
                  <a href={part} target="_blank" rel="noopener noreferrer nofollow">
                    {part}
                  </a>
                ) : (
                  part
                ),
              )}
        </div>
      ))}
    </div>
  );
}

function People({ label, list }: { label: string; list: S.Addr[] }) {
  if (!list.length) return null;
  return (
    <div class="people">
      <span class="people-label">{label}</span>
      <span>
        {list.map((a, i) => (
          <span key={i} title={a.email}>
            {i > 0 ? ", " : ""}
            {a.name ? `${a.name} <${a.email}>` : a.email}
          </span>
        ))}
      </span>
    </div>
  );
}

function CertDetails({ c, sig }: { c: S.CertInfo; sig?: S.SignatureReport }) {
  const stored = S.certStore.value.find((x) => x.fingerprint === c.fingerprint);
  const fp = c.fingerprint.toUpperCase().match(/.{2}/g)!.join(":");
  return (
    <div class="sec-details">
      <dl>
        <dt>{t("from")}</dt>
        <dd>
          {c.name} {c.emails.length > 0 && <span class="muted">&lt;{c.emails.join(", ")}&gt;</span>}
        </dd>
        <dt>{t("details")}</dt>
        <dd>
          {t("issuedBy", c.issuer)} · {t("validUntil", S.fmtDateLong(c.not_after))} · {c.key}
        </dd>
        {sig?.signed_at && (
          <>
            <dt>{t("date")}</dt>
            <dd>{t("signedAt", S.fmtDateLong(sig.signed_at))}</dd>
          </>
        )}
        <dt>{t("fingerprint")}</dt>
        <dd class="mono">{fp}</dd>
      </dl>
      {(sig?.trust_detail || c.trust_detail) && <p class="muted">{sig?.trust_detail || c.trust_detail}</p>}
      {sig?.weak && <p class="warn-text">{t("sigWeak")}</p>}
      <p class="muted small">{t("revocationNote")}</p>
      <div class="sec-actions">
        {stored?.pinned ? (
          <button type="button" class="ghost small" onClick={() => S.setPinned(c.fingerprint, false)}>
            {t("untrustThis")}
          </button>
        ) : (
          c.trust !== "trusted" && (
            <button
              type="button"
              class="ghost small"
              onClick={() => {
                S.addCerts([c], "manual");
                S.toast(t("certSaved"));
              }}
            >
              <Icon name="check" size={14} />
              {t("trustThis")}
            </button>
          )
        )}
      </div>
    </div>
  );
}

/** What S/MIME says about the open message: a line of chips, details on click. */
function SecurityStrip({ v }: { v: S.MessageView }) {
  const [open, setOpen] = useState(false);
  const enc = v.security?.encrypted;
  const sig = v.security?.signed;
  if (!enc && !sig) return null;
  let sigChip = null;
  if (sig) {
    const who = sig.signer ? sig.signer.emails[0] || sig.signer.name : "?";
    let tone = "warn";
    let text = t("sigUnchecked");
    let icon = "alert";
    if (sig.status === "invalid") {
      tone = "bad";
      text = t("sigInvalid");
    } else if (sig.status === "valid" && sig.signer) {
      icon = "seal";
      const pinned = S.certStore.value.some((x) => x.fingerprint === sig.signer!.fingerprint && x.pinned);
      if (!sig.signer_matches_from) text = t("sigMismatch", who);
      else if (sig.trust === "trusted") {
        tone = "ok";
        text = t("sigVerified", who);
      } else if (pinned) {
        tone = "ok";
        text = t("sigTrustedByYou", who);
      } else if (sig.trust === "expired") text = t("sigExpired", who);
      else text = t("sigUntrusted", who);
    }
    sigChip = (
      <button type="button" class={`sec-chip ${tone}`} aria-expanded={open} onClick={() => setOpen(!open)} title={sig.detail || undefined}>
        <Icon name={icon} size={14} />
        <span>{text}</span>
        <Icon name="chevron" size={13} />
      </button>
    );
  }
  return (
    <div class="sec">
      <div class="sec-row">
        {enc?.status === "decrypted" && (
          <span class="sec-chip ok">
            <Icon name="lock" size={14} />
            <span>{t("encDecrypted", enc.algorithm)}</span>
          </span>
        )}
        {sigChip}
      </div>
      {open && sig?.signer && <CertDetails c={sig.signer} sig={sig} />}
      {open && sig && !sig.signer && <p class="muted small">{sig.detail}</p>}
    </div>
  );
}

/** Shown instead of the body when an encrypted message cannot be opened. */
function Locked({ enc }: { enc: S.EncryptionReport }) {
  const text = enc.status === "no_key" ? t("encNoKey") : enc.status === "not_for_you" ? t("encNotForYou") : t("encFailed");
  return (
    <div class="locked">
      <Icon name="lock" size={30} />
      <strong>{text}</strong>
      <span class="muted">{enc.status === "no_key" ? (S.ownKey.value?.invalid ? t("keyInvalid") : t("encNoKeyHint")) : enc.detail}</span>
      {enc.status === "no_key" && (
        <button type="button" class="ghost" onClick={() => (S.dialog.value = { kind: "settings", tab: "security" })}>
          <Icon name="key" size={15} />
          {t("openSettings")}
        </button>
      )}
    </div>
  );
}

export function Reader() {
  const id = S.openId.value;
  const v = S.openView.value;
  const row = S.openSummary.value;
  const [asText, setAsText] = useState(false);
  const [details, setDetails] = useState(false);
  useEffect(() => {
    setAsText(S.prefs.value.preferText);
    setDetails(false);
  }, [id]);
  if (!id) {
    return (
      <section class="reader empty-reader">
        <div class="empty">
          <Icon name="mailOpen" size={40} />
          <span>{t("selectHint")}</span>
        </div>
      </section>
    );
  }
  const box = S.currentBox.value;
  const mailbox = S.current.value;
  const from = v?.from[0];
  const files = v ? v.attachments.filter((a) => !a.inline) : [];
  const isDraft = box?.role === "drafts";
  const junk = S.byRole("junk");
  const inbox = S.byRole("inbox");
  return (
    <section class="reader" aria-label={v?.subject || ""}>
      <header class="reader-bar">
        <IconButton icon="back" label={t("back")} class="only-narrow" onClick={() => S.closeMessage()} />
        {isDraft ? (
          <button type="button" class="primary small" disabled={!v} onClick={() => S.editDraft()}>
            <Icon name="pencil" size={15} />
            <span class="btn-label">{t("editDraft")}</span>
          </button>
        ) : (
          <>
            <button type="button" class="primary small" disabled={!v} onClick={() => S.replyTo(false)}>
              <Icon name="reply" size={15} />
              <span class="btn-label">{t("reply")}</span>
            </button>
            <IconButton icon="replyAll" label={t("replyAll")} disabled={!v} onClick={() => S.replyTo(true)} />
            <IconButton icon="forward" label={t("forward")} disabled={!v} onClick={() => S.forwardOpen()} />
          </>
        )}
        <span class="grow" />
        {row && <IconButton icon="star" label={row.flagged ? t("unstar") : t("star")} fill={row.flagged} active={row.flagged} class="starbtn" onClick={() => void S.setFlag([id], "flagged", !row.flagged)} />}
        {S.byRole("archive") && box?.role !== "archive" && !isDraft && <IconButton icon="archive" label={t("archive")} onClick={() => S.archive([id])} />}
        <MoveMenu ids={() => [id]} />
        <IconButton icon="trash" label={t("delete")} onClick={() => void S.remove([id])} />
        <Menu icon="more" label={t("more")}>
          {(close) => (
            <>
              <MenuItem
                icon="mail"
                label={t("markUnread")}
                onClick={() => {
                  close();
                  void S.setFlag([id], "seen", false);
                  S.closeMessage();
                }}
              />
              {junk && box?.role !== "junk" && (
                <MenuItem
                  icon="junk"
                  label={t("markJunk")}
                  onClick={() => {
                    close();
                    void S.moveTo([id], junk);
                  }}
                />
              )}
              {inbox && box?.role === "junk" && (
                <MenuItem
                  icon="inbox"
                  label={t("notJunk")}
                  onClick={() => {
                    close();
                    void S.moveTo([id], inbox);
                  }}
                />
              )}
              {v?.has_html && (
                <MenuItem
                  icon={asText ? "image" : "drafts"}
                  label={asText ? t("showHtml") : t("showText")}
                  onClick={() => {
                    close();
                    setAsText(!asText);
                  }}
                />
              )}
              <MenuItem
                icon="code"
                label={t("viewSource")}
                onClick={() => {
                  close();
                  void S.viewSource(id);
                }}
              />
              <MenuItem icon="download" label={t("download")} href={S.messageUrl("raw", mailbox, id)} onClick={close} />
            </>
          )}
        </Menu>
      </header>
      <div class="reader-scroll">
        {!v ? (
          <div class="reader-loading">
            <Spinner />
          </div>
        ) : (
          <article>
            <h1 class="subject">{v.subject || t("noSubject")}</h1>
            <div class="sender">
              <Avatar name={from?.name} email={from?.email || "?"} size={40} />
              <div class="sender-text">
                <div class="sender-line">
                  <strong>{from ? from.name || from.email : "—"}</strong>
                  {from?.name && <span class="sender-mail">{from.email}</span>}
                  <span class="grow" />
                  <time>{S.fmtDateLong(v.date)}</time>
                </div>
                <button type="button" class="to-line" onClick={() => setDetails(!details)} aria-expanded={details}>
                  {t("to")}: {S.who([...v.to, ...v.cc], "—")}
                  <Icon name="chevron" size={13} />
                </button>
                {details && (
                  <div class="details">
                    <People label={t("from")} list={v.from} />
                    <People label={t("to")} list={v.to} />
                    <People label={t("cc")} list={v.cc} />
                    <People label={t("bcc")} list={v.bcc} />
                    {v.reply_to.length > 0 && <People label="Reply-To" list={v.reply_to} />}
                    <div class="people">
                      <span class="people-label">{t("date")}</span>
                      <span>{S.fmtDateLong(v.date)}</span>
                    </div>
                  </div>
                )}
              </div>
            </div>
            <SecurityStrip v={v} />
            {v.has_html && !asText && v.remote_images && !S.showImages.value && (
              <div class="banner">
                <Icon name="shield" size={16} />
                <span>
                  {!v.can_load_images
                    ? t("imagesBlocked")
                    : S.prefs.value.images === "never"
                      ? t("imagesBlockedSetting")
                      : v.security?.encrypted
                        ? t("encryptedImages")
                        : t("imagesHidden")}
                </span>
                {v.can_load_images && S.prefs.value.images !== "never" && (
                  <>
                    <button type="button" class="link" onClick={() => (S.showImages.value = true)}>
                      {t("showImages")}
                    </button>
                    {from && !v.security?.encrypted && (
                      <button type="button" class="link" onClick={() => S.trustSender(from.email)}>
                        {t("alwaysFromSender", from.email)}
                      </button>
                    )}
                  </>
                )}
              </div>
            )}
            <div class="body">
              {v.security?.encrypted && v.security.encrypted.status !== "decrypted" ? (
                <Locked enc={v.security.encrypted} />
              ) : v.has_html && !asText ? (
                <MailFrame key={`${id}:${S.showImages.value}`} src={S.messageUrl("html", mailbox, id, S.showImages.value ? { images: 1 } : {})} />
              ) : (
                <PlainText text={v.text} />
              )}
            </div>
            {files.length > 0 && (
              <div class="attachments">
                <div class="attachments-title">
                  <Icon name="clip" size={15} />
                  {files.length === 1 ? t("attachment") : t("attachments", files.length)}
                </div>
                <div class="chips">
                  {files.map((a) => (
                    <a
                      key={a.part}
                      class="chip"
                      href={S.messageUrl("part", mailbox, id, { part: a.part })}
                      download={a.name}
                      title={a.name}
                      onClick={(e) => {
                        // Encrypted messages need the key, which a plain link cannot carry.
                        if (v.security?.encrypted) {
                          e.preventDefault();
                          void S.downloadPart(mailbox, id, a);
                        }
                      }}
                    >
                      <Icon name={a.mime.startsWith("image/") ? "image" : "drafts"} size={18} />
                      <span class="chip-text">
                        <span class="chip-name">{a.name}</span>
                        <span class="chip-size">{S.fmtSize(a.size)}</span>
                      </span>
                      <Icon name="download" size={15} />
                    </a>
                  ))}
                </div>
              </div>
            )}
          </article>
        )}
      </div>
    </section>
  );
}
