// Entry point: sign-in screen or the three-pane shell, plus global shortcuts.

import { render } from "preact";
import { useEffect, useState } from "preact/hooks";
import { Composer, Dialogs } from "./compose";
import { t } from "./i18n";
import { MessageList, Rail, Reader } from "./mail";
import * as S from "./state";
import { Icon, Spinner, Toasts } from "./ui";

function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <main class="login">
      <form
        class="login-card"
        onSubmit={async (e) => {
          e.preventDefault();
          if (busy) return;
          setBusy(true);
          setError("");
          try {
            await S.login(email, password);
          } catch (err) {
            setError(err instanceof Error ? err.message : t("errorGeneric"));
            setPassword("");
          } finally {
            setBusy(false);
          }
        }}
      >
        <div class="login-logo" aria-hidden="true">
          <Icon name="mail" size={26} />
        </div>
        <h1>{S.brand.value}</h1>
        <p class="muted">{t("loginHint")}</p>
        {S.notice.value && <div class="banner">{S.notice.value}</div>}
        {!S.configured.value && <div class="banner warn">{t("notConfigured")}</div>}
        <label class="stack">
          <span>{t("email")}</span>
          <input type="email" name="username" autocomplete="username" autocapitalize="none" spellcheck={false} required autofocus value={email} onInput={(e) => setEmail((e.target as HTMLInputElement).value)} />
        </label>
        <label class="stack">
          <span>{t("password")}</span>
          <input type="password" name="password" autocomplete="current-password" required value={password} onInput={(e) => setPassword((e.target as HTMLInputElement).value)} />
        </label>
        {error && (
          <div class="banner error" role="alert">
            {error}
          </div>
        )}
        <button type="submit" class="primary big" disabled={busy}>
          {busy ? t("signingIn") : t("signIn")}
        </button>
      </form>
    </main>
  );
}

function typing(e: KeyboardEvent): boolean {
  const el = e.target as HTMLElement | null;
  return !!el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable);
}

function onKey(e: KeyboardEvent) {
  if (!S.me.value || S.dialog.value || e.ctrlKey || e.metaKey || e.altKey || typing(e)) return;
  const id = S.openId.value;
  const act = (fn: () => void) => {
    e.preventDefault();
    fn();
  };
  switch (e.key) {
    case "j":
    case "ArrowDown":
      return act(() => S.step(1));
    case "k":
    case "ArrowUp":
      return act(() => S.step(-1));
    case "Enter":
      if (!id && S.items.value[0]) act(() => void S.openMessage(S.items.value[0].id));
      return;
    case "u":
    case "Escape":
      if (id) act(() => S.closeMessage());
      return;
    case "c":
      return act(() => S.newMessage());
    case "/":
      return act(() => document.getElementById("search")?.focus());
    case "r":
      if (id) act(() => S.replyTo(false));
      return;
    case "a":
      if (id) act(() => S.replyTo(true));
      return;
    case "f":
      if (id) act(() => S.forwardOpen());
      return;
    case "e":
      if (id) act(() => S.archive([id]));
      return;
    case "#":
    case "Delete":
      if (id) act(() => void S.remove([id]));
      return;
    case "s": {
      const row = S.openSummary.value;
      if (id && row) act(() => void S.setFlag([id], "flagged", !row.flagged));
      return;
    }
    case "m":
      if (id)
        act(() => {
          void S.setFlag([id], "seen", false);
          S.closeMessage();
        });
      return;
  }
}

function Shell() {
  useEffect(() => {
    document.addEventListener("keydown", onKey);
    const poll = setInterval(() => {
      if (document.visibilityState === "visible") void S.refresh(true);
    }, 60_000);
    const seen = () => {
      if (document.visibilityState === "visible") void S.refresh(true);
    };
    document.addEventListener("visibilitychange", seen);
    const leaving = (e: BeforeUnloadEvent) => {
      if (S.draft.value) e.preventDefault();
    };
    window.addEventListener("beforeunload", leaving);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("visibilitychange", seen);
      window.removeEventListener("beforeunload", leaving);
      clearInterval(poll);
    };
  }, []);
  return (
    <div class={`shell ${S.openId.value ? "reading" : ""}`}>
      <Rail />
      {S.railOpen.value && <div class="scrim" onClick={() => (S.railOpen.value = false)} />}
      <MessageList />
      <Reader />
      <Composer />
      <Dialogs />
    </div>
  );
}

function App() {
  const me = S.me.value;
  return (
    <>
      {me === undefined ? (
        <main class="boot">
          <Spinner />
        </main>
      ) : me === null ? (
        <Login />
      ) : (
        <Shell />
      )}
      <Toasts />
    </>
  );
}

render(<App />, document.getElementById("app")!);
void S.boot();
