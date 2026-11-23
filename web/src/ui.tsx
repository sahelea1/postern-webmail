// Small building blocks: icons, avatar, menu, dialog, toasts.
// Icon outlines are from the Feather set (MIT licence).

import type { ComponentChildren } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import { resizePane, persistLayout, resetLayout, toasts } from "./state";

const PATHS: Record<string, string[]> = {
  inbox: ["M22 12h-6l-2 3h-4l-2-3H2", "M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"],
  sent: ["M22 2 11 13", "M22 2 15 22l-4-9-9-4z"],
  drafts: ["M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z", "M14 2v6h6"],
  archive: ["M21 8v13H3V8", "M1 3h22v5H1z", "M10 12h4"],
  trash: ["M3 6h18", "M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6", "M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"],
  junk: ["M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z", "M12 8v4", "M12 16h.01"],
  folder: ["M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"],
  move: ["M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z", "M12 10v7", "M9 14l3 3 3-3"],
  star: ["M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01z"],
  reply: ["M9 14 4 9l5-5", "M4 9h10a6 6 0 0 1 6 6v5"],
  replyAll: ["M7 14 2 9l5-5", "M12 14 7 9l5-5", "M7 9h9a6 6 0 0 1 6 6v5"],
  forward: ["M15 14l5-5-5-5", "M20 9H10a6 6 0 0 0-6 6v5"],
  search: ["M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16z", "M21 21l-4.35-4.35"],
  x: ["M18 6 6 18", "M6 6l12 12"],
  plus: ["M12 5v14", "M5 12h14"],
  minus: ["M5 12h14"],
  more: ["M12 13a1 1 0 1 0 0-2 1 1 0 0 0 0 2z", "M19 13a1 1 0 1 0 0-2 1 1 0 0 0 0 2z", "M5 13a1 1 0 1 0 0-2 1 1 0 0 0 0 2z"],
  clip: ["M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"],
  settings: ["M4 21v-7", "M4 10V3", "M12 21v-9", "M12 8V3", "M20 21v-5", "M20 12V3", "M1 14h6", "M9 8h6", "M17 16h6"],
  logout: ["M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4", "M16 17l5-5-5-5", "M21 12H9"],
  refresh: ["M23 4v6h-6", "M1 20v-6h6", "M3.51 9a9 9 0 0 1 14.85-3.36L23 10", "M1 14l4.64 4.36A9 9 0 0 0 20.49 15"],
  back: ["M19 12H5", "M12 19l-7-7 7-7"],
  menu: ["M3 12h18", "M3 6h18", "M3 18h18"],
  pencil: ["M12 20h9", "M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4z"],
  mail: ["M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z", "M22 6l-10 7L2 6"],
  mailOpen: ["M21.2 8.4c.5.38.8.97.8 1.6v10a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V10a2 2 0 0 1 .8-1.6l8-6a2 2 0 0 1 2.4 0z", "M22 10l-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 10"],
  download: ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4", "M7 10l5 5 5-5", "M12 15V3"],
  image: ["M5 3h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z", "M8.5 10a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3z", "M21 15l-5-5L5 21"],
  shield: ["M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"],
  code: ["M16 18l6-6-6-6", "M8 6l-6 6 6 6"],
  chevron: ["M6 9l6 6 6-6"],
  expand: ["M15 3h6v6", "M9 21H3v-6", "M21 3l-7 7", "M3 21l7-7"],
  lock: ["M5 11h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2z", "M7 11V7a5 5 0 0 1 10 0v4"],
  unlock: ["M5 11h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2z", "M7 11V7a5 5 0 0 1 9.9-1"],
  seal: ["M12 15a7 7 0 1 0 0-14 7 7 0 0 0 0 14z", "M8.21 13.89 7 23l5-3 5 3-1.21-9.12"],
  key: ["M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.78-7.78zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"],
  bell: ["M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9", "M13.73 21a2 2 0 0 1-3.46 0"],
  volume: ["M11 5 6 9H2v6h4l5 4V5z", "M19.07 4.93a10 10 0 0 1 0 14.14", "M15.54 8.46a5 5 0 0 1 0 7.07"],
  eye: ["M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z", "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"],
  eyeOff: ["M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94", "M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19", "M14.12 14.12a3 3 0 1 1-4.24-4.24", "M1 1l22 22"],
  upload: ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4", "M17 8l-5-5-5 5", "M12 3v12"],
  check: ["M20 6 9 17l-5-5"],
  checkCircle: ["M22 11.08V12a10 10 0 1 1-5.93-9.14", "M22 4 12 14.01l-3-3"],
  alert: ["M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z", "M12 9v4", "M12 17h.01"],
  user: ["M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2", "M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z"],
  droplet: ["M12 2.69l5.66 5.66a8 8 0 1 1-11.31 0z"],
  keyboard: ["M4 5h16a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2z", "M6 9h.01", "M10 9h.01", "M14 9h.01", "M18 9h.01", "M7 15h10"],
};

export function Icon({ name, size = 18, fill = false }: { name: string; size?: number; fill?: boolean }) {
  return (
    <svg
      class="icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill={fill ? "currentColor" : "none"}
      stroke="currentColor"
      stroke-width="1.75"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      {(PATHS[name] || []).map((d) => (
        <path d={d} />
      ))}
    </svg>
  );
}

export function IconButton(p: { icon: string; label: string; onClick?: (e: MouseEvent) => void; active?: boolean; fill?: boolean; disabled?: boolean; class?: string }) {
  return (
    <button
      type="button"
      class={`iconbtn ${p.active ? "active" : ""} ${p.class || ""}`}
      title={p.label}
      aria-label={p.label}
      aria-pressed={p.active === undefined ? undefined : p.active}
      disabled={p.disabled}
      onClick={p.onClick}
    >
      <Icon name={p.icon} fill={p.fill} />
    </button>
  );
}

const HUES = [222, 262, 292, 332, 12, 32, 152, 172, 192];

export function Avatar({ name, email, size = 36 }: { name?: string | null; email: string; size?: number }) {
  const label = (name || email.split("@")[0] || "?").trim();
  const parts = label.split(/[\s._-]+/).filter(Boolean);
  const initials = ((parts[0]?.[0] || "?") + (parts.length > 1 ? parts[parts.length - 1][0] : "")).toUpperCase();
  let h = 0;
  for (const c of email.toLowerCase()) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return (
    <span class="avatar" style={{ width: `${size}px`, height: `${size}px`, fontSize: `${Math.round(size * 0.38)}px`, "--hue": String(HUES[h % HUES.length]) }} aria-hidden="true">
      {initials}
    </span>
  );
}

export function Menu(p: { icon: string; label: string; children: (close: () => void) => ComponentChildren; align?: "left" | "right" }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: Event) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    const esc = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        setOpen(false);
      }
    };
    document.addEventListener("pointerdown", away, true);
    document.addEventListener("keydown", esc, true);
    return () => {
      document.removeEventListener("pointerdown", away, true);
      document.removeEventListener("keydown", esc, true);
    };
  }, [open]);
  return (
    <div class="menu" ref={ref}>
      <IconButton icon={p.icon} label={p.label} active={open} onClick={() => setOpen(!open)} />
      {open && (
        <div class={`popover ${p.align === "left" ? "left" : ""}`} role="menu">
          {p.children(() => setOpen(false))}
        </div>
      )}
    </div>
  );
}

export function MenuItem(p: { icon?: string; label: string; onClick: () => void; danger?: boolean; href?: string }) {
  const inner = (
    <>
      {p.icon && <Icon name={p.icon} size={16} />}
      <span>{p.label}</span>
    </>
  );
  return p.href ? (
    <a class="menuitem" role="menuitem" href={p.href} onClick={p.onClick}>
      {inner}
    </a>
  ) : (
    <button type="button" class={`menuitem ${p.danger ? "danger" : ""}`} role="menuitem" onClick={p.onClick}>
      {inner}
    </button>
  );
}

export function Dialog(p: { title: string; onClose: () => void; children: ComponentChildren; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const first = ref.current?.querySelector<HTMLElement>("input, textarea, select, button.primary");
    (first || ref.current)?.focus();
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        p.onClose();
      }
    };
    document.addEventListener("keydown", key, true);
    return () => {
      document.removeEventListener("keydown", key, true);
      prev?.focus?.();
    };
  }, []);
  return (
    <div class="backdrop" onPointerDown={(e) => e.target === e.currentTarget && p.onClose()}>
      <div class={`dialog ${p.wide ? "wide" : ""}`} role="dialog" aria-modal="true" aria-label={p.title} tabIndex={-1} ref={ref}>
        <header>
          <h2>{p.title}</h2>
          <IconButton icon="x" label="Close" onClick={p.onClose} />
        </header>
        {p.children}
      </div>
    </div>
  );
}

export function Toasts() {
  return (
    <div class="toasts" role="status" aria-live="polite">
      {toasts.value.map((x) => (
        <div key={x.id} class={`toast ${x.error ? "error" : ""}`}>
          {x.text}
        </div>
      ))}
    </div>
  );
}

export function Spinner() {
  return <span class="spinner" role="progressbar" aria-label="Loading" />;
}

/** A drag handle on the right edge of a column. Arrow keys work too; a double click resets. */
export function Resizer({ which, label }: { which: "rail" | "list"; label: string }) {
  const width = () => (document.querySelector(`.${which}`) as HTMLElement | null)?.getBoundingClientRect().width ?? 0;
  return (
    <div
      class="resizer"
      role="separator"
      aria-orientation="vertical"
      aria-label={label}
      title={label}
      tabIndex={0}
      onPointerDown={(e) => {
        if (e.button !== 0) return;
        const handle = e.currentTarget as HTMLElement;
        const startX = e.clientX;
        const startW = width();
        handle.setPointerCapture(e.pointerId);
        document.body.classList.add("resizing");
        const move = (ev: PointerEvent) => resizePane(which, startW + ev.clientX - startX, false);
        const up = () => {
          handle.removeEventListener("pointermove", move);
          handle.removeEventListener("pointerup", up);
          handle.removeEventListener("pointercancel", up);
          document.body.classList.remove("resizing");
          persistLayout();
        };
        handle.addEventListener("pointermove", move);
        handle.addEventListener("pointerup", up);
        handle.addEventListener("pointercancel", up);
        e.preventDefault();
      }}
      onDblClick={() => resetLayout(which)}
      onKeyDown={(e) => {
        const step = e.shiftKey ? 48 : 16;
        if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
          e.preventDefault();
          resizePane(which, width() + (e.key === "ArrowLeft" ? -step : step), true);
        } else if (e.key === "Home") {
          e.preventDefault();
          resetLayout(which);
        }
      }}
    />
  );
}

/** A labelled on/off switch built on a real checkbox. */
export function Switch(p: { label: string; hint?: string; checked: boolean; disabled?: boolean; onChange: (on: boolean) => void }) {
  return (
    <label class={`switch ${p.disabled ? "disabled" : ""}`}>
      <span class="switch-text">
        <span>{p.label}</span>
        {p.hint && <small>{p.hint}</small>}
      </span>
      <input type="checkbox" role="switch" checked={p.checked} disabled={p.disabled} onChange={(e) => p.onChange((e.target as HTMLInputElement).checked)} />
      <span class="switch-track" aria-hidden="true" />
    </label>
  );
}
