import { useEffect } from "react";
import { useNavigate } from "react-router-dom";

export const PALETTE_EVENT = "qs:palette-toggle";

export function openPalette() {
  window.dispatchEvent(new CustomEvent(PALETTE_EVENT));
}

function isTyping(el: EventTarget | null): boolean {
  const t = el as HTMLElement | null;
  if (!t) return false;
  const tag = t.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || t.isContentEditable;
}

/**
 * Global keyboard shortcuts:
 *  - Ctrl/Cmd+K or "/"  → command palette
 *  - g then d/f/c/p/a/r/s → navigate
 */
export function useGlobalHotkeys() {
  const nav = useNavigate();

  useEffect(() => {
    let pendingG = false;
    let gTimer: number | undefined;

    const routes: Record<string, string> = {
      d: "/",
      f: "/findings",
      c: "/certificates",
      p: "/dependencies",
      a: "/advisor",
      m: "/migration",
      o: "/compliance",
      n: "/analytics",
      r: "/reports",
      s: "/scan",
      k: "/algorithms",
    };

    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        openPalette();
        return;
      }
      if (isTyping(e.target)) return;

      if (e.key === "/") {
        e.preventDefault();
        openPalette();
        return;
      }
      if (pendingG && routes[e.key.toLowerCase()]) {
        e.preventDefault();
        nav(routes[e.key.toLowerCase()]);
        pendingG = false;
        return;
      }
      if (e.key.toLowerCase() === "g") {
        pendingG = true;
        window.clearTimeout(gTimer);
        gTimer = window.setTimeout(() => (pendingG = false), 1200);
      }
    };

    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.clearTimeout(gTimer);
    };
  }, [nav]);
}
