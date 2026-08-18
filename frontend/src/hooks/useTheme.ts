import { useEffect, useState } from "react";

type Theme = "light" | "dark";

function initialTheme(): Theme {
  const stored = localStorage.getItem("qs-theme-v2");
  if (stored === "light" || stored === "dark") return stored;
  return "dark"; // SOC console defaults to dark (fully black)
}

export function useTheme() {
  const [theme, setTheme] = useState<Theme>(initialTheme);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("dark", theme === "dark");
    localStorage.setItem("qs-theme-v2", theme);
  }, [theme]);

  const toggle = () => setTheme((t) => (t === "dark" ? "light" : "dark"));
  return { theme, toggle };
}
