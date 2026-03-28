import { useEffect, useState } from "react";
import {
  getInitialTheme,
  THEME_STORAGE_KEY,
  type ThemeMode
} from "../lib/monitoring";

export function useThemeMode() {
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => getInitialTheme());

  useEffect(() => {
    document.documentElement.dataset.theme = themeMode;
    document.documentElement.style.colorScheme = themeMode;
    window.localStorage.setItem(THEME_STORAGE_KEY, themeMode);
  }, [themeMode]);

  return { themeMode, setThemeMode };
}
