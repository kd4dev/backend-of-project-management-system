import { useEffect } from "react";

export function useKeyboardShortcuts(callbacks: {
  onEscape?: () => void;
  onCommandK?: () => void;
  onN?: () => void;
}) {
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      // Escape key
      if (event.key === "Escape" && callbacks.onEscape) {
        callbacks.onEscape();
      }

      // Cmd/Ctrl + K for search
      if ((event.metaKey || event.ctrlKey) && event.key === "k" && callbacks.onCommandK) {
        event.preventDefault();
        callbacks.onCommandK();
      }

      // N for new task (only if not typing in input/textarea)
      if (
        event.key === "n" &&
        !event.metaKey &&
        !event.ctrlKey &&
        !event.altKey &&
        callbacks.onN
      ) {
        const target = event.target as HTMLElement;
        if (target.tagName !== "INPUT" && target.tagName !== "TEXTAREA" && !target.isContentEditable) {
          event.preventDefault();
          callbacks.onN();
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [callbacks]);
}
