import { useState, type KeyboardEvent } from "react";
import { TerminalSession } from "./TerminalSession";
import type { Line, Mode } from "./commands";

const TABS: { id: Mode; label: string }[] = [
  { id: "dmarc", label: "dmarc" },
  { id: "spf", label: "spf" },
];

const DMARC_BANNER: Line[] = [
  { kind: "success", text: "dmarcation - a DMARC validator" },
  { kind: "muted", text: "Type 'help' to get started, or try: lookup google.com" },
  { kind: "text", text: "" },
];

const SPF_BANNER: Line[] = [
  { kind: "success", text: "dmarcation - an SPF validator" },
  { kind: "muted", text: "Type 'help' to get started, or try: lookup github.com" },
  { kind: "text", text: "" },
];

const BANNERS: Record<Mode, Line[]> = {
  dmarc: DMARC_BANNER,
  spf: SPF_BANNER,
};

export function Terminal() {
  const [active, setActive] = useState<Mode>("dmarc");

  function cycle(direction: number) {
    const index = TABS.findIndex((t) => t.id === active);
    const next = (index + direction + TABS.length) % TABS.length;
    setActive(TABS[next].id);
  }

  // Ctrl+Tab / Ctrl+Shift+Tab cycles tabs, like a real terminal emulator.
  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key === "Tab" && e.ctrlKey) {
      e.preventDefault();
      cycle(e.shiftKey ? -1 : 1);
    }
  }

  return (
    <div className="terminal" onKeyDown={onKeyDown}>
      <div className="titlebar">
        <span className="dot dot-red" />
        <span className="dot dot-yellow" />
        <span className="dot dot-green" />

        <div className="tabs" role="tablist" aria-label="Validators">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={tab.id === active}
              className={`tab ${tab.id === active ? "tab-active" : ""}`}
              onClick={() => setActive(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <span className="title">dmarcation — zsh</span>
      </div>

      {TABS.map((tab) => (
        <TerminalSession
          key={tab.id}
          mode={tab.id}
          banner={BANNERS[tab.id]}
          active={tab.id === active}
        />
      ))}
    </div>
  );
}
