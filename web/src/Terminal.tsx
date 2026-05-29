import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { runCommand, type Line } from "./commands";

const PROMPT = "visitor@dmarcation ~ %";

const BANNER: Line[] = [
  { kind: "success", text: "dmarcation - a simple DMARC validator" },
  { kind: "muted", text: "Type 'help' to get started, or try: lookup google.com" },
  { kind: "text", text: "" },
];

export function Terminal() {
  const [history, setHistory] = useState<Line[]>(BANNER);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [commandLog, setCommandLog] = useState<string[]>([]);
  const [logIndex, setLogIndex] = useState<number | null>(null);

  const inputRef = useRef<HTMLInputElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [history, busy]);

  const focusInput = () => inputRef.current?.focus();

  async function submit(raw: string) {
    const entry: Line = { kind: "input", text: `${PROMPT} ${raw}` };
    setHistory((h) => [...h, entry]);
    setInput("");
    setLogIndex(null);

    if (raw.trim() !== "") {
      setCommandLog((log) => [...log, raw]);
    }

    setBusy(true);
    const result = await runCommand(raw);
    setBusy(false);

    if (result.clear) {
      setHistory([]);
      return;
    }
    if (result.lines.length > 0) {
      setHistory((h) => [...h, ...result.lines]);
    }
  }

  function onKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" && !busy) {
      submit(input);
      return;
    }

    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (commandLog.length === 0) return;
      const next = logIndex === null ? commandLog.length - 1 : Math.max(0, logIndex - 1);
      setLogIndex(next);
      setInput(commandLog[next]);
    }

    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (logIndex === null) return;
      const next = logIndex + 1;
      if (next >= commandLog.length) {
        setLogIndex(null);
        setInput("");
      } else {
        setLogIndex(next);
        setInput(commandLog[next]);
      }
    }
  }

  return (
    <div className="terminal" onClick={focusInput}>
      <div className="titlebar">
        <span className="dot dot-red" />
        <span className="dot dot-yellow" />
        <span className="dot dot-green" />
          <span className="title">dmarcation — zsh</span>
      </div>

      <div className="body" ref={bodyRef}>
        {history.map((l, i) => (
          <div key={i} className={`line line-${l.kind}`}>
            {l.text === "" ? "\u00a0" : l.text}
          </div>
        ))}

        {!busy && (
          <div className="line input-line">
            <span className="prompt">{PROMPT}</span>
            <input
              ref={inputRef}
              className="cmd-input"
              value={input}
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              autoComplete="off"
              autoFocus
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={onKeyDown}
            />
          </div>
        )}

        {busy && <div className="line line-muted">…</div>}
      </div>
    </div>
  );
}
