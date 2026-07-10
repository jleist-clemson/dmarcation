import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { runCommand, type Line, type Mode } from "./commands";

const PROMPT = "visitor@dmarcation ~ %";

interface TerminalSessionProps {
  mode: Mode;
  banner: Line[];
  /** Whether this session's tab is currently selected and visible. */
  active: boolean;
}

/**
 * A single terminal tab: its own scrollback, input, and command history. Both
 * sessions stay mounted so switching tabs preserves each one's state; the
 * inactive session is hidden with CSS rather than unmounted.
 */
export function TerminalSession({ mode, banner, active }: TerminalSessionProps) {
  const [history, setHistory] = useState<Line[]>(banner);
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

  useEffect(() => {
    if (active) {
      inputRef.current?.focus();
    }
  }, [active]);

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
    const result = await runCommand(mode, raw);
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
    <div className={`body ${active ? "" : "body-hidden"}`} ref={bodyRef} onClick={focusInput}>
      {history.map((l, i) => (
        <div key={i} className={`line line-${l.kind}`}>
          {l.text === "" ? " " : l.text}
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
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKeyDown}
          />
        </div>
      )}

      {busy && <div className="line line-muted">…</div>}
    </div>
  );
}
