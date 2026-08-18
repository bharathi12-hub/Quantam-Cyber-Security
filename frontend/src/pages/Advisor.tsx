import { useEffect, useRef, useState } from "react";
import { Send, Sparkles, User } from "lucide-react";
import { api } from "../lib/api";
import { Card } from "../components/primitives";
import { Markdown } from "../components/Markdown";

interface Msg {
  role: "user" | "assistant";
  content: string;
  refs?: string[];
}

const SUGGESTIONS = [
  "Summarize my scan",
  "What is ML-KEM?",
  "How do I migrate ECDSA?",
  "What are my critical findings?",
  "Explain Shor's algorithm",
];

export default function Advisor() {
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api
      .advisorAsk("help")
      .then((r) => setMessages([{ role: "assistant", content: r.answer, refs: r.references }]))
      .catch(() => setMessages([{ role: "assistant", content: "## QuantumShield Security Advisor\n\nAsk me about your findings, algorithms, or migration strategy." }]));
  }, []);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, busy]);

  const send = async (q: string) => {
    const question = q.trim();
    if (!question || busy) return;
    setMessages((m) => [...m, { role: "user", content: question }]);
    setInput("");
    setBusy(true);
    try {
      const r = await api.advisorAsk(question);
      setMessages((m) => [...m, { role: "assistant", content: r.answer, refs: r.references }]);
    } catch (e) {
      setMessages((m) => [...m, { role: "assistant", content: `⚠️ ${(e as Error).message}` }]);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto flex h-[calc(100vh-9rem)] max-w-3xl flex-col">
      <div className="flex-1 space-y-4 overflow-y-auto pb-4">
        {messages.map((m, i) =>
          m.role === "user" ? (
            <div key={i} className="flex justify-end">
              <div className="flex items-start gap-2.5">
                <div className="max-w-lg rounded-2xl rounded-tr-sm bg-brand-600 px-4 py-2.5 text-sm text-white shadow-lg shadow-brand-600/25">
                  {m.content}
                </div>
                <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-slate-200 dark:bg-white/10">
                  <User className="h-4 w-4 text-slate-500 dark:text-slate-300" />
                </div>
              </div>
            </div>
          ) : (
            <div key={i} className="flex items-start gap-2.5">
              <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-brand-400 to-brand-600">
                <Sparkles className="h-4 w-4 text-white" />
              </div>
              <Card className="max-w-2xl flex-1 animate-fade-in !py-3">
                <Markdown content={m.content} />
                {m.refs && m.refs.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5 border-t border-slate-100 pt-2 dark:border-white/10">
                    {m.refs.map((r) => (
                      <span key={r} className="chip bg-slate-100 text-slate-500 ring-slate-500/10 dark:bg-white/5 dark:text-slate-400">
                        {r}
                      </span>
                    ))}
                  </div>
                )}
              </Card>
            </div>
          )
        )}
        {busy && (
          <div className="flex items-center gap-2.5 text-sm text-slate-400">
            <div className="flex h-7 w-7 items-center justify-center rounded-full bg-gradient-to-br from-brand-400 to-brand-600">
              <Sparkles className="h-4 w-4 text-white" />
            </div>
            <span className="animate-pulse">Analyzing…</span>
          </div>
        )}
        <div ref={endRef} />
      </div>

      {messages.length <= 1 && (
        <div className="mb-3 flex flex-wrap gap-2">
          {SUGGESTIONS.map((s) => (
            <button
              key={s}
              onClick={() => send(s)}
              className="rounded-full border border-slate-300/70 bg-white/60 px-3 py-1.5 text-xs font-medium text-slate-600 transition hover:border-brand-400 hover:text-brand-600 dark:border-white/10 dark:bg-white/5 dark:text-slate-300 dark:hover:text-brand-300"
            >
              {s}
            </button>
          ))}
        </div>
      )}

      <form
        onSubmit={(e) => {
          e.preventDefault();
          send(input);
        }}
        className="flex items-center gap-2"
      >
        <input
          className="input"
          placeholder="Ask about findings, algorithms, or migration…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <button type="submit" className="btn-primary h-[42px] w-[42px] shrink-0 !px-0" disabled={busy}>
          <Send className="h-4 w-4" />
        </button>
      </form>
    </div>
  );
}
