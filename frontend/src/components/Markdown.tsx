import { ReactNode } from "react";

// Minimal markdown renderer for advisor content (headings, lists, bold,
// italic, inline + fenced code). Avoids a heavy dependency.
//
// Order matters: **bold** must be tried before *italic*. Underscore italics
// require non-word boundaries so identifiers like token_signing_key are left
// alone, matching CommonMark's intraword rule.
const INLINE_RE = /(\*\*[^*]+\*\*|`[^`]+`|\*[^*\n]+\*|(?<![A-Za-z0-9])_[^_\n]+_(?![A-Za-z0-9]))/g;

function inline(text: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  let key = 0;
  INLINE_RE.lastIndex = 0;
  while ((m = INLINE_RE.exec(text))) {
    if (m.index > last) nodes.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith("**"))
      nodes.push(<strong key={key++} className="font-semibold text-slate-900 dark:text-white">{tok.slice(2, -2)}</strong>);
    else if (tok.startsWith("`"))
      nodes.push(
        <code key={key++} className="rounded bg-slate-200/70 px-1 py-0.5 font-mono text-[0.85em] text-brand-700 dark:bg-white/10 dark:text-brand-300">
          {tok.slice(1, -1)}
        </code>
      );
    else
      nodes.push(<em key={key++} className="italic">{tok.slice(1, -1)}</em>);
    last = m.index + tok.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

export function Markdown({ content }: { content: string }) {
  const lines = content.split("\n");
  const blocks: ReactNode[] = [];
  let i = 0;
  let key = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (line.trim().startsWith("```")) {
      const buf: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith("```")) buf.push(lines[i++]);
      i++;
      blocks.push(
        <pre key={key++} className="my-3 overflow-x-auto rounded-lg bg-slate-900 p-3 font-mono text-xs leading-relaxed text-slate-100 ring-1 ring-white/10">
          {buf.join("\n")}
        </pre>
      );
      continue;
    }

    if (line.startsWith("### ")) {
      blocks.push(<h4 key={key++} className="mt-4 mb-1 text-sm font-bold text-slate-800 dark:text-slate-100">{inline(line.slice(4))}</h4>);
      i++;
      continue;
    }
    if (line.startsWith("## ")) {
      blocks.push(<h3 key={key++} className="mt-2 mb-2 text-lg font-bold text-slate-900 dark:text-white">{inline(line.slice(3))}</h3>);
      i++;
      continue;
    }

    if (/^\s*[-*]\s+/.test(line) || /^\s*\d+\.\s+/.test(line)) {
      const items: string[] = [];
      const ordered = /^\s*\d+\.\s+/.test(line);
      while (i < lines.length && (/^\s*[-*]\s+/.test(lines[i]) || /^\s*\d+\.\s+/.test(lines[i]))) {
        items.push(lines[i].replace(/^\s*(?:[-*]|\d+\.)\s+/, ""));
        i++;
      }
      const ListTag = ordered ? "ol" : "ul";
      blocks.push(
        <ListTag key={key++} className={`my-2 space-y-1 pl-5 text-sm text-slate-600 dark:text-slate-300 ${ordered ? "list-decimal" : "list-disc"}`}>
          {items.map((it, idx) => (
            <li key={idx}>{inline(it)}</li>
          ))}
        </ListTag>
      );
      continue;
    }

    if (line.trim() === "") {
      i++;
      continue;
    }

    blocks.push(<p key={key++} className="my-1.5 text-sm leading-relaxed text-slate-600 dark:text-slate-300">{inline(line)}</p>);
    i++;
  }

  return <div>{blocks}</div>;
}
