import { riskColor } from "../lib/ui";

// Semicircular risk gauge (0-100, higher = worse).
export function RiskGauge({ score, grade }: { score: number; grade: string }) {
  const radius = 90;
  const cx = 110;
  const cy = 110;
  const circumference = Math.PI * radius; // half circle
  const pct = Math.min(100, Math.max(0, score)) / 100;
  const color = riskColor(score);

  const describeArc = (fraction: number) => {
    const angle = Math.PI * (1 - fraction); // 180deg -> 0deg
    const x = cx + radius * Math.cos(angle);
    const y = cy - radius * Math.sin(angle);
    return { x, y };
  };
  const end = describeArc(pct);
  const largeArc = pct > 0.5 ? 1 : 0;

  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 220 130" className="w-full max-w-[240px]">
        {/* track */}
        <path
          d={`M ${cx - radius} ${cy} A ${radius} ${radius} 0 0 1 ${cx + radius} ${cy}`}
          fill="none"
          className="stroke-slate-200 dark:stroke-slate-800"
          strokeWidth={16}
          strokeLinecap="round"
        />
        {/* value */}
        <path
          d={`M ${cx - radius} ${cy} A ${radius} ${radius} 0 ${largeArc} 1 ${end.x} ${end.y}`}
          fill="none"
          stroke={color}
          strokeWidth={16}
          strokeLinecap="round"
          style={{ transition: "all 0.8s cubic-bezier(0.4,0,0.2,1)" }}
        />
        <text
          x={cx}
          y={cy - 18}
          textAnchor="middle"
          className="fill-slate-900 dark:fill-white"
          style={{ fontSize: 40, fontWeight: 800 }}
        >
          {score}
        </text>
        <text
          x={cx}
          y={cy + 4}
          textAnchor="middle"
          className="fill-slate-400"
          style={{ fontSize: 12, fontWeight: 600, letterSpacing: 1 }}
        >
          RISK SCORE
        </text>
      </svg>
      <div className="mt-1 flex items-center gap-2">
        <span className="text-sm text-slate-500 dark:text-slate-400">Posture grade</span>
        <span
          className="flex h-7 w-7 items-center justify-center rounded-md text-sm font-bold text-white"
          style={{ backgroundColor: color }}
        >
          {grade}
        </span>
      </div>
    </div>
  );
}
