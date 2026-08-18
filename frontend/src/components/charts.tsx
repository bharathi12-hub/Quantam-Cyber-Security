import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const AXIS = "#94a3b8";

const tooltipStyle = {
  borderRadius: 12,
  border: "1px solid rgba(100,116,139,0.25)",
  background: "rgba(15,23,42,0.92)",
  color: "#e2e8f0",
  fontSize: 12,
  padding: "8px 12px",
};

export interface Datum {
  name: string;
  value: number;
}

// Donut chart with a centered total.
export function DonutChart({
  data,
  colors,
  centerLabel,
  centerValue,
}: {
  data: Datum[];
  colors: string[];
  centerLabel?: string;
  centerValue?: number | string;
}) {
  const total = data.reduce((s, d) => s + d.value, 0);
  return (
    <div className="relative h-56">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            innerRadius={62}
            outerRadius={88}
            paddingAngle={2}
            stroke="none"
          >
            {data.map((_, i) => (
              <Cell key={i} fill={colors[i % colors.length]} />
            ))}
          </Pie>
          <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: "#e2e8f0" }} />
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-bold text-slate-900 dark:text-white">
          {centerValue ?? total}
        </span>
        {centerLabel && (
          <span className="text-xs font-medium uppercase tracking-wide text-slate-400">
            {centerLabel}
          </span>
        )}
      </div>
    </div>
  );
}

// Vertical bar chart.
export function BarsChart({
  data,
  color = "#6366f1",
  height = 240,
}: {
  data: Datum[];
  color?: string;
  height?: number;
}) {
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 8, bottom: 4, left: -12 }}>
          <XAxis
            dataKey="name"
            tick={{ fill: AXIS, fontSize: 11 }}
            axisLine={false}
            tickLine={false}
            interval={0}
            angle={data.length > 6 ? -25 : 0}
            textAnchor={data.length > 6 ? "end" : "middle"}
            height={data.length > 6 ? 60 : 24}
          />
          <YAxis tick={{ fill: AXIS, fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
          <Tooltip
            cursor={{ fill: "rgba(148,163,184,0.12)" }}
            contentStyle={tooltipStyle}
            itemStyle={{ color: "#e2e8f0" }}
          />
          <Bar dataKey="value" fill={color} radius={[6, 6, 0, 0]} maxBarSize={48} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// Horizontal ranked bars (for algorithm / target distributions).
export function RankedBars({
  data,
  color = "#4f46e5",
  height = 260,
}: {
  data: Datum[];
  color?: string;
  height?: number;
}) {
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 4, right: 16, bottom: 4, left: 8 }}
        >
          <XAxis type="number" hide allowDecimals={false} />
          <YAxis
            type="category"
            dataKey="name"
            tick={{ fill: AXIS, fontSize: 11 }}
            axisLine={false}
            tickLine={false}
            width={128}
          />
          <Tooltip
            cursor={{ fill: "rgba(148,163,184,0.12)" }}
            contentStyle={tooltipStyle}
            itemStyle={{ color: "#e2e8f0" }}
          />
          <Bar dataKey="value" fill={color} radius={[0, 6, 6, 0]} maxBarSize={22} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
