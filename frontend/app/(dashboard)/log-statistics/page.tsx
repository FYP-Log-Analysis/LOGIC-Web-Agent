"use client";

import { useEffect, useState } from "react";
import { getNormalizedLogs } from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import { SectionHeader, MetricCard, Divider, Spinner, DataTable } from "@/components/ui-primitives";
import BarChart from "@/components/charts/bar-chart";
import PieChart from "@/components/charts/pie-chart";

interface LogEntry {
  method?: string;
  status?: number | string;
  ip?: string;
  path?: string;
  user_agent?: string;
  is_bot?: boolean;
  timestamp?: string;
  response_size?: number;
}

function topN<T>(map: Record<string, number>, n: number): { label: string; count: number }[] {
  return Object.entries(map)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([label, count]) => ({ label, count }));
}

function statusClass(status: number | string): string {
  const s = Number(status);
  if (s >= 500) return "5xx";
  if (s >= 400) return "4xx";
  if (s >= 300) return "3xx";
  if (s >= 200) return "2xx";
  return "other";
}

/** Interpolate a count (0..maxCount) into a CSS background-color string. */
function heatColor(count: number, maxCount: number): string {
  if (maxCount === 0 || count === 0) return "#111";
  const ratio = count / maxCount;
  if (ratio > 0.75) return "#7c2020";
  if (ratio > 0.5) return "#5a3010";
  if (ratio > 0.25) return "#3a3010";
  return "#1a2a18";
}

export default function LogStatisticsPage() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const { activeProject, timeRange } = useAuthStore();
  const scope = { projectId: activeProject?.id, startTs: timeRange?.from, endTs: timeRange?.to };

  useEffect(() => {
    setLoading(true);
    getNormalizedLogs(scope)
      .then((d) => setLogs(Array.isArray(d) ? (d as LogEntry[]) : []))
      .catch(() => {})
      .finally(() => setLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeProject?.id, timeRange?.from, timeRange?.to]);

  if (loading) return <div style={{ textAlign: "center", padding: 60 }}><Spinner size={28} /></div>;

  // Aggregate
  const methodMap: Record<string, number> = {};
  const statusMap: Record<string, number> = {};
  const ipMap: Record<string, number> = {};
  const pathMap: Record<string, number> = {};
  const uaMap: Record<string, number> = {};
  const hourMap: Record<number, number> = {};
  const sizeBuckets = [0, 0, 0, 0, 0, 0]; // <1KB, 1-10KB, 10-50KB, 50-100KB, 100KB-1MB, >1MB
  let bots = 0;
  const seenIps = new Set<string>();

  for (const l of logs) {
    if (l.method) methodMap[l.method] = (methodMap[l.method] ?? 0) + 1;
    const sc = statusClass(l.status ?? 0);
    statusMap[sc] = (statusMap[sc] ?? 0) + 1;
    if (l.ip) { ipMap[l.ip] = (ipMap[l.ip] ?? 0) + 1; seenIps.add(l.ip); }
    if (l.path) pathMap[l.path] = (pathMap[l.path] ?? 0) + 1;
    if (l.user_agent) uaMap[l.user_agent] = (uaMap[l.user_agent] ?? 0) + 1;
    if (l.is_bot) bots++;
    if (l.timestamp) {
      const h = new Date(l.timestamp).getUTCHours();
      hourMap[h] = (hourMap[h] ?? 0) + 1;
    }
    if (l.response_size !== undefined) {
      const b = l.response_size;
      if (b < 1024) sizeBuckets[0]++;
      else if (b < 10 * 1024) sizeBuckets[1]++;
      else if (b < 50 * 1024) sizeBuckets[2]++;
      else if (b < 100 * 1024) sizeBuckets[3]++;
      else if (b < 1024 * 1024) sizeBuckets[4]++;
      else sizeBuckets[5]++;
    }
  }

  const topMethods = topN(methodMap, 6);
  const topPaths = topN(pathMap, 8);
  const topIPs = topN(ipMap, 8);
  const topUAs = topN(uaMap, 10);

  const statusColors: Record<string, string> = { "2xx": "#4caf50", "3xx": "#4488ff", "4xx": "#f0c040", "5xx": "#ff4444", other: "#555" };

  const hourCounts = Array.from({ length: 24 }, (_, h) => hourMap[h] ?? 0);
  const maxHour = Math.max(...hourCounts, 1);
  const hasTimestamps = logs.some((l) => l.timestamp);
  const hasSizes = logs.some((l) => l.response_size !== undefined);

  return (
    <div>
      <SectionHeader
        title="Log Statistics"
        subtitle="Distribution analysis of ingested and normalised log data"
      />

      {/* Top metrics */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 24 }}>
        <MetricCard label="Total Entries" value={logs.length.toLocaleString()} />
        <MetricCard label="Unique IPs" value={seenIps.size.toLocaleString()} />
        <MetricCard label="Bot Requests" value={bots.toLocaleString()} accent="#f0c040" />
        <MetricCard label="Human Requests" value={(logs.length - bots).toLocaleString()} accent="#4488ff" />
      </div>

      {/* Hourly Heatmap */}
      {hasTimestamps && (
        <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 20, marginBottom: 24 }}>
          <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 14 }}>
            Hourly Traffic Distribution (UTC) — request volume per hour of day
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(24, 1fr)", gap: 3 }}>
            {hourCounts.map((count, h) => (
              <div key={h} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
                <div
                  title={`${h.toString().padStart(2, "0")}:00 — ${count.toLocaleString()} requests`}
                  style={{
                    width: "100%",
                    height: 48,
                    background: heatColor(count, maxHour),
                    borderRadius: 2,
                    border: "1px solid #1a1a1a",
                    cursor: "default",
                  }}
                />
                <span style={{ fontSize: 9, color: "#333", letterSpacing: 0 }}>{h.toString().padStart(2, "0")}</span>
              </div>
            ))}
          </div>
          <div style={{ display: "flex", gap: 8, marginTop: 10, alignItems: "center" }}>
            <span style={{ fontSize: 10, color: "#333" }}>Low</span>
            {["#1a2a18", "#3a3010", "#5a3010", "#7c2020"].map((c) => (
              <div key={c} style={{ width: 16, height: 10, background: c, borderRadius: 2 }} />
            ))}
            <span style={{ fontSize: 10, color: "#333" }}>High</span>
          </div>
        </div>
      )}

      {/* Charts row 1 */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
        <BarChart
          title="HTTP Methods"
          labels={topMethods.map((m) => m.label)}
          values={topMethods.map((m) => m.count)}
          color="#808080"
        />
        <PieChart
          title="Status Code Classes"
          labels={Object.keys(statusMap)}
          values={Object.keys(statusMap).map((k) => statusMap[k])}
          colors={Object.keys(statusMap).map((k) => (statusColors as Record<string, string>)[k] ?? "#555")}
        />
      </div>

      {/* Bot vs Human */}
      <div style={{ marginBottom: 24 }}>
        <PieChart
          title="Bot vs Human"
          labels={["Human", "Bot"]}
          values={[logs.length - bots, bots]}
          colors={["#4488ff", "#f0c040"]}
          height={180}
        />
      </div>

      {/* Response Size Distribution */}
      {hasSizes && (
        <div style={{ marginBottom: 24 }}>
          <BarChart
            title="Response Size Distribution — request count by response body size"
            labels={["< 1 KB", "1–10 KB", "10–50 KB", "50–100 KB", "100 KB–1 MB", "> 1 MB"]}
            values={sizeBuckets}
            color="#4a5a6a"
          />
        </div>
      )}

      <Divider />

      {/* Top Paths */}
      {topPaths.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <BarChart
            title="Top Requested Paths"
            labels={topPaths.map((p) => p.label.length > 40 ? p.label.slice(0, 40) + "…" : p.label)}
            values={topPaths.map((p) => p.count)}
            color="#606060"
            horizontal
          />
        </div>
      )}

      {/* Top IPs */}
      {topIPs.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <BarChart
            title="Top Source IPs"
            labels={topIPs.map((p) => p.label)}
            values={topIPs.map((p) => p.count)}
            color="#484848"
            horizontal
          />
        </div>
      )}

      <Divider />

      {/* Top User-Agents */}
      {topUAs.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
            Top User-Agent Strings
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #1e1e1e" }}>
                <th style={{ textAlign: "left", color: "#444", padding: "5px 8px", fontSize: 10, letterSpacing: 0.8, textTransform: "uppercase" }}>User-Agent</th>
                <th style={{ textAlign: "right", color: "#444", padding: "5px 8px", fontSize: 10, letterSpacing: 0.8, textTransform: "uppercase" }}>Requests</th>
              </tr>
            </thead>
            <tbody>
              {topUAs.map((ua, i) => (
                <tr key={i} style={{ borderBottom: "1px solid #0f0f0f" }}>
                  <td style={{ padding: "6px 8px", color: "#808080", fontSize: 11, maxWidth: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                    title={ua.label}>
                    {ua.label || "—"}
                  </td>
                  <td style={{ padding: "6px 8px", color: "#555", textAlign: "right", fontFamily: "monospace", fontSize: 11 }}>
                    {ua.count.toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Top Paths Detail Table */}
      {topPaths.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
            Top Paths Detail
          </div>
          <DataTable
            columns={["Path", "Requests"]}
            rows={topPaths.map((p) => [p.label, p.count.toLocaleString()])}
          />
        </div>
      )}
    </div>
  );
}
