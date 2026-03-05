"use client";

import { useEffect, useState } from "react";
import { getNormalizedLogs } from "@/lib/client";
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

export default function LogStatisticsPage() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getNormalizedLogs().then((d: LogEntry[]) => setLogs(Array.isArray(d) ? d : [])).catch(() => {}).finally(() => setLoading(false));
  }, []);

  if (loading) return <div style={{ textAlign: "center", padding: 60 }}><Spinner size={28} /></div>;

  // Aggregate
  const methodMap: Record<string, number> = {};
  const statusMap: Record<string, number> = {};
  const ipMap: Record<string, number> = {};
  const pathMap: Record<string, number> = {};
  let bots = 0;
  const seenIps = new Set<string>();

  for (const l of logs) {
    if (l.method) methodMap[l.method] = (methodMap[l.method] ?? 0) + 1;
    const sc = statusClass(l.status ?? 0);
    statusMap[sc] = (statusMap[sc] ?? 0) + 1;
    if (l.ip) { ipMap[l.ip] = (ipMap[l.ip] ?? 0) + 1; seenIps.add(l.ip); }
    if (l.path) pathMap[l.path] = (pathMap[l.path] ?? 0) + 1;
    if (l.is_bot) bots++;
  }

  const topMethods = topN(methodMap, 6);
  const topPaths = topN(pathMap, 8);
  const topIPs = topN(ipMap, 8);

  const statusColors = { "2xx": "#4caf50", "3xx": "#4488ff", "4xx": "#f0c040", "5xx": "#ff4444", other: "#555" };
  const methodColors = ["#808080", "#606060", "#484848", "#343434", "#282828", "#1e1e1e"];

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

      {/* Table: top paths */}
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
