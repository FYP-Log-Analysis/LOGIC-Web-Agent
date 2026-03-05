"use client";

import { useEffect, useState } from "react";
import { getRuleMatches, getNormalizedLogs, getCRSMatches, getCRSStats } from "@/lib/client";
import {
  SectionHeader,
  MetricCard,
  Tabs,
  SearchInput,
  SelectInput,
  Divider,
  Spinner,
  DataTable,
} from "@/components/ui-primitives";
import BarChart from "@/components/charts/bar-chart";
import PieChart from "@/components/charts/pie-chart";
import ScatterChart from "@/components/charts/scatter-chart";
import HawkinsChat from "@/components/hawkins-chat";

// ─── Types ────────────────────────────────────────────────────────────────────

interface RuleMatch {
  rule_id?: string;
  rule_name?: string;
  severity?: string;
  ip?: string;
  method?: string;
  path?: string;
  status?: number | string;
  timestamp?: string;
  anomaly_score?: number;
}

interface LogEntry {
  ip?: string;
  method?: string;
  status?: number | string;
  path?: string;
  is_bot?: boolean;
  timestamp?: string;
}

interface CRSMatch {
  rule_id?: string;
  severity?: string;
  ip?: string;
  timestamp?: string;
  anomaly_score?: number;
  paranoia_level?: number;
  description?: string;
}

interface CRSStats {
  total?: number;
  by_severity?: Record<string, number>;
  avg_anomaly_score?: number;
  max_anomaly_score?: number;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEV_ORDER = ["critical", "high", "medium", "low", "unknown"];
const SEV_COLORS: Record<string, string> = {
  critical: "#ff4444", high: "#ff8800", medium: "#f0c040", low: "#4488ff", unknown: "#555",
};

function countBy<T>(arr: T[], key: (item: T) => string): Record<string, number> {
  return arr.reduce<Record<string, number>>((acc, item) => {
    const k = key(item) ?? "unknown";
    acc[k] = (acc[k] ?? 0) + 1;
    return acc;
  }, {});
}

function topN(map: Record<string, number>, n: number): { label: string; count: number }[] {
  return Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, n).map(([label, count]) => ({ label, count }));
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function OverviewCharts({ matches, logs, crsStats }: { matches: RuleMatch[]; logs: LogEntry[]; crsStats: CRSStats }) {
  const sevCounts = countBy(matches, (m) => (m.severity ?? "unknown").toLowerCase());
  const ruleCounts = countBy(matches, (m) => m.rule_name ?? m.rule_id ?? "unknown");
  const ipCounts = countBy(matches, (m) => m.ip ?? "unknown");
  const methodCounts = countBy(logs, (l) => l.method ?? "unknown");
  const statusCounts = countBy(logs, (l) => {
    const s = Number(l.status ?? 0);
    if (s >= 500) return "5xx"; if (s >= 400) return "4xx";
    if (s >= 300) return "3xx"; if (s >= 200) return "2xx"; return "other";
  });
  const pathCounts = countBy(matches, (m) => m.path ?? "unknown");
  const botCount = logs.filter((l) => l.is_bot).length;

  const topRules = topN(ruleCounts, 8);
  const topIPs = topN(ipCounts, 8);
  const topPaths = topN(pathCounts, 8);

  const orderedSev = SEV_ORDER.filter((s) => sevCounts[s] != null);

  return (
    <div>
      {/* Row 1: Severity + top rules */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
        <BarChart
          title="Alerts by Severity"
          labels={orderedSev}
          values={orderedSev.map((s) => sevCounts[s] ?? 0)}
          color="#808080"
        />
        <BarChart
          title="Top Triggered Rules"
          labels={topRules.map((r) => r.label.length > 35 ? r.label.slice(0, 35) + "…" : r.label)}
          values={topRules.map((r) => r.count)}
          color="#606060"
          horizontal
        />
      </div>

      {/* Row 2: top IPs + HTTP methods */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
        <BarChart
          title="Top Source IPs"
          labels={topIPs.map((i) => i.label)}
          values={topIPs.map((i) => i.count)}
          color="#484848"
          horizontal
        />
        <PieChart
          title="HTTP Methods"
          labels={Object.keys(methodCounts)}
          values={Object.values(methodCounts)}
          colors={Object.keys(methodCounts).map((_, i) => ["#808080","#606060","#484848","#343434","#282828"][i % 5])}
        />
      </div>

      {/* Row 3: status classes + top paths + bot/human */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
        <PieChart
          title="Status Code Classes"
          labels={Object.keys(statusCounts)}
          values={Object.values(statusCounts)}
          colors={Object.keys(statusCounts).map((k) => ({ "2xx": "#4caf50", "3xx": "#4488ff", "4xx": "#f0c040", "5xx": "#ff4444", other: "#555" } as Record<string, string>)[k] ?? "#555")}
        />
        <PieChart
          title="Bot vs Human"
          labels={["Human", "Bot"]}
          values={[logs.length - botCount, botCount]}
          colors={["#4488ff", "#f0c040"]}
        />
      </div>

      {topPaths.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <BarChart
            title="Top Flagged Paths"
            labels={topPaths.map((p) => p.label.length > 45 ? p.label.slice(0, 45) + "…" : p.label)}
            values={topPaths.map((p) => p.count)}
            color="#383838"
            horizontal
          />
        </div>
      )}

      {/* CRS anomaly scatter */}
      {crsStats.total != null && crsStats.total > 0 && (
        <div style={{ marginTop: 8, marginBottom: 8, fontSize: 12, color: "#555" }}>
          CRS: {crsStats.total.toLocaleString()} matches · avg score {crsStats.avg_anomaly_score?.toFixed(1) ?? "—"} · max {crsStats.max_anomaly_score?.toFixed(1) ?? "—"}
        </div>
      )}
    </div>
  );
}

function ThreatTable({ matches }: { matches: RuleMatch[] }) {
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [methodFilter, setMethodFilter] = useState("");

  const severities = [...new Set(matches.map((m) => (m.severity ?? "unknown").toLowerCase()))].sort();
  const methods = [...new Set(matches.map((m) => m.method ?? "").filter(Boolean))].sort();

  const filtered = matches.filter((m) => {
    const sev = (m.severity ?? "").toLowerCase();
    if (sevFilter && sev !== sevFilter) return false;
    if (methodFilter && (m.method ?? "") !== methodFilter) return false;
    if (search) {
      const s = search.toLowerCase();
      return (
        (m.rule_name ?? m.rule_id ?? "").toLowerCase().includes(s) ||
        (m.ip ?? "").toLowerCase().includes(s) ||
        (m.path ?? "").toLowerCase().includes(s)
      );
    }
    return true;
  });

  return (
    <div>
      <div style={{ display: "flex", gap: 10, marginBottom: 14 }}>
        <SearchInput value={search} onChange={setSearch} placeholder="Search rule, IP, path…" />
        <SelectInput
          value={sevFilter}
          onChange={setSevFilter}
          options={[{ value: "", label: "All Severities" }, ...severities.map((s) => ({ value: s, label: s.toUpperCase() }))]}
        />
        {methods.length > 0 && (
          <SelectInput
            value={methodFilter}
            onChange={setMethodFilter}
            options={[{ value: "", label: "All Methods" }, ...methods.map((m) => ({ value: m, label: m }))]}
          />
        )}
        <div style={{ fontSize: 11, color: "#444", alignSelf: "center", whiteSpace: "nowrap" }}>
          {filtered.length.toLocaleString()} / {matches.length.toLocaleString()}
        </div>
      </div>

      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
        <thead>
          <tr style={{ borderBottom: "1px solid #1e1e1e" }}>
            {["Severity", "Rule", "IP", "Method", "Path", "Status", "Time"].map((h) => (
              <th key={h} style={{ textAlign: "left", color: "#444", padding: "6px 8px", fontSize: 10, letterSpacing: 0.8, textTransform: "uppercase" }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {filtered.slice(0, 200).map((m, i) => {
            const sev = (m.severity ?? "unknown").toLowerCase();
            const c = SEV_COLORS[sev] ?? "#555";
            return (
              <tr key={i} style={{ borderBottom: "1px solid #0f0f0f" }}>
                <td style={{ padding: "6px 8px" }}>
                  <span style={{ color: c, fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5 }}>{m.severity ?? "—"}</span>
                </td>
                <td style={{ padding: "6px 8px", color: "#c0c0c0", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {m.rule_name ?? m.rule_id ?? "—"}
                </td>
                <td style={{ padding: "6px 8px", color: "#808080", fontFamily: "monospace" }}>{m.ip ?? "—"}</td>
                <td style={{ padding: "6px 8px", color: "#666" }}>{m.method ?? "—"}</td>
                <td style={{ padding: "6px 8px", color: "#555", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {m.path ?? "—"}
                </td>
                <td style={{ padding: "6px 8px", color: "#555" }}>{m.status ?? "—"}</td>
                <td style={{ padding: "6px 8px", color: "#333", whiteSpace: "nowrap" }}>
                  {m.timestamp ? new Date(m.timestamp).toLocaleTimeString() : "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {filtered.length > 200 && (
        <div style={{ color: "#444", fontSize: 11, marginTop: 6, textAlign: "center" }}>
          Showing 200 of {filtered.length.toLocaleString()} — refine search to narrow results
        </div>
      )}
    </div>
  );
}

function CRSDetails({ matches }: { matches: CRSMatch[] }) {
  const [paranoia, setParanoia] = useState("");
  const plLevels = [...new Set(matches.map((m) => String(m.paranoia_level ?? "")))].filter(Boolean).sort();

  const filtered = paranoia ? matches.filter((m) => String(m.paranoia_level) === paranoia) : matches;

  return (
    <div>
      <div style={{ display: "flex", gap: 10, marginBottom: 14, alignItems: "center" }}>
        <SelectInput
          value={paranoia}
          onChange={setParanoia}
          options={[{ value: "", label: "All Paranoia Levels" }, ...plLevels.map((p) => ({ value: p, label: `PL ${p}` }))]}
        />
        <div style={{ fontSize: 11, color: "#444" }}>{filtered.length.toLocaleString()} entries</div>
      </div>

      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
        <thead>
          <tr style={{ borderBottom: "1px solid #1e1e1e" }}>
            {["Severity", "Rule ID", "IP", "Anomaly Score", "PL", "Description", "Time"].map((h) => (
              <th key={h} style={{ textAlign: "left", color: "#444", padding: "6px 8px", fontSize: 10, letterSpacing: 0.8, textTransform: "uppercase" }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {filtered.slice(0, 200).map((m, i) => {
            const sev = (m.severity ?? "unknown").toLowerCase();
            const c = SEV_COLORS[sev] ?? "#555";
            const score = m.anomaly_score ?? 0;
            const scoreColor = score >= 20 ? "#ff4444" : score >= 10 ? "#ff8800" : score >= 5 ? "#f0c040" : "#808080";
            return (
              <tr key={i} style={{ borderBottom: "1px solid #0f0f0f" }}>
                <td style={{ padding: "6px 8px" }}>
                  <span style={{ color: c, fontSize: 10, textTransform: "uppercase" }}>{m.severity ?? "—"}</span>
                </td>
                <td style={{ padding: "6px 8px", color: "#808080", fontFamily: "monospace" }}>{m.rule_id ?? "—"}</td>
                <td style={{ padding: "6px 8px", color: "#808080", fontFamily: "monospace" }}>{m.ip ?? "—"}</td>
                <td style={{ padding: "6px 8px" }}>
                  <span style={{ color: scoreColor }}>{score.toFixed(1)}</span>
                </td>
                <td style={{ padding: "6px 8px", color: "#444" }}>{m.paranoia_level ?? "—"}</td>
                <td style={{ padding: "6px 8px", color: "#555", maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {m.description ?? "—"}
                </td>
                <td style={{ padding: "6px 8px", color: "#333", whiteSpace: "nowrap" }}>
                  {m.timestamp ? new Date(m.timestamp).toLocaleTimeString() : "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function DetectionsPage() {
  const [matches, setMatches] = useState<RuleMatch[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [crsMatches, setCrsMatches] = useState<CRSMatch[]>([]);
  const [crsStats, setCrsStats] = useState<CRSStats>({});
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState("Overview Charts");

  useEffect(() => {
    Promise.all([
      getRuleMatches().then((d) => { const raw = d as unknown as {matches?: RuleMatch[]}; setMatches(raw.matches ?? []); }).catch(() => {}),
      getNormalizedLogs().then((d: LogEntry[]) => setLogs(Array.isArray(d) ? d : [])).catch(() => {}),
      getCRSMatches().then((d: CRSMatch[]) => setCrsMatches(Array.isArray(d) ? d : [])).catch(() => {}),
      getCRSStats().then((d: CRSStats) => setCrsStats(d ?? {})).catch(() => {}),
    ]).finally(() => setLoading(false));
  }, []);

  if (loading) return <div style={{ textAlign: "center", padding: 60 }}><Spinner size={28} /></div>;

  const sevCounts = countBy(matches, (m) => (m.severity ?? "unknown").toLowerCase());
  const uniqueRules = new Set(matches.map((m) => m.rule_id ?? m.rule_name)).size;

  return (
    <div>
      <SectionHeader
        title="Detected Threats"
        subtitle="Rule-based detection results — alerts, OWASP CRS audit log, and threat detail"
      />

      {/* Top metrics */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 24 }}>
        <MetricCard label="Total Alerts" value={matches.length.toLocaleString()} />
        <MetricCard label="Unique Rules" value={uniqueRules.toLocaleString()} />
        <MetricCard label="Critical" value={(sevCounts.critical ?? 0).toLocaleString()} accent="#ff4444" />
        <MetricCard label="High" value={(sevCounts.high ?? 0).toLocaleString()} accent="#ff8800" />
      </div>

      <Tabs
        tabs={["Overview Charts", "Detected Threats", "CRS Audit Log"]}
        active={tab}
        onChange={setTab}
      />

      {tab === "Overview Charts" && (
        <OverviewCharts matches={matches} logs={logs} crsStats={crsStats} />
      )}

      {tab === "Detected Threats" && (
        <ThreatTable matches={matches} />
      )}

      {tab === "CRS Audit Log" && (
        <CRSDetails matches={crsMatches} />
      )}

      <div style={{ marginTop: 40 }}>
        <HawkinsChat
          title="Hawkins — Detections"
          description="Ask about specific threats, attack patterns, or suspicious IPs"
          dataSummary={`${matches.length} rule matches, ${uniqueRules} unique rules, ${sevCounts.critical ?? 0} critical`}
          componentKey="detections"
          helpGuide="Try: 'Which IPs are most suspicious?' or 'Explain the SQL injection alerts'"
        />
      </div>
    </div>
  );
}
