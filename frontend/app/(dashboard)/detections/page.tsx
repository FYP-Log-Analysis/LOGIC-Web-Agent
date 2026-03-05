"use client";

import { useEffect, useState } from "react";
import { getRuleMatches, getNormalizedLogs } from "@/lib/client";
import {
  SectionHeader,
  MetricCard,
  Tabs,
  SearchInput,
  SelectInput,
  Spinner,
} from "@/components/ui-primitives";
import BarChart from "@/components/charts/bar-chart";
import PieChart from "@/components/charts/pie-chart";
import HawkinsChat from "@/components/hawkins-chat";

// ─── Types ────────────────────────────────────────────────────────────────────

interface RuleMatch {
  rule_id?: string;
  rule_title?: string;
  severity?: string;
  client_ip?: string;
  method?: string;
  path?: string;
  status_code?: number | string;
  timestamp?: string;
}

interface LogEntry {
  ip?: string;
  method?: string;
  status?: number | string;
  path?: string;
  is_bot?: boolean;
  timestamp?: string;
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

function OverviewCharts({ matches, logs }: { matches: RuleMatch[]; logs: LogEntry[] }) {
  const sevCounts = countBy(matches, (m) => (m.severity ?? "unknown").toLowerCase());
  const ruleCounts = countBy(matches, (m) => m.rule_title ?? m.rule_id ?? "Unknown Rule");
  const ipCounts = countBy(matches, (m) => m.client_ip ?? "unknown");
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
  const sevLabels = orderedSev.map((s) => `${s.toUpperCase()} (${sevCounts[s]})`);
  const sevColors = orderedSev.map((s) => SEV_COLORS[s] ?? "#555");
  const statusOrdered = ["2xx", "3xx", "4xx", "5xx", "other"] as const;
  const statusLabelMap: Record<string, string> = { "2xx": "2xx Success", "3xx": "3xx Redirect", "4xx": "4xx Client Error", "5xx": "5xx Server Error", other: "Other" };
  const statusColorMap: Record<string, string> = { "2xx": "#4caf50", "3xx": "#4488ff", "4xx": "#f0c040", "5xx": "#ff4444", other: "#555" };
  const statusFiltered = statusOrdered.filter((k) => (statusCounts[k] ?? 0) > 0);

  return (
    <div>
      {/* Row 1: Severity (coloured) + top rules */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
        <BarChart
          title="Alerts by Severity — total rule-match count per severity level"
          labels={sevLabels}
          values={orderedSev.map((s) => sevCounts[s] ?? 0)}
          color={sevColors}
          height={240}
        />
        <BarChart
          title="Top Triggered Rules — number of log entries matched per rule"
          labels={topRules.map((r) => r.label.length > 38 ? r.label.slice(0, 38) + "…" : r.label)}
          values={topRules.map((r) => r.count)}
          color="#5a5a9a"
          horizontal
          height={240}
        />
      </div>

      {/* Row 2: top IPs + HTTP methods */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
        <BarChart
          title="Top Offending IPs — source IPs with the most rule matches"
          labels={topIPs.map((i) => i.label)}
          values={topIPs.map((i) => i.count)}
          color="#7a4a4a"
          horizontal
          height={240}
        />
        <PieChart
          title="HTTP Method Distribution — breakdown of request methods across all log entries"
          labels={Object.keys(methodCounts)}
          values={Object.values(methodCounts)}
          colors={["#5a7a9a", "#4a6a8a", "#3a5a7a", "#2a4a6a", "#1a3a5a"]}
        />
      </div>

      {/* Row 3: status classes + bot/human */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
        <PieChart
          title="Response Status Classes — HTTP status code groups from all log entries"
          labels={statusFiltered.map((k) => statusLabelMap[k])}
          values={statusFiltered.map((k) => statusCounts[k])}
          colors={statusFiltered.map((k) => statusColorMap[k])}
        />
        <PieChart
          title="Bot vs Human Traffic — automated scrapers vs browser requests"
          labels={["Human Requests", "Automated Bots"]}
          values={[logs.length - botCount, botCount]}
          colors={["#4488ff", "#f0c040"]}
        />
      </div>

      {topPaths.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <BarChart
            title="Most Targeted Paths — URL paths that triggered the most detection rules"
            labels={topPaths.map((p) => p.label.length > 50 ? "…" + p.label.slice(-47) : p.label)}
            values={topPaths.map((p) => p.count)}
            color="#4a7a4a"
            horizontal
            height={280}
          />
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
        (m.rule_title ?? m.rule_id ?? "").toLowerCase().includes(s) ||
        (m.client_ip ?? "").toLowerCase().includes(s) ||
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
                <td style={{ padding: "6px 8px", color: "#c0c0c0", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                  title={m.rule_title ?? m.rule_id ?? ""}>
                  {m.rule_title ?? m.rule_id ?? "—"}
                </td>
                <td style={{ padding: "6px 8px", color: "#808080", fontFamily: "monospace", fontSize: 11 }}>{m.client_ip ?? "—"}</td>
                <td style={{ padding: "6px 8px", color: "#666", fontFamily: "monospace", fontSize: 11 }}>{m.method ?? "—"}</td>
                <td style={{ padding: "6px 8px", color: "#555", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                  title={m.path ?? ""}>
                  {m.path ?? "—"}
                </td>
                <td style={{ padding: "6px 8px", fontFamily: "monospace", fontSize: 11 }}>
                  <span style={{ color: Number(m.status_code ?? 0) >= 500 ? "#ff4444" : Number(m.status_code ?? 0) >= 400 ? "#f0c040" : Number(m.status_code ?? 0) >= 200 ? "#4caf50" : "#555" }}>
                    {m.status_code ?? "—"}
                  </span>
                </td>
                <td style={{ padding: "6px 8px", color: "#444", whiteSpace: "nowrap", fontSize: 11 }}>
                  {m.timestamp ? new Date(m.timestamp).toLocaleString() : "—"}
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

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function DetectionsPage() {
  const [matches, setMatches] = useState<RuleMatch[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState("Overview Charts");

  useEffect(() => {
    Promise.allSettled([
      getRuleMatches().then((d) => setMatches(d.matches as RuleMatch[])),
      getNormalizedLogs().then((d: LogEntry[]) => setLogs(Array.isArray(d) ? d : [])),
    ]).finally(() => setLoading(false));
  }, []);

  if (loading) return <div style={{ textAlign: "center", padding: 60 }}><Spinner size={28} /></div>;

  const sevCounts = countBy(matches, (m) => (m.severity ?? "unknown").toLowerCase());
  const uniqueRules = new Set(matches.map((m) => m.rule_id ?? m.rule_title)).size;

  return (
    <div>
      <SectionHeader
        title="Detected Threats"
        subtitle="Rule-based detection results — matched alerts, source IP analysis, and request detail"
      />

      {/* Top metrics */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 24 }}>
        <MetricCard label="Total Alerts" value={matches.length.toLocaleString()} />
        <MetricCard label="Unique Rules" value={uniqueRules.toLocaleString()} />
        <MetricCard label="Critical" value={(sevCounts.critical ?? 0).toLocaleString()} accent="#ff4444" />
        <MetricCard label="High" value={(sevCounts.high ?? 0).toLocaleString()} accent="#ff8800" />
      </div>

      <Tabs
        tabs={["Overview Charts", "Detected Threats"]}
        active={tab}
        onChange={setTab}
      />

      {tab === "Overview Charts" && <OverviewCharts matches={matches} logs={logs} />}
      {tab === "Detected Threats" && <ThreatTable matches={matches} />}

      <div style={{ marginTop: 40 }}>
        <HawkinsChat
          title="Hawkins — Detections"
          description="Ask about specific threats, attack patterns, or suspicious IPs"
          dataSummary={`${matches.length} rule matches across ${uniqueRules} unique rules. Critical: ${sevCounts.critical ?? 0}, High: ${sevCounts.high ?? 0}.`}
          componentKey="detections"
          helpGuide="Try: 'Which IPs are most suspicious?' or 'Explain the SQL injection alerts'"
        />
      </div>
    </div>
  );
}
