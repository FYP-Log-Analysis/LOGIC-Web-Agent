"use client";

import { useEffect, useState } from "react";
import { getBehavioralResults, runBehavioralAnalysis } from "@/lib/client";
import {
  SectionHeader,
  MetricCard,
  Btn,
  Tabs,
  StatusBadge,
  Divider,
  TextInput,
  Spinner,
} from "@/components/ui-primitives";
import BarChart from "@/components/charts/bar-chart";
import ScatterChart from "@/components/charts/scatter-chart";
import LineChart from "@/components/charts/line-chart";
import HawkinsChat from "@/components/hawkins-chat";

// ─── Types ────────────────────────────────────────────────────────────────────

interface RateSpike { ip?: string; client_ip?: string; window?: string; count?: number; rate?: number; is_anomaly?: boolean; timestamp?: string; }
interface UrlEnum { ip?: string; client_ip?: string; unique_paths?: number; is_anomaly?: boolean; paths?: string[]; }
interface StatusSpike { window?: string; status?: number | string; count?: number; rate?: number; is_anomaly?: boolean; timestamp?: string; }
interface VisitorRate { ip?: string; window?: string; requests?: number; mean?: number; is_anomaly?: boolean; timestamp?: string; }

interface BehavioralData {
  request_rate_spikes?: RateSpike[];
  url_enumeration?: UrlEnum[];
  status_code_spikes?: StatusSpike[];
  visitor_rates?: VisitorRate[];
  summary?: {
    total_rate_spikes?: number;
    total_url_enumerators?: number;
    total_status_spikes?: number;
    analysis_window?: string;
  };
}

interface Thresholds {
  rate_spike_threshold?: string;
  url_enum_threshold?: string;
  status_spike_threshold?: string;
  window_seconds?: string;
}

// ─── Tab 1: Rate Spikes ───────────────────────────────────────────────────────

function RateSpikesTab({ data }: { data: RateSpike[] }) {
  const anomalies = data.filter((d) => d.is_anomaly);
  const topIPs: { label: string; count: number }[] = Object.entries(
    data.reduce<Record<string, number>>((acc, r) => { acc[r.ip ?? "?"] = (acc[r.ip ?? "?"] ?? 0) + (r.count ?? 0); return acc; }, {})
  ).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([label, count]) => ({ label, count }));

  const scatterAll = data.map((r) => ({ x: r.count ?? 0, y: r.rate ?? 0 }));
  const scatterAnomaly = anomalies.map((r) => ({ x: r.count ?? 0, y: r.rate ?? 0 }));

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: 18 }}>
        <MetricCard label="Rate Spikes" value={data.length.toLocaleString()} />
        <MetricCard label="Anomalies" value={anomalies.length.toLocaleString()} accent="#ff8800" />
        <MetricCard label="Unique IPs" value={new Set(data.map((d) => d.ip)).size.toLocaleString()} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <BarChart
          title="Top IPs by Request Count"
          labels={topIPs.map((i) => i.label)}
          values={topIPs.map((i) => i.count)}
          color="#808080"
          horizontal
        />
        <ScatterChart
          title="Request Count vs Rate"
          datasets={[
            { label: "Normal", data: scatterAll.filter((_, i) => !data[i]?.is_anomaly), color: "#444" },
            { label: "Anomaly", data: scatterAnomaly, color: "#ff8800" },
          ]}
          xLabel="Count"
          yLabel="Rate"
        />
      </div>
    </div>
  );
}

// ─── Tab 2: URL Enumeration ───────────────────────────────────────────────────

function UrlEnumTab({ data }: { data: UrlEnum[] }) {
  const anomalies = data.filter((d) => d.is_anomaly);
  const sorted = [...data].sort((a, b) => (b.unique_paths ?? 0) - (a.unique_paths ?? 0)).slice(0, 10);

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: 18 }}>
        <MetricCard label="Enumerators" value={data.length.toLocaleString()} />
        <MetricCard label="Flagged" value={anomalies.length.toLocaleString()} accent="#ff4444" />
        <MetricCard label="Max Paths" value={(Math.max(...data.map((d) => d.unique_paths ?? 0), 0)).toLocaleString()} />
      </div>

      <BarChart
        title="Top IPs by Unique Paths"
        labels={sorted.map((s) => s.ip ?? "?")}
        values={sorted.map((s) => s.unique_paths ?? 0)}
        color="#808080"
        horizontal
      />

      {anomalies.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>
            Flagged Enumerators
          </div>
          {anomalies.slice(0, 20).map((a, i) => (
            <div key={i} style={{ borderBottom: "1px solid #111", padding: "8px 0", display: "flex", gap: 16 }}>
              <span style={{ color: "#ff4444", fontFamily: "monospace", fontSize: 12 }}>{a.ip}</span>
              <span style={{ color: "#808080", fontSize: 12 }}>{a.unique_paths} unique paths</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Tab 3: Status Spikes ─────────────────────────────────────────────────────

function StatusSpikesTab({ data }: { data: StatusSpike[] }) {
  const anomalies = data.filter((d) => d.is_anomaly);

  // Build time-series per status code
  const statusMap: Record<string, { t: string; c: number }[]> = {};
  for (const s of data) {
    const key = String(s.status ?? "?");
    if (!statusMap[key]) statusMap[key] = [];
    statusMap[key].push({ t: s.timestamp ?? s.window ?? "", c: s.count ?? 0 });
  }

  const allTimes = [...new Set(data.map((d) => d.timestamp ?? d.window ?? ""))].sort().slice(0, 50);
  const statusColors: Record<string, string> = { "200": "#4caf50", "400": "#f0c040", "404": "#ff8800", "500": "#ff4444", "503": "#cc4444" };

  const datasets = Object.entries(statusMap).slice(0, 5).map(([status, pts]) => {
    const values = allTimes.map((t) => pts.find((p) => p.t === t)?.c ?? 0);
    return {
      label: status,
      data: values,
      color: statusColors[status] ?? "#808080",
      fill: false,
    };
  });

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: 18 }}>
        <MetricCard label="Status Spikes" value={data.length.toLocaleString()} />
        <MetricCard label="Anomalies" value={anomalies.length.toLocaleString()} accent="#ff4444" />
        <MetricCard label="Codes Seen" value={Object.keys(statusMap).length.toLocaleString()} />
      </div>

      <LineChart
        title="Status Code Rates Over Time"
        labels={allTimes.map((t) => new Date(t).toLocaleTimeString() || t)}
        datasets={datasets}
        yLabel="Count"
      />
    </div>
  );
}

// ─── Tab 4: Visitor Rates ─────────────────────────────────────────────────────

function VisitorRatesTab({ data }: { data: VisitorRate[] }) {
  const anomalies = data.filter((d) => d.is_anomaly);
  const topIPs = [...new Set(data.map((d) => d.ip))].slice(0, 5);

  const allTimes = [...new Set(data.map((d) => d.timestamp ?? d.window ?? ""))].sort().slice(0, 50);
  const ipColors = ["#4488ff", "#ff8800", "#f0c040", "#4caf50", "#ff4444"];

  const datasets = topIPs.map((ip, idx) => {
    const pts = data.filter((d) => d.ip === ip);
    const values = allTimes.map((t) => pts.find((d) => (d.timestamp ?? d.window) === t)?.requests ?? 0);
    return { label: ip ?? "?", data: values, color: ipColors[idx] ?? "#808080", fill: false };
  });

  const meanLine = allTimes.map((t) => {
    const pts = data.filter((d) => (d.timestamp ?? d.window) === t);
    return pts.length ? pts[0].mean ?? 0 : 0;
  });
  const avgMean = data.length ? data.reduce((s, d) => s + (d.mean ?? 0), 0) / data.length : 0;

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: 18 }}>
        <MetricCard label="Visitor Events" value={data.length.toLocaleString()} />
        <MetricCard label="Anomalies" value={anomalies.length.toLocaleString()} accent="#f0c040" />
        <MetricCard label="Avg Mean Rate" value={avgMean.toFixed(1)} />
      </div>

      <LineChart
        title="Request Rates by IP"
        labels={allTimes.map((t) => new Date(t).toLocaleTimeString() || t)}
        datasets={datasets}
        yLabel="Requests"
        threshold={avgMean > 0 ? avgMean : undefined}
        thresholdLabel="Mean"
      />
    </div>
  );
}

// ─── IP Risk Leaderboard ──────────────────────────────────────────────────────

function IpRiskLeaderboard({ data }: { data: BehavioralData }) {
  type IpScore = { rateSpike: number; urlEnum: number; visitorAnomaly: number; score: number };
  const scores: Record<string, IpScore> = {};

  (data.request_rate_spikes ?? []).forEach((r: RateSpike) => {
    const ip = r.ip ?? r.client_ip ?? "?";
    if (!scores[ip]) scores[ip] = { rateSpike: 0, urlEnum: 0, visitorAnomaly: 0, score: 0 };
    scores[ip].rateSpike++;
    scores[ip].score += 3;
  });
  (data.url_enumeration ?? []).forEach((u: UrlEnum) => {
    const ip = u.ip ?? u.client_ip ?? "?";
    if (!scores[ip]) scores[ip] = { rateSpike: 0, urlEnum: 0, visitorAnomaly: 0, score: 0 };
    scores[ip].urlEnum++;
    scores[ip].score += 2;
  });
  (data.visitor_rates ?? []).filter((v: VisitorRate) => v.is_anomaly).forEach((v: VisitorRate) => {
    const ip = v.ip ?? "?";
    if (ip === "?" || !ip) return;
    if (!scores[ip]) scores[ip] = { rateSpike: 0, urlEnum: 0, visitorAnomaly: 0, score: 0 };
    scores[ip].visitorAnomaly++;
    scores[ip].score += 1;
  });

  const top10 = Object.entries(scores)
    .sort((a, b) => b[1].score - a[1].score)
    .slice(0, 10)
    .filter(([, s]) => s.score > 0);

  if (top10.length === 0) return null;

  return (
    <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 20, marginBottom: 24 }}>
      <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 14 }}>
        IP Risk Leaderboard — cross-category behavioral threat scoring
      </div>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
        <thead>
          <tr style={{ borderBottom: "1px solid #1e1e1e" }}>
            {["#", "IP Address", "Risk Score", "Rate Spike", "URL Enum", "Visitor Anomaly"].map((h) => (
              <th key={h} style={{ textAlign: "left", color: "#444", padding: "5px 8px", fontSize: 10, letterSpacing: 0.8, textTransform: "uppercase" }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {top10.map(([ip, s], i) => (
            <tr key={i} style={{ borderBottom: "1px solid #0f0f0f" }}>
              <td style={{ padding: "7px 8px", color: "#333", fontSize: 10 }}>{i + 1}</td>
              <td style={{ padding: "7px 8px", color: "#c0c0c0", fontFamily: "monospace", fontSize: 11 }}>{ip}</td>
              <td style={{ padding: "7px 8px" }}>
                <span style={{
                  color: s.score >= 10 ? "#ff4444" : s.score >= 5 ? "#ff8800" : "#f0c040",
                  fontSize: 13, fontWeight: 600,
                }}>
                  {s.score}
                </span>
              </td>
              <td style={{ padding: "7px 8px" }}>
                {s.rateSpike > 0
                  ? <span style={{ color: "#ff8800", fontSize: 11 }}>● {s.rateSpike}x</span>
                  : <span style={{ color: "#333" }}>—</span>}
              </td>
              <td style={{ padding: "7px 8px" }}>
                {s.urlEnum > 0
                  ? <span style={{ color: "#ff4444", fontSize: 11 }}>● {s.urlEnum}x</span>
                  : <span style={{ color: "#333" }}>—</span>}
              </td>
              <td style={{ padding: "7px 8px" }}>
                {s.visitorAnomaly > 0
                  ? <span style={{ color: "#f0c040", fontSize: 11 }}>● {s.visitorAnomaly}x</span>
                  : <span style={{ color: "#333" }}>—</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ fontSize: 10, color: "#333", marginTop: 10 }}>
        Score: Rate Spike = 3pts · URL Enum = 2pts · Visitor Anomaly = 1pt
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function BehavioralPage() {
  const [data, setData] = useState<BehavioralData | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [tab, setTab] = useState("Rate Spikes");
  const [showSettings, setShowSettings] = useState(false);
  const [thresholds, setThresholds] = useState<Thresholds>({});

  const load = async () => {
    try {
      const d = await getBehavioralResults();
      setData((d as unknown as BehavioralData) ?? {});
    } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const handleRun = async () => {
    setRunning(true);
    try {
      const params: Record<string, number> = {};
      if (thresholds.rate_spike_threshold) params.rate_spike_threshold = Number(thresholds.rate_spike_threshold);
      if (thresholds.url_enum_threshold) params.url_enum_threshold = Number(thresholds.url_enum_threshold);
      if (thresholds.status_spike_threshold) params.status_spike_threshold = Number(thresholds.status_spike_threshold);
      if (thresholds.window_seconds) params.window_seconds = Number(thresholds.window_seconds);

      const d = await runBehavioralAnalysis(Object.keys(params).length > 0 ? params : undefined);
      setData((d as unknown as BehavioralData) ?? {});
    } catch {}
    setRunning(false);
  };

  const summary = data?.summary;

  return (
    <div>
      <SectionHeader
        title="Behavioral Analysis"
        subtitle="Anomaly detection across request rate spikes, URL enumeration, status spikes, and visitor patterns"
      />

      {/* Controls */}
      <div style={{ display: "flex", gap: 10, marginBottom: 16, alignItems: "center" }}>
        <Btn onClick={handleRun} disabled={running}>
          {running ? <><Spinner size={12} />&nbsp;&nbsp;RUNNING…</> : "RUN ANALYSIS"}
        </Btn>
        <Btn variant="ghost" onClick={() => setShowSettings(!showSettings)}>
          {showSettings ? "HIDE SETTINGS" : "SETTINGS"}
        </Btn>
      </div>

      {showSettings && (
        <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 16, marginBottom: 20 }}>
          <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 12 }}>
            Threshold Settings
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <TextInput
              label="Rate Spike Threshold"
              value={thresholds.rate_spike_threshold ?? ""}
              onValueChange={(v) => setThresholds((t) => ({ ...t, rate_spike_threshold: v }))}
              placeholder="e.g. 100"
            />
            <TextInput
              label="URL Enum Threshold"
              value={thresholds.url_enum_threshold ?? ""}
              onValueChange={(v) => setThresholds((t) => ({ ...t, url_enum_threshold: v }))}
              placeholder="e.g. 50"
            />
            <TextInput
              label="Status Spike Threshold"
              value={thresholds.status_spike_threshold ?? ""}
              onValueChange={(v) => setThresholds((t) => ({ ...t, status_spike_threshold: v }))}
              placeholder="e.g. 10"
            />
            <TextInput
              label="Window (seconds)"
              value={thresholds.window_seconds ?? ""}
              onValueChange={(v) => setThresholds((t) => ({ ...t, window_seconds: v }))}
              placeholder="e.g. 60"
            />
          </div>
        </div>
      )}

      {loading ? (
        <div style={{ textAlign: "center", padding: 60 }}><Spinner size={28} /></div>
      ) : !data ? (
        <div style={{ color: "#444", fontSize: 13, padding: "24px 0" }}>
          No behavioral data — run analysis first
        </div>
      ) : (
        <>
          {/* Summary metrics */}
          {summary && (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 20 }}>
              <MetricCard label="Rate Spikes" value={(summary.total_rate_spikes ?? 0).toLocaleString()} accent="#ff8800" />
              <MetricCard label="URL Enumerators" value={(summary.total_url_enumerators ?? 0).toLocaleString()} accent="#ff4444" />
              <MetricCard label="Status Spikes" value={(summary.total_status_spikes ?? 0).toLocaleString()} accent="#f0c040" />
              <MetricCard label="Window" value={summary.analysis_window ?? "—"} />
            </div>
          )}

          <IpRiskLeaderboard data={data} />

          <Tabs
            tabs={["Rate Spikes", "URL Enumeration", "Status Spikes", "Visitor Rates"]}
            active={tab}
            onChange={setTab}
          />

          {tab === "Rate Spikes" && <RateSpikesTab data={data.request_rate_spikes ?? []} />}
          {tab === "URL Enumeration" && <UrlEnumTab data={data.url_enumeration ?? []} />}
          {tab === "Status Spikes" && <StatusSpikesTab data={data.status_code_spikes ?? []} />}
          {tab === "Visitor Rates" && <VisitorRatesTab data={data.visitor_rates ?? []} />}
        </>
      )}

      <div style={{ marginTop: 40 }}>
        <HawkinsChat
          title="Hawkins — Behavioral"
          description="Ask about rate spikes, URL scanning activity, or anomalous visitor patterns"
          dataSummary={summary ? `${summary.total_rate_spikes} rate spikes, ${summary.total_url_enumerators} URL enumerators, ${summary.total_status_spikes} status spikes` : "No behavioral data"}
          componentKey="behavioral"
          helpGuide="Try: 'Which IPs are scanning for URLs?' or 'Describe the rate spike anomalies'"
        />
      </div>
    </div>
  );
}
