"use client";

import { useEffect, useState } from "react";
import { getRuleMatches, getNormalizedLogs } from "@/lib/client";
import { SectionHeader, MetricCard, AlertBanner, Divider, ApiStatusLine } from "@/components/ui-primitives";
import BarChart from "@/components/charts/bar-chart";
import { SEV_COLORS } from "@/components/charts/setup";
import HawkinsChat from "@/components/hawkins-chat";
import { apiHealth } from "@/lib/api";

type RuleMatch = {
  rule_id?: string;
  rule_title?: string;
  severity?: string;
  client_ip?: string;
  method?: string;
  path?: string;
  timestamp?: string;
};

export default function OverviewPage() {
  const [matches, setMatches] = useState<RuleMatch[]>([]);
  const [totalEvents, setTotalEvents] = useState(0);
  const [totalMatches, setTotalMatches] = useState(0);
  const [uniqueRules, setUniqueRules] = useState(0);
  const [healthy, setHealthy] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([getRuleMatches(), getNormalizedLogs(), apiHealth()]).then(
      ([ruleResult, logsResult, healthResult]) => {
        if (healthResult.status === "fulfilled") setHealthy(healthResult.value);
        if (ruleResult.status === "fulfilled") {
          const ruleData = ruleResult.value;
          setMatches(ruleData.matches ?? []);
          setTotalMatches(ruleData.total_matches ?? 0);
          setUniqueRules((ruleData.matched_rules ?? []).length);
        }
        if (logsResult.status === "fulfilled") setTotalEvents(logsResult.value.length);
        setLoading(false);
      }
    );
  }, []);

  const highCritical = matches.filter((m) =>
    ["critical", "high"].includes((m.severity ?? "").toLowerCase())
  );

  // Build severity chart data — sorted by severity order, labels include counts
  const SEV_ORDER = ["critical", "high", "medium", "low", "unknown"];
  const sevCounts: Record<string, number> = {};
  matches.forEach((m) => {
    const s = (m.severity ?? "unknown").toLowerCase();
    sevCounts[s] = (sevCounts[s] ?? 0) + 1;
  });
  const sortedSev = SEV_ORDER.filter((s) => sevCounts[s] != null);
  const sevLabels = sortedSev.map((s) => `${s.toUpperCase()} (${sevCounts[s]})`);
  const sevValues = sortedSev.map((k) => sevCounts[k]);
  const sevColors = sortedSev.map((k) => SEV_COLORS[k] ?? "#555555");

  // Build top IPs chart
  const ipCounts: Record<string, number> = {};
  matches.forEach((m) => {
    if (m.client_ip) ipCounts[m.client_ip] = (ipCounts[m.client_ip] ?? 0) + 1;
  });
  const topIps = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);
  const ipLabels = topIps.map((x) => x[0]);
  const ipValues = topIps.map((x) => x[1]);

  // Build top rules chart
  const ruleCounts: Record<string, number> = {};
  matches.forEach((m) => {
    const key = m.rule_title ?? m.rule_id ?? "Unknown Rule";
    ruleCounts[key] = (ruleCounts[key] ?? 0) + 1;
  });
  const topRules = Object.entries(ruleCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);

  // Hawkins data summary
  const hawkinsData = {
    total_log_entries: totalEvents,
    total_rule_matches: totalMatches,
    unique_rules_triggered: uniqueRules,
    high_critical_alert_count: highCritical.length,
  };

  return (
    <div>
      <SectionHeader
        title="OVERVIEW"
        subtitle="Security posture at a glance — latest detection results across all analysis engines."
      />
      <ApiStatusLine healthy={healthy} />

      {/* Metrics */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, marginBottom: 24 }}>
        <MetricCard label="Log Entries" value={totalEvents} />
        <MetricCard label="Rule Matches" value={totalMatches} />
        <MetricCard label="Unique Rules" value={uniqueRules} />
      </div>

      <Divider />

      {/* High/Critical feed */}
      {highCritical.length > 0 ? (
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 11, letterSpacing: 1.5, textTransform: "uppercase", color: "#cc4444", marginBottom: 12 }}>
            HIGH / CRITICAL ALERTS ({highCritical.length})
          </div>
          {highCritical.slice(0, 15).map((m, i) => (
            <AlertBanner key={i} match={m} />
          ))}
        </div>
      ) : (
        !loading && (
          <div style={{ background: "#0a0f0a", border: "1px solid #1a3a1a", borderRadius: 4, padding: "16px 20px", color: "#2E8B57", fontSize: 13, marginBottom: 24 }}>
            No high or critical alerts detected in the last analysis run.
          </div>
        )
      )}

      <Divider />

      {/* Charts */}
      {matches.length > 0 && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24, marginBottom: 24 }}>
            <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 20 }}>
              <BarChart
                title="Alerts by Severity — rule-match count per severity level"
                labels={sevLabels}
                values={sevValues}
                color={sevColors}
                height={280}
              />
            </div>
            <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 20 }}>
              <BarChart
                title="Top Offending IPs — source IPs with the most matched alerts"
                labels={ipLabels}
                values={ipValues}
                horizontal
                color="#3a3a6a"
                height={280}
              />
            </div>
          </div>
          {topRules.length > 0 && (
            <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 20, marginBottom: 24 }}>
              <BarChart
                title="Top Triggered Rules — detection rules that matched the most log entries"
                labels={topRules.map(([label]) => label.length > 48 ? label.slice(0, 48) + "…" : label)}
                values={topRules.map(([, count]) => count)}
                color="#5a5a9a"
                horizontal
                height={topRules.length > 4 ? 320 : 220}
              />
            </div>
          )}
        </>
      )}

      <HawkinsChat
        title="Security Overview"
        description="High-level security posture dashboard — rule matches and high/critical alert feed from the last analysis run."
        dataSummary={hawkinsData}
        componentKey="overview"
        helpGuide="The Security Overview is your starting point. The three KPI cards show total log entries ingested, total rule matches, and number of unique rules triggered. The alert feed below highlights only HIGH and CRITICAL severity matches. Navigate to Detections for full rule tables, Behavioral Analysis for traffic-pattern threats, or AI Insights for LLM threat summaries."
      />
    </div>
  );
}
