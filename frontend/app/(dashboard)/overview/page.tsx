"use client";

import { useEffect, useState } from "react";
import { getGeoSummary, getRuleMatches, getNormalizedLogs, type GeoCountrySummary } from "@/lib/client";
import { SectionHeader, MetricCard, AlertBanner, Divider, ApiStatusLine } from "@/components/ui-primitives";
import BarChart from "@/components/charts/bar-chart";
import LineChart from "@/components/charts/line-chart";
import { SEV_COLORS } from "@/components/charts/setup";
import HawkinsChat from "@/components/hawkins-chat";
import { apiHealth } from "@/lib/api";
import WorldChoropleth from "@/components/charts/world-choropleth";

type RuleMatch = {
  rule_id?: string;
  rule_title?: string;
  severity?: string;
  client_ip?: string;
  method?: string;
  path?: string;
  timestamp?: string;
  status_code?: number | string;
};

export default function OverviewPage() {
  const [matches, setMatches] = useState<RuleMatch[]>([]);
  const [geoSummary, setGeoSummary] = useState<{
    countries_impacted: number;
    total_detections: number;
    geolocated_detections: number;
    unknown_detections: number;
    coverage_pct: number;
    backfilled_ip_count: number;
    top_source_country: GeoCountrySummary | null;
    countries: GeoCountrySummary[];
    top_countries: GeoCountrySummary[];
  } | null>(null);
  const [totalEvents, setTotalEvents] = useState(0);
  const [totalMatches, setTotalMatches] = useState(0);
  const [uniqueRules, setUniqueRules] = useState(0);
  const [healthy, setHealthy] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([getRuleMatches(), getNormalizedLogs(), apiHealth(), getGeoSummary()]).then(
      ([ruleResult, logsResult, healthResult, geoResult]) => {
        if (healthResult.status === "fulfilled") setHealthy(healthResult.value);
        if (ruleResult.status === "fulfilled") {
          const ruleData = ruleResult.value;
          setMatches(ruleData.matches ?? []);
          setTotalMatches(ruleData.total_matches ?? 0);
          setUniqueRules((ruleData.matched_rules ?? []).length);
        }
        if (logsResult.status === "fulfilled") setTotalEvents(logsResult.value.length);
        if (geoResult.status === "fulfilled") setGeoSummary(geoResult.value);
        setLoading(false);
      }
    );
  }, []);

  const highCritical = matches.filter((m) =>
    ["critical", "high"].includes((m.severity ?? "").toLowerCase())
  );

  // Severity chart
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

  // Top IPs chart
  const ipCounts: Record<string, number> = {};
  matches.forEach((m) => {
    if (m.client_ip) ipCounts[m.client_ip] = (ipCounts[m.client_ip] ?? 0) + 1;
  });
  const topIps = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);

  // Top rules chart
  const ruleCounts: Record<string, number> = {};
  matches.forEach((m) => {
    const key = m.rule_title ?? m.rule_id ?? "Unknown Rule";
    ruleCounts[key] = (ruleCounts[key] ?? 0) + 1;
  });
  const topRules = Object.entries(ruleCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);

  // ── Attack Timeline (group by hour, split by severity) ──────────────────────
  const hourlyBySev: Record<string, Record<string, number>> = {};
  matches.forEach((m) => {
    if (!m.timestamp) return;
    const hour = m.timestamp.slice(0, 13); // "2026-02-22T06"
    const sev = (m.severity ?? "unknown").toLowerCase();
    if (!hourlyBySev[hour]) hourlyBySev[hour] = {};
    hourlyBySev[hour][sev] = (hourlyBySev[hour][sev] ?? 0) + 1;
  });
  const timelineHours = Object.keys(hourlyBySev).sort().slice(-24);
  const timelineLabels = timelineHours.map((h) =>
    new Date(h + ":00:00Z").toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  );
  const timelineSevColors: Record<string, string> = {
    critical: "#ff4444", high: "#ff8800", medium: "#f0c040", low: "#4488ff",
  };
  const timelineDatasets = ["critical", "high", "medium", "low"].map((sev) => ({
    label: sev.charAt(0).toUpperCase() + sev.slice(1),
    data: timelineHours.map((h) => hourlyBySev[h]?.[sev] ?? 0),
    color: timelineSevColors[sev],
    fill: false,
  }));

  // ── Threat Velocity (last active hour vs prior hour) ─────────────────────────
  const sortedHours = Object.keys(hourlyBySev).sort();
  let velocityText = "—";
  let velocityAccent = "#555";
  if (sortedHours.length >= 2) {
    const last = sortedHours[sortedHours.length - 1];
    const prev = sortedHours[sortedHours.length - 2];
    const lastCount = Object.values(hourlyBySev[last] ?? {}).reduce((a, b) => a + b, 0);
    const prevCount = Object.values(hourlyBySev[prev] ?? {}).reduce((a, b) => a + b, 0);
    if (prevCount > 0) {
      const pct = Math.round(((lastCount - prevCount) / prevCount) * 100);
      velocityText = pct >= 0 ? `+${pct}%` : `${pct}%`;
      velocityAccent = pct > 50 ? "#ff4444" : pct > 0 ? "#ff8800" : "#4caf50";
    }
  }

  // ── Attack Success Rate (matches where server returned 2xx) ──────────────────
  const successHits = matches.filter((m) => [200, 201, 204].includes(Number(m.status_code ?? -1)));
  const successRate = matches.length > 0 ? Math.round((successHits.length / matches.length) * 100) : 0;
  const successAccent = successRate > 20 ? "#ff4444" : successRate > 5 ? "#ff8800" : "#4caf50";

  // Sorted recent alerts
  const sortedAlerts = [...highCritical].sort((a, b) =>
    (b.timestamp ?? "").localeCompare(a.timestamp ?? "")
  );

  const hawkinsData = {
    total_log_entries: totalEvents,
    total_rule_matches: totalMatches,
    unique_rules_triggered: uniqueRules,
    high_critical_alert_count: highCritical.length,
    attack_success_rate_pct: successRate,
    threat_velocity: velocityText,
    countries_impacted: geoSummary?.countries_impacted ?? 0,
    geolocated_detection_coverage_pct: geoSummary?.coverage_pct ?? 0,
    top_source_country: geoSummary?.top_source_country?.country_name ?? "Unknown",
  };

  const geoTopCountry = geoSummary?.top_source_country;
  const geoCountries = geoSummary?.countries ?? [];
  const geoTopCountries = geoSummary?.top_countries ?? [];

  return (
    <div>
      <SectionHeader
        title="OVERVIEW"
        subtitle="Security posture at a glance — latest detection results across all analysis engines."
      />
      <ApiStatusLine healthy={healthy} />

      {/* KPI Row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: 12, marginBottom: 24 }}>
        <MetricCard label="Log Entries" value={totalEvents} />
        <MetricCard label="Rule Matches" value={totalMatches} />
        <MetricCard label="Unique Rules" value={uniqueRules} />
        <MetricCard
          label="Attack Success Rate"
          value={`${successRate}%`}
          sub={`${successHits.length} hits returned 2xx`}
          accent={successAccent}
        />
        <MetricCard
          label="Threat Velocity"
          value={velocityText}
          sub="vs previous hour bucket"
          accent={velocityAccent}
        />
        <MetricCard
          label="Countries Impacted"
          value={geoSummary?.countries_impacted ?? 0}
          sub={`${geoSummary?.geolocated_detections ?? 0} mapped detections`}
          accent="#f59e0b"
        />
        <MetricCard
          label="Top Source Country"
          value={geoTopCountry?.country_code ?? "--"}
          sub={geoTopCountry ? `${geoTopCountry.country_name} · ${geoTopCountry.detection_count} hits` : "No public IP matches yet"}
          accent="#f97316"
        />
        <MetricCard
          label="Geo Coverage"
          value={`${geoSummary?.coverage_pct ?? 0}%`}
          sub={`${geoSummary?.unknown_detections ?? 0} detections unresolved/private`}
          accent="#eab308"
        />
      </div>

      <Divider />

      {/* Geographic view */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 11, letterSpacing: 1.5, textTransform: "uppercase", color: "#f59e0b", marginBottom: 12 }}>
          Global Threat Surface
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 24 }}>
          <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 20 }}>
            <div style={{ fontSize: 12, color: "#777", marginBottom: 12 }}>
              Country-level distribution of detections resolved from the bundled GeoLite country database.
            </div>
            <WorldChoropleth countries={geoCountries} />
          </div>
          <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 20 }}>
            <div style={{ fontSize: 11, letterSpacing: 1.2, textTransform: "uppercase", color: "#e8e8e8", marginBottom: 14 }}>
              Top Affected Countries
            </div>
            {geoTopCountries.length ? (
              <div style={{ display: "grid", gap: 10 }}>
                {geoTopCountries.map((country) => (
                  <div
                    key={country.country_code}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "56px minmax(0, 1fr) auto",
                      alignItems: "center",
                      gap: 12,
                      padding: "10px 12px",
                      background: "linear-gradient(90deg, rgba(217,119,6,0.08), rgba(13,13,13,0.7))",
                      border: "1px solid #272727",
                      borderRadius: 4,
                    }}
                  >
                    <div style={{ fontSize: 18, fontWeight: 300, color: "#f59e0b" }}>{country.country_code}</div>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ color: "#e8e8e8", fontSize: 13, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {country.country_name}
                      </div>
                      <div style={{ color: "#555", fontSize: 11, marginTop: 2 }}>
                        Critical {country.critical_count} · High {country.high_count} · Unique IPs {country.unique_ips}
                      </div>
                    </div>
                    <div style={{ color: "#f8fafc", fontSize: 18, fontWeight: 300 }}>{country.detection_count}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ color: "#555", fontSize: 12, border: "1px dashed #2a2a2a", borderRadius: 4, padding: 20 }}>
                No country-level detections available yet. Upload logs and run analysis to populate the map.
              </div>
            )}
            {geoSummary?.backfilled_ip_count ? (
              <div style={{ color: "#444", fontSize: 10, marginTop: 12 }}>
                Geo cache refreshed for {geoSummary.backfilled_ip_count} previously unseen IPs.
              </div>
            ) : null}
          </div>
        </div>
      </div>

      <Divider />

      {/* Attack Timeline */}
      {timelineHours.length > 1 && (
        <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 20, marginBottom: 24 }}>
          <LineChart
            title="Attack Timeline — detections per hour grouped by severity"
            labels={timelineLabels}
            datasets={timelineDatasets}
            yLabel="Detections"
            height={260}
          />
        </div>
      )}

      {/* High/Critical feed */}
      {sortedAlerts.length > 0 ? (
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 11, letterSpacing: 1.5, textTransform: "uppercase", color: "#cc4444", marginBottom: 12 }}>
            HIGH / CRITICAL ALERTS ({sortedAlerts.length})
          </div>
          {sortedAlerts.slice(0, 15).map((m, i) => (
            <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 10, marginBottom: 4 }}>
              {m.timestamp && (
                <span style={{ color: "#393939", fontSize: 10, fontFamily: "monospace", whiteSpace: "nowrap", paddingTop: 10 }}>
                  {new Date(m.timestamp).toLocaleString()}
                </span>
              )}
              <div style={{ flex: 1 }}>
                <AlertBanner match={m} />
              </div>
            </div>
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
                labels={topIps.map((x) => x[0])}
                values={topIps.map((x) => x[1])}
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
        helpGuide="The Security Overview is your starting point. KPI cards show log entries, rule matches, unique rules, attack success rate (2xx responses on matched requests), and threat velocity (% change in detections between the two most recent hourly buckets). The Attack Timeline shows per-hour detection volume split by severity. Navigate to Detections for full rule tables, Threat Actor for IP profiling, or Correlation for cross-module analysis."
      />
    </div>
  );
}
