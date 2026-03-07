"use client";

import { useEffect, useState, useCallback } from "react";
import { runAnalysis, getAnalysisRun, getLogTimeRange } from "@/lib/client";
import { useAuthStore } from "@/lib/store";
import {
  SectionHeader,
  MetricCard,
  Btn,
  StatusBadge,
  Divider,
  Spinner,
  AlertBanner,
} from "@/components/ui-primitives";
import HawkinsChat from "@/components/hawkins-chat";

interface TimeRange { start?: string; end?: string; total_logs?: number; }
interface RunResult {
  run_id?: string;
  status?: string;
  stats?: {
    total_logs?: number;
    flagged_logs?: number;
    rule_matches?: number;
    critical_count?: number;
    high_count?: number;
    medium_count?: number;
    low_count?: number;
    unique_ips?: number;
    unique_rules?: number;
    analysis_duration_seconds?: number;
  };
  top_threats?: { rule?: string; count?: number; severity?: string }[];
  error?: string;
}

export default function AnalysisPage() {
  const [timeRange, setTimeRange] = useState<TimeRange>({});
  const [running, setRunning] = useState(false);
  const [polling, setPolling] = useState(false);
  const [result, setResult] = useState<RunResult | null>(null);
  const [error, setError] = useState("");
  const { activeProject, timeRange: storeTimeRange } = useAuthStore();

  useEffect(() => {
    (getLogTimeRange(activeProject?.id) as Promise<TimeRange>).then((d) => setTimeRange(d)).catch(() => {});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeProject?.id]);

  const pollRun = useCallback(async (runId: string) => {
    setPolling(true);
    while (true) {
      try {
        const r = await getAnalysisRun(runId);
        setResult(r as RunResult);
        if (r.status === "complete" || r.status === "failed" || r.status === "error") break;
      } catch { break; }
      await new Promise((res) => setTimeout(res, 1500));
    }
    setPolling(false);
  }, []);

  const handleRun = async () => {
    setRunning(true); setError(""); setResult(null);
    try {
      const r = await runAnalysis({
        project_id: activeProject?.id,
        start_ts: storeTimeRange?.from,
        end_ts: storeTimeRange?.to,
      }) as unknown as RunResult;
      if (r.run_id) {
        setResult(r);
        await pollRun(r.run_id);
      } else {
        // synchronous result
        setResult(r);
      }
    } catch (e) { setError(String(e)); }
    setRunning(false);
  };

  const stats = result?.stats;
  const isComplete = result?.status === "complete" || (result && !result.status);
  const statusLabel: "running" | "complete" | "failed" | "error" | undefined =
    polling ? "running" : (result?.status as "complete" | "failed" | "error" | "running" | undefined) ?? undefined;

  return (
    <div>
      <SectionHeader
        title="Analysis"
        subtitle="Run rule-based detection analysis on ingested log data"
      />

      {/* Time range info */}
      {(timeRange.total_logs || timeRange.start) && (
        <div style={{ fontSize: 12, color: "#555", marginBottom: 20, display: "flex", gap: 20 }}>
          {timeRange.total_logs && (
            <span><span style={{ color: "#808080" }}>{timeRange.total_logs.toLocaleString()}</span> log entries loaded</span>
          )}
          {timeRange.start && (
            <span>From <span style={{ color: "#808080" }}>{new Date(timeRange.start).toLocaleDateString()}</span>
              {" to "}
              <span style={{ color: "#808080" }}>{timeRange.end ? new Date(timeRange.end).toLocaleDateString() : "now"}</span>
            </span>
          )}
        </div>
      )}

      {/* Run Button */}
      <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 24 }}>
        <Btn onClick={handleRun} disabled={running || polling}>
          {running || polling ? <><Spinner size={12} />&nbsp;&nbsp;{"RUNNING\u2026"}</> : "RUN ANALYSIS"}
        </Btn>
        {statusLabel && <StatusBadge status={statusLabel} />}
      </div>

      {error && <AlertBanner type="error" message={error} />}

      {/* Results */}
      {stats && isComplete && (
        <>
          <Divider />
          <div style={{ marginBottom: 18 }}>
            <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 12 }}>
              Run Summary
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
              <MetricCard label="Total Logs" value={(stats.total_logs ?? 0).toLocaleString()} />
              <MetricCard label="Flagged" value={(stats.flagged_logs ?? 0).toLocaleString()} />
              <MetricCard label="Rule Matches" value={(stats.rule_matches ?? 0).toLocaleString()} />
              <MetricCard label="Unique IPs" value={(stats.unique_ips ?? 0).toLocaleString()} />
            </div>
          </div>

          {/* Severity breakdown */}
          {(stats.critical_count || stats.high_count || stats.medium_count || stats.low_count) ? (
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
                Severity Breakdown
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
                <MetricCard label="Critical" value={(stats.critical_count ?? 0).toLocaleString()} accent="#ff4444" />
                <MetricCard label="High" value={(stats.high_count ?? 0).toLocaleString()} accent="#ff8800" />
                <MetricCard label="Medium" value={(stats.medium_count ?? 0).toLocaleString()} accent="#f0c040" />
                <MetricCard label="Low" value={(stats.low_count ?? 0).toLocaleString()} accent="#4488ff" />
              </div>
            </div>
          ) : null}

          {/* Duration */}
          {stats.analysis_duration_seconds != null && (
            <div style={{ fontSize: 12, color: "#444", marginBottom: 20 }}>
              Completed in {stats.analysis_duration_seconds.toFixed(2)}s
              {stats.unique_rules ? ` · ${stats.unique_rules} unique rules triggered` : ""}
            </div>
          )}

          {/* Top threats table */}
          {result.top_threats && result.top_threats.length > 0 && (
            <>
              <Divider />
              <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
                Top Triggered Rules
              </div>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #1e1e1e" }}>
                    {["Rule", "Severity", "Matches"].map((h) => (
                      <th key={h} style={{ textAlign: "left", color: "#444", padding: "6px 10px", fontSize: 10, letterSpacing: 0.8, textTransform: "uppercase" }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {result.top_threats.map((t, i) => {
                    const sev = (t.severity ?? "low").toLowerCase();
                    const sevColor: Record<string, string> = { critical: "#ff4444", high: "#ff8800", medium: "#f0c040", low: "#4488ff" };
                    return (
                      <tr key={i} style={{ borderBottom: "1px solid #111" }}>
                        <td style={{ padding: "7px 10px", color: "#c0c0c0" }}>{t.rule}</td>
                        <td style={{ padding: "7px 10px" }}>
                          <span style={{ color: sevColor[sev] ?? "#808080", fontSize: 11, textTransform: "uppercase", letterSpacing: 0.5 }}>
                            {t.severity}
                          </span>
                        </td>
                        <td style={{ padding: "7px 10px", color: "#808080" }}>{t.count?.toLocaleString()}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </>
          )}
        </>
      )}

      {result?.status === "failed" && (
        <AlertBanner type="error" message={result.error ?? "Analysis failed"} />
      )}

      <div style={{ marginTop: 40 }}>
        <HawkinsChat
          title="Hawkins — Analysis"
          description="Ask about rule detections, severity distribution, or threat patterns"
          dataSummary={stats ? `${stats.total_logs} logs, ${stats.flagged_logs} flagged, ${stats.rule_matches} rule matches` : "No analysis run yet"}
          componentKey="analysis"
          helpGuide="Try: 'Which rules triggered most often?' or 'Summarise the severity distribution'"
        />
      </div>
    </div>
  );
}
