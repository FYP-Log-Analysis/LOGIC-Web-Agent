"use client";

import { useEffect, useState, useRef } from "react";
import { getThreatInsights, getInsightsStatus } from "@/lib/client";
import {
  SectionHeader,
  Btn,
  StatusBadge,
  Divider,
  Spinner,
  AlertBanner,
} from "@/components/ui-primitives";
import HawkinsChat from "@/components/hawkins-chat";

interface InsightsStatus {
  status?: string;
  ready?: boolean;
  generated_at?: string;
}

interface InsightsData {
  status?: string;
  narrative?: string;
  summary?: string;
  threats?: { title?: string; description?: string; severity?: string }[];
  recommendations?: string[];
  generated_at?: string;
}

export default function AiInsightsPage() {
  const [generating, setGenerating] = useState(false);
  const [polling, setPolling] = useState(false);
  const [insightsStatus, setInsightsStatus] = useState<InsightsStatus | null>(null);
  const [insights, setInsights] = useState<InsightsData | null>(null);
  const [error, setError] = useState("");
  const pollingRef = useRef(false);

  useEffect(() => {
    // Check if insights exist
    getInsightsStatus()
      .then((s) => {
        const status = s as unknown as InsightsStatus;
        setInsightsStatus(status);
        if (status.ready || status.status === "complete") {
          fetchInsights();
        }
      })
      .catch(() => {});
  }, []);

  const fetchInsights = async () => {
    try {
      const data = await getThreatInsights();
      setInsights(data as unknown as InsightsData);
    } catch {}
  };

  const pollStatus = async () => {
    pollingRef.current = true;
    setPolling(true);
    while (pollingRef.current) {
      try {
        const s = await getInsightsStatus();
        const status = s as unknown as InsightsStatus;
        setInsightsStatus(status);
        if (status.ready || status.status === "complete") {
          await fetchInsights();
          break;
        }
        if (status.status === "failed" || status.status === "error") {
          setError("Insight generation failed — check API logs");
          break;
        }
      } catch { break; }
      await new Promise((r) => setTimeout(r, 2000));
    }
    pollingRef.current = false;
    setPolling(false);
  };

  const handleGenerate = async () => {
    setGenerating(true); setError("");
    try {
      await getThreatInsights(); // triggers generation
      await pollStatus();
    } catch (e) { setError(String(e)); }
    setGenerating(false);
  };

  const sevColor: Record<string, string> = {
    critical: "#ff4444", high: "#ff8800", medium: "#f0c040", low: "#4488ff",
  };

  const isReady = insights && (insights.narrative || insights.summary || (insights.threats && insights.threats.length > 0));
  const statusLabel: "running" | "complete" | undefined =
    polling ? "running" : isReady ? "complete" : undefined;

  return (
    <div>
      <SectionHeader
        title="AI Insights"
        subtitle="LLM-generated threat narrative and actionable recommendations"
      />

      <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 24 }}>
        <Btn onClick={handleGenerate} disabled={generating || polling}>
          {generating || polling ? <><Spinner size={12} />&nbsp;&nbsp;GENERATING…</> : "GENERATE INSIGHTS"}
        </Btn>
        {statusLabel && <StatusBadge status={statusLabel} />}
        {insightsStatus?.generated_at && !polling && (
          <span style={{ fontSize: 11, color: "#444" }}>
            Last generated: {new Date(insightsStatus.generated_at).toLocaleString()}
          </span>
        )}
      </div>

      {error && <AlertBanner type="error" message={error} />}

      {isReady && (
        <>
          <Divider />

          {/* Narrative / Summary */}
          {(insights.narrative || insights.summary) && (
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
                Threat Narrative
              </div>
              <div style={{
                background: "#0d0d0d",
                border: "1px solid #1e1e1e",
                borderRadius: 4,
                padding: 16,
                color: "#c0c0c0",
                fontSize: 13,
                lineHeight: 1.75,
                whiteSpace: "pre-wrap",
              }}>
                {insights.narrative ?? insights.summary}
              </div>
            </div>
          )}

          {/* Individual threats */}
          {insights.threats && insights.threats.length > 0 && (
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
                Identified Threats
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {insights.threats.map((t, i) => {
                  const sev = (t.severity ?? "low").toLowerCase();
                  const c = sevColor[sev] ?? "#555";
                  return (
                    <div key={i} style={{
                      background: "#0d0d0d", border: `1px solid ${c}22`,
                      borderLeft: `3px solid ${c}`, borderRadius: 4, padding: "12px 14px",
                    }}>
                      <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 6 }}>
                        <span style={{ color: c, fontSize: 10, letterSpacing: 1, textTransform: "uppercase" }}>
                          {t.severity?.toUpperCase() ?? "—"}
                        </span>
                        {t.title && <span style={{ color: "#e0e0e0", fontSize: 13 }}>{t.title}</span>}
                      </div>
                      {t.description && (
                        <div style={{ color: "#808080", fontSize: 12, lineHeight: 1.6 }}>{t.description}</div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {insights.recommendations && insights.recommendations.length > 0 && (
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
                Recommendations
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {insights.recommendations.map((r, i) => (
                  <div key={i} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                    <span style={{ color: "#404040", fontSize: 12, marginTop: 2 }}>{i + 1}.</span>
                    <span style={{ color: "#c0c0c0", fontSize: 13, lineHeight: 1.6 }}>{r}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {!isReady && !polling && !generating && (
        <div style={{ color: "#333", fontSize: 13, padding: "24px 0" }}>
          No insights generated yet — click Generate Insights to analyse current detection data
        </div>
      )}

      <div style={{ marginTop: 40 }}>
        <HawkinsChat
          title="Hawkins — AI Insights"
          description="Ask Hawkins to elaborate on threats, explain patterns, or suggest mitigations"
          dataSummary={isReady ? (insights.summary ?? insights.narrative ?? "Insights available") : "No insights yet"}
          componentKey="ai_insights"
          helpGuide="Try: 'What is the most critical threat?' or 'Explain the SQL injection findings'"
        />
      </div>
    </div>
  );
}
