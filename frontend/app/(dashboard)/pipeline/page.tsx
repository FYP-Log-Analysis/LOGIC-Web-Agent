"use client";

import { useEffect, useState } from "react";
import { getPipelineSteps, runPipeline, runPipelineStep } from "@/lib/client";
import { apiHealth } from "@/lib/api";
import {
  SectionHeader,
  Btn,
  StatusBadge,
  Divider,
  Spinner,
  AlertBanner,
  ApiStatusLine,
} from "@/components/ui-primitives";

type StepStatus = "idle" | "running" | "complete" | "failed" | "error" | "timeout";

interface PipelineStep {
  step_id: string;
  name: string;
  description?: string;
  status?: StepStatus;
  duration?: number;
  error?: string;
}

export default function PipelinePage() {
  const [steps, setSteps] = useState<PipelineStep[]>([]);
  const [apiUp, setApiUp] = useState<null | boolean>(null);
  const [running, setRunning] = useState(false);
  const [runningStep, setRunningStep] = useState<string | null>(null);
  const [error, setError] = useState("");

  const loadSteps = async () => {
    try {
      const data = await getPipelineSteps();
      const raw = (data as { steps?: Record<string, { name?: string; description?: string; order?: number }> }).steps ?? {};
      setSteps(
        Object.entries(raw).map(([step_id, s]) => ({
          step_id,
          name: s.name ?? step_id,
          description: s.description,
          status: "idle" as StepStatus,
        }))
      );
    } catch {}
  };

  useEffect(() => {
    loadSteps();
    apiHealth()
      .then(() => setApiUp(true))
      .catch(() => setApiUp(false));
  }, []);

  const updateStep = (id: string, patch: Partial<PipelineStep>) =>
    setSteps((prev) => prev.map((s) => (s.step_id === id ? { ...s, ...patch } : s)));

  const handleRunAll = async () => {
    setRunning(true); setError("");
    // Reset all statuses
    setSteps((prev) => prev.map((s) => ({ ...s, status: "idle" as StepStatus })));
    try {
      const result = await runPipeline();
      // Result may include per-step outcomes
      if (result?.results) {
        setSteps(result.results.map((r) => ({
          step_id: (r as { step_id?: string }).step_id ?? "",
          name: (r as { step_name?: string }).step_name ?? "",
          status: ((r as { status?: string }).status ?? "idle") as StepStatus,
          error: (r as { error?: string }).error,
        })));
      } else {
        await loadSteps();
      }
    } catch (e) { setError(String(e)); }
    setRunning(false);
  };

  const handleRunStep = async (stepId: string) => {
    setRunningStep(stepId);
    updateStep(stepId, { status: "running" });
    try {
      const result = await runPipelineStep(stepId);
      updateStep(stepId, {
        status: (result?.status ?? "complete") as StepStatus,
        error: result?.error,
      });
    } catch (e) {
      updateStep(stepId, { status: "error", error: String(e) });
    }
    setRunningStep(null);
  };

  const statusColor: Record<string, string> = {
    complete: "#4caf50", failed: "#ff4444", error: "#ff4444",
    running: "#f0c040", timeout: "#ff8800", idle: "#333",
  };

  return (
    <div>
      <SectionHeader
        title="Pipeline"
        subtitle="Execute the end-to-end log processing pipeline or run individual steps"
      />

      <ApiStatusLine up={apiUp} />

      {error && <AlertBanner type="error" message={error} />}

      <div style={{ display: "flex", gap: 12, marginBottom: 24, alignItems: "center" }}>
        <Btn onClick={handleRunAll} disabled={running}>
          {running ? <><Spinner size={12} />&nbsp;&nbsp;RUNNING PIPELINE…</> : "RUN FULL PIPELINE"}
        </Btn>
        {running && <StatusBadge status="running" />}
      </div>

      <Divider />

      {steps.length === 0 ? (
        <div style={{ textAlign: "center", padding: 40 }}><Spinner size={24} /></div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {steps.map((step, idx) => {
            const isRunning = runningStep === step.step_id;
            const st = step.status ?? "idle";
            return (
              <div key={step.step_id} style={{
                background: "#0d0d0d",
                border: `1px solid ${st === "complete" ? "#1a3a1a" : st === "error" || st === "failed" ? "#3a1a1a" : "#1e1e1e"}`,
                borderRadius: 4,
                padding: "12px 16px",
                display: "flex",
                alignItems: "center",
                gap: 14,
              }}>
                {/* Step number */}
                <div style={{
                  width: 26, height: 26, borderRadius: "50%",
                  background: statusColor[st] ?? "#1e1e1e",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 11, color: st === "idle" ? "#444" : "#000",
                  fontWeight: 600, flexShrink: 0,
                }}>
                  {st === "complete" ? "✓" : st === "error" || st === "failed" ? "✗" : idx + 1}
                </div>

                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ color: "#c0c0c0", fontSize: 13 }}>{step.name}</div>
                  {step.description && (
                    <div style={{ color: "#444", fontSize: 11, marginTop: 2 }}>{step.description}</div>
                  )}
                  {step.error && (
                    <div style={{ color: "#cc4444", fontSize: 11, marginTop: 4 }}>{step.error}</div>
                  )}
                  {step.duration != null && (
                    <div style={{ color: "#333", fontSize: 11, marginTop: 2 }}>
                      {step.duration.toFixed(2)}s
                    </div>
                  )}
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
                  {st !== "idle" && <StatusBadge status={st as "complete" | "failed" | "error" | "running" | "idle"} />}
                  <Btn
                    variant="ghost"
                    onClick={() => handleRunStep(step.step_id)}
                    disabled={running || isRunning}
                  >
                    {isRunning ? <Spinner size={10} /> : "RUN"}
                  </Btn>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
