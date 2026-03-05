"use client";

import { useEffect, useState } from "react";
import { uploadFile, getUploadStatus } from "@/lib/client";

const STAGES = [
  { key: "uploading", label: "Uploading" },
  { key: "parsing", label: "Parsing" },
  { key: "normalizing", label: "Normalizing" },
  { key: "saved", label: "Saved to Database" },
];

function stageIndex(stage: string) {
  if (stage === "error") return -1;
  return STAGES.findIndex((s) => s.key === stage);
}

interface StepperProps {
  currentStage: string;
  currentStatus: string;
  entryCount: number;
}

function Stepper({ currentStage, currentStatus, entryCount }: StepperProps) {
  const idx = stageIndex(currentStage);
  const isError = currentStage === "error";
  const isDone = currentStage === "saved" && currentStatus === "complete";

  return (
    <div>
      <div style={{ display: "flex", gap: 0 }}>
        {STAGES.map((s, i) => {
          let icon = "○";
          let color = "#333";
          let labelColor = "#555";

          if (isError && currentStage === s.key) { icon = "✗"; color = "#ff4444"; labelColor = "#ff4444"; }
          else if (isDone || i < idx) { icon = "✓"; color = "#e0e0e0"; labelColor = "#e0e0e0"; }
          else if (i === idx && currentStatus === "running") { icon = "◌"; color = "#888"; labelColor = "#ccc"; }
          else if (i === idx) { icon = "✓"; color = "#e0e0e0"; labelColor = "#e0e0e0"; }

          return (
            <div key={s.key} style={{ flex: 1, textAlign: "center", padding: "12px 4px" }}>
              <div style={{ fontSize: 26, color, fontWeight: 300 }}>{icon}</div>
              <div style={{ fontSize: 11, color: labelColor, marginTop: 6, letterSpacing: 0.8, textTransform: "uppercase" }}>
                {s.label}
              </div>
            </div>
          );
        })}
      </div>
      <div style={{ height: 1, background: "#222", margin: "0 0 12px 0" }} />
      {isDone ? (
        <div style={{ textAlign: "center", color: "#b0b0b0", fontSize: 13 }}>
          {entryCount.toLocaleString()} log entries stored — ready for analysis
        </div>
      ) : isError ? (
        <div style={{ textAlign: "center", color: "#ff4444", fontSize: 13 }}>
          Processing error — check API logs
        </div>
      ) : (
        <div style={{ textAlign: "center", color: "#666", fontSize: 13 }}>
          {STAGES.find((s) => s.key === currentStage)?.label ?? currentStage}…
        </div>
      )}
    </div>
  );
}

interface UploadStepperProps {
  projectId?: string;
  onComplete?: () => void;
}

export default function UploadStepper({ projectId, onComplete }: UploadStepperProps) {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [stage, setStage] = useState("idle");
  const [status, setStatus] = useState("idle");
  const [entryCount, setEntryCount] = useState(0);
  const [error, setError] = useState("");
  const [dragOver, setDragOver] = useState(false);

  const handleFile = (f: File) => { setFile(f); setStage("idle"); setStatus("idle"); setError(""); };

  const startUpload = async () => {
    if (!file) return;
    setUploading(true);
    setStage("uploading");
    setStatus("running");
    setError("");

    try {
      const result = await uploadFile(file, projectId);
      const uploadId = result.upload_id;
      if (!uploadId) throw new Error("No upload_id returned");

      // Poll until complete
      while (true) {
        const s = await getUploadStatus(uploadId);
        setStage(s.stage ?? "uploading");
        setStatus(s.status ?? "running");
        setEntryCount(s.entry_count ?? 0);

        if (s.stage === "saved" && s.status === "complete") {
          onComplete?.();
          break;
        }
        if (s.stage === "error") {
          setError(s.error ?? "Upload failed");
          break;
        }
        await new Promise((r) => setTimeout(r, 1000));
      }
    } catch (e) {
      setError(String(e));
      setStage("error");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div>
      {/* Drop zone */}
      {!uploading && stage === "idle" && (
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
          style={{
            border: `1px dashed ${dragOver ? "#808080" : "#2a2a2a"}`,
            borderRadius: 4,
            padding: "32px 20px",
            textAlign: "center",
            cursor: "pointer",
            background: dragOver ? "#111" : "#0d0d0d",
            marginBottom: 12,
            transition: "all 0.15s",
          }}
          onClick={() => document.getElementById("upload-file-input")?.click()}
        >
          <input
            id="upload-file-input"
            type="file"
            accept=".log,.txt,.gz,.json,.access,.error"
            style={{ display: "none" }}
            onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
          />
          {file ? (
            <div style={{ color: "#c0c0c0", fontSize: 13 }}>
              <span style={{ color: "#e0e0e0" }}>{file.name}</span>
              <span style={{ color: "#555", marginLeft: 8, fontSize: 11 }}>
                ({(file.size / 1024).toFixed(1)} KB)
              </span>
            </div>
          ) : (
            <div style={{ color: "#444", fontSize: 13, letterSpacing: 0.5 }}>
              Drag & drop a log file here, or click to browse
            </div>
          )}
        </div>
      )}

      {file && !uploading && stage === "idle" && (
        <button
          onClick={startUpload}
          style={{
            background: "#111", border: "1px solid #404040", color: "#c0c0c0",
            borderRadius: 2, fontSize: 11, letterSpacing: 1, textTransform: "uppercase",
            padding: "8px 20px", fontFamily: "inherit", cursor: "pointer",
          }}
        >
          Upload & Process
        </button>
      )}

      {(uploading || stage !== "idle") && stage !== "error" && (
        <Stepper currentStage={stage} currentStatus={status} entryCount={entryCount} />
      )}

      {error && (
        <div style={{ color: "#cc4444", fontSize: 12, marginTop: 8 }}>{error}</div>
      )}

      {stage === "saved" && status === "complete" && (
        <button
          onClick={() => { setFile(null); setStage("idle"); setStatus("idle"); }}
          style={{
            marginTop: 12, background: "transparent", border: "1px solid #333",
            color: "#555", fontSize: 10, letterSpacing: 1, padding: "6px 12px",
            borderRadius: 2, cursor: "pointer", fontFamily: "inherit",
          }}
        >
          UPLOAD ANOTHER
        </button>
      )}
    </div>
  );
}
