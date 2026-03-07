"use client";

import { useEffect, useState, useCallback } from "react";
import { useAuthStore } from "@/lib/store";
import {
  getProjects,
  createProject,
  deleteProject,
  getProjectUploads,
  getLogTimeRange,
} from "@/lib/client";
import {
  SectionHeader,
  Btn,
  Badge,
  Divider,
  TextInput,
  Spinner,
} from "@/components/ui-primitives";
import UploadStepper from "@/components/upload-stepper";

interface Project {
  id: string;
  name?: string;
  description?: string;
  status?: string;
  last_run_at?: string;
}

interface UploadRecord {
  upload_id: string;
  filename?: string;
  stage?: string;
  status?: string;
  entry_count?: number;
  started_at?: string;
}

// ── Time-range modal ─────────────────────────────────────────────────────────

function TimeRangeModal({
  project,
  onConfirm,
  onCancel,
}: {
  project: Project;
  onConfirm: (from: string, to: string) => void;
  onCancel: () => void;
}) {
  const [loading, setLoading] = useState(true);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [minTs, setMinTs] = useState("");
  const [maxTs, setMaxTs] = useState("");

  useEffect(() => {
    getLogTimeRange(project.id)
      .then((d) => {
        const f = d.min_timestamp ?? "";
        const t = d.max_timestamp ?? "";
        setMinTs(f);
        setMaxTs(t);
        setFrom(f ? f.slice(0, 16) : "");
        setTo(t ? t.slice(0, 16) : "");
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [project.id]);

  const handleFullRange = () => {
    setFrom(minTs ? minTs.slice(0, 16) : "");
    setTo(maxTs ? maxTs.slice(0, 16) : "");
  };

  const handleConfirm = () => {
    if (from && to) onConfirm(from, to);
  };

  const overlayStyle: React.CSSProperties = {
    position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)",
    display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000,
  };
  const boxStyle: React.CSSProperties = {
    background: "#0d0d0d", border: "1px solid #2a2a2a", borderRadius: 6,
    padding: 28, width: 420, maxWidth: "92vw",
  };

  return (
    <div style={overlayStyle} onClick={onCancel}>
      <div style={boxStyle} onClick={(e) => e.stopPropagation()}>
        <div style={{ fontSize: 11, color: "#666", letterSpacing: 1, textTransform: "uppercase", marginBottom: 14 }}>
          Select Log Time Range
        </div>
        <div style={{ color: "#c0c0c0", fontSize: 13, marginBottom: 18 }}>
          {project.name}
        </div>
        {loading ? (
          <div style={{ textAlign: "center", padding: 24 }}><Spinner size={20} /></div>
        ) : (
          <>
            {minTs && (
              <div style={{ fontSize: 11, color: "#555", marginBottom: 12 }}>
                Log data available: {new Date(minTs).toLocaleString()} → {new Date(maxTs).toLocaleString()}
              </div>
            )}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 12 }}>
              <div>
                <div style={{ fontSize: 11, color: "#555", marginBottom: 4 }}>FROM</div>
                <input
                  type="datetime-local"
                  value={from}
                  onChange={(e) => setFrom(e.target.value)}
                  style={{
                    background: "#111", border: "1px solid #2a2a2a", color: "#c0c0c0",
                    padding: "6px 8px", fontSize: 12, borderRadius: 3, width: "100%",
                    colorScheme: "dark",
                  }}
                />
              </div>
              <div>
                <div style={{ fontSize: 11, color: "#555", marginBottom: 4 }}>TO</div>
                <input
                  type="datetime-local"
                  value={to}
                  onChange={(e) => setTo(e.target.value)}
                  style={{
                    background: "#111", border: "1px solid #2a2a2a", color: "#c0c0c0",
                    padding: "6px 8px", fontSize: 12, borderRadius: 3, width: "100%",
                    colorScheme: "dark",
                  }}
                />
              </div>
            </div>
            {minTs && (
              <Btn variant="ghost" onClick={handleFullRange} style={{ fontSize: 11, marginBottom: 16 }}>
                USE FULL RANGE
              </Btn>
            )}
            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <Btn variant="ghost" onClick={onCancel}>CANCEL</Btn>
              <Btn variant="default" onClick={handleConfirm} disabled={!from || !to}>
                CONFIRM
              </Btn>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ── Upload status badge helper ────────────────────────────────────────────────

function UploadStatusBadge({ stage, status }: { stage?: string; status?: string }) {
  if (stage === "saved" && status === "complete") return <Badge color="#4caf50">SAVED</Badge>;
  if (stage === "error" || status === "error") return <Badge color="#cc4444">ERROR</Badge>;
  if (stage === "normalizing") return <Badge color="#f0c040">NORMALIZING</Badge>;
  if (stage === "parsing") return <Badge color="#f0c040">PARSING</Badge>;
  if (stage === "uploading") return <Badge color="#4488ff">UPLOADING</Badge>;
  return <Badge color="#555">{(stage ?? status ?? "UNKNOWN").toUpperCase()}</Badge>;
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ProjectsPage() {
  const { activeProject, setActiveProject, setProjectSelectPending, setTimeRange } = useAuthStore();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [error, setError] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [expandedUploads, setExpandedUploads] = useState<Record<string, UploadRecord[]>>({});
  const [loadingUploads, setLoadingUploads] = useState<Record<string, boolean>>({});
  const [timeRangeFor, setTimeRangeFor] = useState<Project | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await getProjects();
      setProjects(data);
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const loadUploads = async (projectId: string) => {
    if (expandedUploads[projectId]) {
      // Toggle collapse
      setExpandedUploads((prev) => { const n = { ...prev }; delete n[projectId]; return n; });
      return;
    }
    setLoadingUploads((prev) => ({ ...prev, [projectId]: true }));
    try {
      const uploads = await getProjectUploads(projectId);
      setExpandedUploads((prev) => ({ ...prev, [projectId]: uploads }));
    } catch {}
    setLoadingUploads((prev) => ({ ...prev, [projectId]: false }));
  };

  const handleCreate = async () => {
    if (!newName.trim()) { setError("Project name required"); return; }
    setCreating(true); setError("");
    try {
      await createProject(newName.trim(), newDesc.trim());
      setNewName(""); setNewDesc(""); setShowCreate(false);
      await load();
    } catch (e) { setError(String(e)); }
    setCreating(false);
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this project and all associated data?")) return;
    try {
      await deleteProject(id);
      if (activeProject?.id === id) { setActiveProject(null); setTimeRange(null); }
      await load();
    } catch {}
  };

  const handleSetActive = (p: Project) => {
    // Open time-range modal first
    setTimeRangeFor(p);
  };

  const handleTimeRangeConfirm = (from: string, to: string) => {
    if (!timeRangeFor) return;
    setActiveProject({ id: timeRangeFor.id, name: timeRangeFor.name ?? timeRangeFor.id });
    setTimeRange({ from: new Date(from).toISOString(), to: new Date(to).toISOString() });
    setProjectSelectPending(false);
    setTimeRangeFor(null);
  };

  const handleDeactivate = () => {
    setActiveProject(null);
    setTimeRange(null);
  };

  return (
    <div>
      {timeRangeFor && (
        <TimeRangeModal
          project={timeRangeFor}
          onConfirm={handleTimeRangeConfirm}
          onCancel={() => setTimeRangeFor(null)}
        />
      )}

      <SectionHeader
        title="Projects"
        subtitle="Isolate log pipelines by project — each project maintains its own log data and analysis results"
      />

      {/* Active Project Banner */}
      {activeProject && (
        <div style={{
          background: "#0d1a0d", border: "1px solid #1a4a1a", borderRadius: 4,
          padding: "12px 16px", marginBottom: 20, display: "flex", alignItems: "center", gap: 12,
        }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#4caf50" }} />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 11, color: "#4caf50", letterSpacing: 1, textTransform: "uppercase", marginBottom: 2 }}>
              Active Project
            </div>
            <div style={{ color: "#c0c0c0", fontSize: 13 }}>{activeProject.name}</div>
          </div>
          <Btn variant="ghost" onClick={handleDeactivate} style={{ fontSize: 11 }}>
            DEACTIVATE
          </Btn>
        </div>
      )}

      {/* Upload Stepper for active project */}
      {activeProject && (
        <div style={{ marginBottom: 24 }}>
          <div style={{ fontSize: 11, color: "#666", letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>
            Upload Logs → {activeProject.name}
          </div>
          <UploadStepper
            projectId={activeProject.id}
            onComplete={() => {
              load();
              // Refresh uploads list if expanded
              if (expandedUploads[activeProject.id]) {
                getProjectUploads(activeProject.id)
                  .then((u) => setExpandedUploads((prev) => ({ ...prev, [activeProject.id]: u })))
                  .catch(() => {});
              }
            }}
          />
        </div>
      )}

      <Divider />

      {/* Create New */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase" }}>
          {projects.length} Project{projects.length !== 1 ? "s" : ""}
        </div>
        <Btn variant="default" onClick={() => setShowCreate(!showCreate)}>
          {showCreate ? "CANCEL" : "NEW PROJECT"}
        </Btn>
      </div>

      {showCreate && (
        <div style={{ background: "#0d0d0d", border: "1px solid #1e1e1e", borderRadius: 4, padding: 16, marginBottom: 20 }}>
          <div style={{ fontSize: 11, color: "#666", letterSpacing: 1, textTransform: "uppercase", marginBottom: 12 }}>
            Create Project
          </div>
          <TextInput label="Name *" value={newName} onValueChange={setNewName} placeholder="e.g. Production Apache 2025" />
          <TextInput label="Description" value={newDesc} onValueChange={setNewDesc} placeholder="Optional description" />
          {error && <div style={{ color: "#cc4444", fontSize: 12, marginBottom: 8 }}>{error}</div>}
          <Btn onClick={handleCreate} disabled={creating}>
            {creating ? <Spinner size={12} /> : "CREATE"}
          </Btn>
        </div>
      )}

      {/* Project List */}
      {loading ? (
        <div style={{ textAlign: "center", padding: 40 }}><Spinner size={24} /></div>
      ) : projects.length === 0 ? (
        <div style={{ textAlign: "center", color: "#444", padding: 48, fontSize: 13 }}>
          No projects yet — create one to begin
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {projects.map((p) => {
            const isActive = activeProject?.id === p.id;
            const uploads = expandedUploads[p.id];
            const uploadsLoading = loadingUploads[p.id];
            return (
              <div key={p.id} style={{
                background: isActive ? "#0d1a0d" : "#0d0d0d",
                border: `1px solid ${isActive ? "#1a4a1a" : "#1e1e1e"}`,
                borderRadius: 4,
              }}>
                {/* Project header row */}
                <div style={{ padding: "14px 16px", display: "flex", alignItems: "center", gap: 14 }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                      <div style={{ color: "#e0e0e0", fontSize: 13, fontWeight: 500 }}>{p.name}</div>
                      {isActive && <Badge color="#4caf50">ACTIVE</Badge>}
                    </div>
                    {p.description && (
                      <div style={{ color: "#555", fontSize: 12 }}>{p.description}</div>
                    )}
                    <div style={{ color: "#333", fontSize: 11, marginTop: 4 }}>
                      {p.last_run_at ? `Last run: ${new Date(p.last_run_at).toLocaleDateString()}` : ""}
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
                    <Btn variant="ghost" onClick={() => loadUploads(p.id)} style={{ fontSize: 11 }}>
                      {uploadsLoading ? <Spinner size={10} /> : uploads ? "HIDE FILES" : "FILES"}
                    </Btn>
                    {isActive ? (
                      <Btn variant="ghost" onClick={handleDeactivate}>DEACTIVATE</Btn>
                    ) : (
                      <Btn variant="default" onClick={() => handleSetActive(p)}>SET ACTIVE</Btn>
                    )}
                    <Btn variant="danger" onClick={() => handleDelete(p.id)}>DELETE</Btn>
                  </div>
                </div>

                {/* Uploads list */}
                {uploads && (
                  <div style={{ borderTop: "1px solid #1a1a1a", padding: "10px 16px" }}>
                    <div style={{ fontSize: 11, color: "#555", letterSpacing: 1, textTransform: "uppercase", marginBottom: 8 }}>
                      Uploaded Log Files
                    </div>
                    {uploads.length === 0 ? (
                      <div style={{ color: "#333", fontSize: 12 }}>No log files uploaded yet</div>
                    ) : (
                      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                        {uploads.map((u) => (
                          <div key={u.upload_id} style={{
                            display: "flex", alignItems: "center", gap: 10,
                            background: "#0a0a0a", border: "1px solid #1a1a1a",
                            borderRadius: 3, padding: "7px 10px",
                          }}>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ color: "#c0c0c0", fontSize: 12, marginBottom: 2 }}>
                                {u.filename ?? u.upload_id}
                              </div>
                              <div style={{ color: "#444", fontSize: 11 }}>
                                {u.started_at ? new Date(u.started_at).toLocaleString() : ""}
                                {u.entry_count ? ` · ${u.entry_count.toLocaleString()} entries` : ""}
                              </div>
                            </div>
                            <UploadStatusBadge stage={u.stage} status={u.status} />
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
