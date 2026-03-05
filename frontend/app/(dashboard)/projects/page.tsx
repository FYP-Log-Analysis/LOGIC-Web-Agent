"use client";

import { useEffect, useState } from "react";
import { useAuthStore } from "@/lib/store";
import { getProjects, createProject, deleteProject } from "@/lib/client";
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

export default function ProjectsPage() {
  const { activeProject, setActiveProject, setProjectSelectPending } = useAuthStore();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [error, setError] = useState("");
  const [showCreate, setShowCreate] = useState(false);

  const load = async () => {
    try {
      const data = await getProjects();
      setProjects(data);
    } catch {}
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

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
      if (activeProject?.id === id) setActiveProject(null);
      await load();
    } catch {}
  };

  const handleSetActive = (p: Project) => {
    setActiveProject({ id: p.id, name: p.name ?? p.id });
    setProjectSelectPending(false);
  };

  const handleDeactivate = () => { setActiveProject(null); };

  return (
    <div>
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
          <UploadStepper projectId={activeProject.id} onComplete={load} />
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
          <TextInput
            label="Name *"
            value={newName}
            onValueChange={setNewName}
            placeholder="e.g. Production Apache 2025"
          />
          <TextInput
            label="Description"
            value={newDesc}
            onValueChange={setNewDesc}
            placeholder="Optional description"
          />
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
            return (
              <div key={p.id} style={{
                background: isActive ? "#0d1a0d" : "#0d0d0d",
                border: `1px solid ${isActive ? "#1a4a1a" : "#1e1e1e"}`,
                borderRadius: 4,
                padding: "14px 16px",
                display: "flex",
                alignItems: "center",
                gap: 14,
              }}>
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
                  {isActive ? (
                    <Btn variant="ghost" onClick={handleDeactivate}>DEACTIVATE</Btn>
                  ) : (
                    <Btn variant="default" onClick={() => handleSetActive(p)}>SET ACTIVE</Btn>
                  )}
                  <Btn variant="danger" onClick={() => handleDelete(p.id)}>DELETE</Btn>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
