"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/store";

const NAV = [
  { key: "overview", href: "/overview", label: "Overview", analystOnly: true },
  { key: "projects", href: "/projects", label: "Projects", analystOnly: true },
  { key: "analysis", href: "/analysis", label: "Analysis", analystOnly: true },
  {
    key: "detections",
    href: "/detections",
    label: "Detected Threats",
    analystOnly: true,
  },
  {
    key: "behavioral",
    href: "/behavioral",
    label: "Behavioral Analysis",
    analystOnly: true,
  },
  {
    key: "threat-actor",
    href: "/threat-actor",
    label: "Threat Actor",
    analystOnly: true,
  },
  {
    key: "correlation",
    href: "/correlation",
    label: "Correlation",
    analystOnly: true,
  },
  {
    key: "log-statistics",
    href: "/log-statistics",
    label: "Log Statistics",
    analystOnly: true,
  },
  {
    key: "ai-insights",
    href: "/ai-insights",
    label: "AI Insights",
    analystOnly: true,
  },
  {
    key: "pipeline",
    href: "/pipeline",
    label: "Pipeline",
    analystOnly: true,
  },
  { key: "admin", href: "/admin", label: "Admin", adminOnly: true },
];

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const { user, activeProject, logout } = useAuthStore();
  const role = user?.role ?? "analyst";

  const handleLogout = async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    logout();
    router.push("/login");
  };

  const roleColor =
    role === "admin" ? "#6b46c1" : role === "analyst" ? "#1d4ed8" : "#334155";

  return (
    <aside
      style={{
        width: 240,
        minWidth: 240,
        maxWidth: 240,
        background: "#0d0d0d",
        borderRight: "1px solid #1e1e1e",
        display: "flex",
        flexDirection: "column",
        height: "100vh",
        overflow: "hidden",
      }}
    >
      {/* Branding */}
      <div
        style={{
          padding: "20px 16px 24px",
          borderBottom: "1px solid #1a1a1a",
        }}
      >
        <div
          style={{
            fontSize: 15,
            letterSpacing: 4,
            color: "#e0e0e0",
            fontWeight: 300,
          }}
        >
          LOGIC
        </div>
        <div
          style={{
            fontSize: 9,
            letterSpacing: 3,
            color: "#333",
            marginTop: 4,
            textTransform: "uppercase",
          }}
        >
          Web Agent · Security Analysis
        </div>
      </div>

      {/* User badge */}
      <div style={{ padding: "12px 12px 0" }}>
        <div
          style={{
            background: "#111",
            border: "1px solid #1e1e1e",
            borderRadius: 4,
            padding: "10px 14px",
            marginBottom: 16,
          }}
        >
          <div style={{ fontSize: 12, color: "#c0c0c0", letterSpacing: 0.5 }}>
            {user?.username}
          </div>
          <div style={{ marginTop: 3 }}>
            <span
              style={{
                background: roleColor,
                color: "#fff",
                fontSize: 8,
                letterSpacing: 2,
                textTransform: "uppercase",
                borderRadius: 2,
                padding: "1px 6px",
              }}
            >
              {role}
            </span>
          </div>
          {activeProject?.name && (
            <div
              style={{
                fontSize: 10,
                color: "#444",
                marginTop: 5,
                letterSpacing: 0.5,
              }}
            >
              ▸ {activeProject.name}
            </div>
          )}
        </div>
      </div>

      {/* Nav links */}
      <nav style={{ flex: 1, overflowY: "auto", padding: "0 12px" }}>
        {NAV.map((item, i) => {
          // Role gating: same as Python NAV logic
          if (item.analystOnly && role === "admin") return null;
          if (item.adminOnly && role !== "admin") return null;

          // Separator before Pipeline
          const showSep = item.key === "pipeline";

          const active =
            pathname === item.href ||
            pathname.startsWith(`${item.href}/`) ||
            (item.href === "/overview" && pathname === "/");

          return (
            <div key={item.key}>
              {showSep && (
                <div
                  style={{
                    height: 1,
                    background: "#1a1a1a",
                    margin: "8px 0",
                  }}
                />
              )}
              <Link
                href={item.href}
                style={{
                  display: "block",
                  padding: "9px 12px",
                  borderRadius: 2,
                  fontSize: 11,
                  letterSpacing: 1,
                  textTransform: "uppercase",
                  textDecoration: "none",
                  color: active ? "#e0e0e0" : "#555",
                  background: active ? "#1a1a1a" : "transparent",
                  borderLeft: active ? "2px solid #808080" : "2px solid transparent",
                  transition: "all 0.1s",
                  marginBottom: 2,
                }}
              >
                {item.label}
              </Link>
            </div>
          );
        })}
      </nav>

      {/* Logout */}
      <div style={{ padding: "12px 12px 20px" }}>
        <button
          onClick={handleLogout}
          style={{
            width: "100%",
            background: "#111",
            border: "1px solid #404040",
            color: "#c0c0c0",
            borderRadius: 2,
            fontSize: 11,
            letterSpacing: 1,
            textTransform: "uppercase",
            padding: "8px 16px",
            fontFamily: "inherit",
            cursor: "pointer",
            transition: "all 0.15s",
          }}
          onMouseEnter={(e) => {
            (e.target as HTMLButtonElement).style.borderColor = "#c0c0c0";
            (e.target as HTMLButtonElement).style.color = "#fff";
          }}
          onMouseLeave={(e) => {
            (e.target as HTMLButtonElement).style.borderColor = "#404040";
            (e.target as HTMLButtonElement).style.color = "#c0c0c0";
          }}
        >
          Sign Out
        </button>
      </div>
    </aside>
  );
}
