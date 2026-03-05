"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/store";
import Sidebar from "@/components/sidebar";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { user, setUser } = useAuthStore();
  const router = useRouter();

  useEffect(() => {
    // Hydrate auth store from the cookie-backed /api/auth/me endpoint
    if (!user) {
      fetch("/api/auth/me")
        .then((r) => {
          if (!r.ok) throw new Error("Not authenticated");
          return r.json();
        })
        .then((me) =>
          setUser({
            username: me.username,
            role: me.role,
            userId: me.user_id,
            email: me.email,
          }),
        )
        .catch(() => router.push("/login"));
    }
  }, [user, setUser, router]);

  if (!user) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100vh",
          background: "#080808",
          color: "#555",
          fontFamily: "monospace",
          fontSize: 12,
          letterSpacing: 2,
        }}
      >
        LOADING…
      </div>
    );
  }

  return (
    <div style={{ display: "flex", height: "100vh", overflow: "hidden" }}>
      <Sidebar />
      <main
        style={{
          flex: 1,
          overflowY: "auto",
          background: "#080808",
          padding: "32px 36px",
        }}
      >
        {children}
      </main>
    </div>
  );
}
