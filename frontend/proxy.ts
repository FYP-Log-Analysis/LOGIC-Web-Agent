import { NextRequest, NextResponse } from "next/server";

const API_BASE = process.env.API_BASE_URL ?? "http://localhost:4000";

/** Ask FastAPI whether the token is actually valid (covers signature + expiry). */
async function isTokenValid(token: string): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/api/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(3000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

const PROTECTED = [
  "/overview",
  "/projects",
  "/analysis",
  "/detections",
  "/behavioral",
  "/log-statistics",
  "/ai-insights",
  "/pipeline",
  "/admin",
];

export async function proxy(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const token = req.cookies.get("auth_token")?.value;

  const isProtected = PROTECTED.some(
    (p) => pathname === p || pathname.startsWith(`${p}/`),
  );

  // Not a route we manage — pass through immediately
  if (!isProtected && pathname !== "/login") {
    return NextResponse.next();
  }

  const valid = token ? await isTokenValid(token) : false;

  if (isProtected && !valid) {
    const res = NextResponse.redirect(new URL("/login", req.url));
    if (token) res.cookies.delete("auth_token"); // clear the stale cookie
    return res;
  }

  if (pathname === "/login" && valid) {
    return NextResponse.redirect(new URL("/overview", req.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    "/overview/:path*",
    "/projects/:path*",
    "/analysis/:path*",
    "/detections/:path*",
    "/behavioral/:path*",
    "/log-statistics/:path*",
    "/ai-insights/:path*",
    "/pipeline/:path*",
    "/admin/:path*",
    "/login",
  ],
};
