import { NextRequest, NextResponse } from "next/server";

/** Decode JWT payload and check if it is expired (no signature verification). */
function isTokenExpired(token: string): boolean {
  try {
    const payloadB64 = token.split(".")[1];
    if (!payloadB64) return true;
    const json = atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/"));
    const { exp } = JSON.parse(json) as { exp?: number };
    return exp ? exp < Math.floor(Date.now() / 1000) : false;
  } catch {
    return true; // malformed token → treat as expired
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

export function proxy(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const token = req.cookies.get("auth_token")?.value;

  const isProtected = PROTECTED.some(
    (p) => pathname === p || pathname.startsWith(`${p}/`),
  );

  if (isProtected && !token) {
    return NextResponse.redirect(new URL("/login", req.url));
  }

  // Clear expired/invalid token and redirect to login
  if (isProtected && token && isTokenExpired(token)) {
    const res = NextResponse.redirect(new URL("/login", req.url));
    res.cookies.delete("auth_token");
    return res;
  }

  // Redirect authenticated users away from login page
  if (pathname === "/login" && token && !isTokenExpired(token)) {
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
