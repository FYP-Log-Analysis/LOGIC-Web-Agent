import { NextRequest, NextResponse } from "next/server";

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

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const token = req.cookies.get("auth_token")?.value;

  const isProtected = PROTECTED.some(
    (p) => pathname === p || pathname.startsWith(`${p}/`),
  );

  if (isProtected && !token) {
    return NextResponse.redirect(new URL("/login", req.url));
  }

  // Redirect authenticated users away from login page
  if (pathname === "/login" && token) {
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
