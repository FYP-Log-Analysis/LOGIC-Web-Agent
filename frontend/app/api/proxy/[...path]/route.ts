import { NextRequest, NextResponse } from "next/server";

const API_BASE = process.env.API_BASE_URL ?? "http://localhost:4000";

type Params = { path: string[] };

async function proxyRequest(
  req: NextRequest,
  params: Promise<Params>,
): Promise<NextResponse> {
  const { path } = await params;
  const token = req.cookies.get("auth_token")?.value;

  // Reconstruct the target URL, preserving query string
  const pathStr = (path ?? []).join("/");
  const search = req.nextUrl.searchParams.toString();
  const targetUrl = `${API_BASE}/${pathStr}${search ? `?${search}` : ""}`;

  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;

  // Forward Content-Type only when not multipart (let fetch handle boundary)
  const contentType = req.headers.get("content-type") ?? "";
  if (contentType && !contentType.startsWith("multipart/form-data")) {
    headers["Content-Type"] = contentType;
  }

  let body: BodyInit | undefined;
  if (!["GET", "HEAD"].includes(req.method)) {
    if (contentType.startsWith("multipart/form-data")) {
      body = await req.blob();
      // copy full original content-type header with boundary
      headers["Content-Type"] = contentType;
    } else {
      body = await req.text();
    }
  }

  let upstream: Response;
  try {
    upstream = await fetch(targetUrl, {
      method: req.method,
      headers,
      body,
      // @ts-expect-error — Node 18+ fetch supports this
      duplex: "half",
    });
  } catch (err) {
    return NextResponse.json(
      { error: `API unreachable: ${String(err)}` },
      { status: 503 },
    );
  }

  // Stream the response body back to the client
  // (preserves SSE / chunked streaming for the chat endpoint)
  const responseHeaders = new Headers();
  upstream.headers.forEach((value, key) => {
    // Skip headers that Next.js manages
    if (!["transfer-encoding", "connection"].includes(key.toLowerCase())) {
      responseHeaders.set(key, value);
    }
  });

  return new NextResponse(upstream.body, {
    status: upstream.status,
    headers: responseHeaders,
  });
}

export async function GET(req: NextRequest, { params }: { params: Promise<Params> }) {
  return proxyRequest(req, params);
}

export async function POST(req: NextRequest, { params }: { params: Promise<Params> }) {
  return proxyRequest(req, params);
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<Params> }) {
  return proxyRequest(req, params);
}

export async function PUT(req: NextRequest, { params }: { params: Promise<Params> }) {
  return proxyRequest(req, params);
}

export async function PATCH(req: NextRequest, { params }: { params: Promise<Params> }) {
  return proxyRequest(req, params);
}
