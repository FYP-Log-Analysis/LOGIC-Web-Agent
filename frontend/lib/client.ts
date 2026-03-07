import { apiGet, apiPost, apiDelete, apiUpload } from "./api";

// ── Shared scope options ──────────────────────────────────────────────────────

export interface ScopeOpts {
  projectId?: string;
  startTs?: string;
  endTs?: string;
}

function buildQuery(base: string, opts?: ScopeOpts & { limit?: number }): string {
  const params = new URLSearchParams();
  // Preserve existing query from base
  const [path, existing] = base.split("?");
  if (existing) new URLSearchParams(existing).forEach((v, k) => params.set(k, v));
  if (opts?.limit != null) params.set("limit", String(opts.limit));
  if (opts?.projectId) params.set("project_id", opts.projectId);
  if (opts?.startTs) params.set("start_ts", opts.startTs);
  if (opts?.endTs) params.set("end_ts", opts.endTs);
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

// ── Data (rule matches, normalized logs, CRS) ─────────────────────────────────

export async function getRuleMatches(opts?: ScopeOpts) {
  const data = await apiGet<{
    count: number;
    results: Array<{
      id?: number;
      rule_id?: string;
      rule_title?: string;
      severity?: string;
      client_ip?: string;
      method?: string;
      path?: string;
      status_code?: number;
      timestamp?: string;
      user_agent?: string;
    }>;
  }>(buildQuery("api/search/detections", { ...opts, limit: 2000 }));
  const results = data.results ?? [];
  return {
    total_matches: data.count,
    matched_rules: [...new Set(results.map((r) => r.rule_id).filter(Boolean))] as string[],
    matches: results.map((r) => ({
      rule_id: r.rule_id,
      rule_title: r.rule_title,
      severity: r.severity,
      client_ip: r.client_ip,
      method: r.method,
      path: r.path,
      status_code: r.status_code,
      timestamp: r.timestamp,
      tags: [] as string[],
    })),
  };
}

export async function getNormalizedLogs(opts?: ScopeOpts) {
  const rows = await apiGet<
    Array<{
      client_ip?: string;
      http_method?: string;
      request_path?: string;
      status_code?: number;
      is_bot?: number | boolean;
      timestamp?: string;
      user_agent?: string;
      response_size?: number;
      [key: string]: unknown;
    }>
  >(buildQuery("api/logs/entries", { ...opts, limit: 5000 }));
  return rows.map((r) => ({
    ip: r.client_ip,
    method: r.http_method,
    path: r.request_path,
    status: r.status_code,
    is_bot: Boolean(r.is_bot),
    timestamp: r.timestamp,
    user_agent: r.user_agent,
    response_size: r.response_size,
  }));
}

export async function getCRSMatches(limit = 2000, opts?: ScopeOpts) {
  const data = await apiGet<{
    count: number;
    results: Array<{
      rule_id?: string;
      client_ip?: string;
      path?: string;
      timestamp?: string;
      status_code?: number;
    }>;
  }>(buildQuery("api/search/detections", { ...opts, limit }));
  return (data.results ?? []).map((r) => ({
    client_ip: r.client_ip,
    rule_id: r.rule_id,
    uri: r.path,
    anomaly_score: 0 as number,
    timestamp: r.timestamp,
    paranoia_level: 0 as number,
  }));
}

export async function getCRSStats(opts?: Pick<ScopeOpts, "projectId">) {
  const data = await apiGet<{
    total_detections?: number;
    detections_by_severity?: Record<string, number>;
    top_offending_ips?: Array<{ client_ip: string; hit_count: number }>;
  }>(buildQuery("api/search/stats", opts));
  return {
    total_crs_matches: data.total_detections ?? 0,
    unique_ips: (data.top_offending_ips ?? []).length,
    avg_anomaly_score: undefined as number | undefined,
    detections_by_severity: data.detections_by_severity,
    top_offending_ips: data.top_offending_ips,
  };
}

export interface GeoCountrySummary {
  country_code: string;
  country_name: string;
  detection_count: number;
  unique_ips: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export async function getGeoSummary(limit = 10, opts?: Pick<ScopeOpts, "projectId">) {
  return apiGet<{
    countries_impacted: number;
    total_detections: number;
    geolocated_detections: number;
    unknown_detections: number;
    coverage_pct: number;
    backfilled_ip_count: number;
    top_source_country: GeoCountrySummary | null;
    countries: GeoCountrySummary[];
    top_countries: GeoCountrySummary[];
  }>(buildQuery(`api/search/geography/summary`, { projectId: opts?.projectId, limit }));
}

// ── Analysis ─────────────────────────────────────────────────────────────────

export async function runAnalysis(params?: {
  mode?: string;
  project_id?: string;
  start_ts?: string;
  end_ts?: string;
}) {
  return apiPost<{ run_id?: string; status?: string; [key: string]: unknown }>(
    "api/analysis/run",
    { mode: "auto", ...params },
  );
}

export async function getAnalysisRun(runId: string) {
  return apiGet<{ status?: string; [key: string]: unknown }>(
    `api/analysis/run/${runId}`,
  );
}

export async function getLogTimeRange(projectId?: string) {
  return apiGet<{ min_timestamp?: string; max_timestamp?: string; total_logs?: number }>(
    buildQuery("api/logs/time-range", { projectId }),
  );
}

export async function getThreatInsights() {
  return apiPost<{
    insights?: string;
    status?: string;
    [key: string]: unknown;
  }>("api/analysis/threat-insights");
}

export async function getInsightsStatus() {
  return apiGet<{ status?: string; insights?: string; [key: string]: unknown }>(
    "api/analysis/threat-insights/status",
  );
}

// ── Behavioral Analysis ───────────────────────────────────────────────────────

export interface BehavioralParams {
  rate_window_minutes?: number;
  rate_threshold?: number;
  enum_window_hours?: number;
  enum_threshold?: number;
  status_window_minutes?: number;
  status_error_ratio?: number;
  visitor_zscore?: number;
  start_ts?: string;
  end_ts?: string;
  project_id?: string;
}

export async function runBehavioralAnalysis(params?: BehavioralParams) {
  return apiPost<unknown>("api/analysis/behavioral", params ?? {});
}

export async function getBehavioralResults(opts?: Pick<ScopeOpts, "projectId">) {
  return apiGet<{
    request_rate_spikes?: unknown[];
    url_enumeration?: unknown[];
    status_code_spikes?: unknown[];
    visitor_rates?: unknown[];
    thresholds?: Record<string, number>;
  }>(buildQuery("api/analysis/behavioral/results", opts));
}

export async function getIpSummary(clientIp: string) {
  return apiGet<{
    client_ip: string;
    country_code: string | null;
    country_name: string;
    request_count: number;
    unique_paths: number;
    first_seen: string | null;
    last_seen: string | null;
    user_agents: Array<{ user_agent: string; count: number }>;
    status_distribution: Record<string, number>;
    top_paths: Array<{ request_path: string; count: number }>;
  }>(`api/search/ip-summary/${encodeURIComponent(clientIp)}`);
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

export async function getPipelineSteps() {
  return apiGet<{
    steps: Record<
      string,
      { name?: string; description?: string; order?: number }
    >;
  }>("api/pipeline/steps");
}

export async function runPipeline() {
  return apiPost<{
    status?: string;
    results?: Array<{
      step_id?: string;
      step_name?: string;
      status?: string;
      output?: string;
      error?: string;
    }>;
  }>("api/pipeline/run");
}

export async function runPipelineStep(stepId: string) {
  return apiPost<{ status?: string; output?: string; error?: string }>(
    `api/pipeline/run/${stepId}`,
  );
}

// ── Projects ─────────────────────────────────────────────────────────────────

export async function getProjects() {
  const result = await apiGet<
    | Array<{ id: string; name?: string; description?: string; status?: string; last_run_at?: string }>
    | { projects: Array<{ id: string; name?: string; description?: string; status?: string; last_run_at?: string }> }
  >("api/projects");
  if (Array.isArray(result)) return result;
  return (result as unknown as { projects: Array<{ id: string; name?: string; description?: string; status?: string; last_run_at?: string }> }).projects ?? [];
}

export async function createProject(name: string, description = "") {
  return apiPost<{ id?: string; project_id?: string; name?: string }>(
    "api/projects",
    { name, description },
  );
}

export async function deleteProject(projectId: string) {
  return apiDelete(`api/projects/${projectId}`);
}

export async function getProjectStats(projectId: string) {
  return apiGet<{ project_id: string; log_entries: number; detections: number }>(
    `api/projects/${projectId}/stats`,
  );
}

export async function getProjectUploads(projectId: string) {
  return apiGet<Array<{
    upload_id: string;
    filename?: string;
    stage?: string;
    status?: string;
    entry_count?: number;
    started_at?: string;
    updated_at?: string;
  }>>(`api/projects/${projectId}/uploads`);
}

// ── Upload ────────────────────────────────────────────────────────────────────

export async function uploadFile(
  file: File,
  projectId?: string,
): Promise<{ upload_id: string; [key: string]: unknown }> {
  const fd = new FormData();
  fd.append("file", file);
  if (projectId) fd.append("project_id", projectId);
  return apiUpload("api/upload", fd);
}

export async function getUploadStatus(uploadId: string) {
  return apiGet<{
    stage?: string;
    status?: string;
    entry_count?: number;
    error?: string;
  }>(`api/upload/status/${uploadId}`);
}

// ── Admin ─────────────────────────────────────────────────────────────────────

export async function adminStats() {
  return apiGet<{
    total_users: number;
    total_projects: number;
    total_log_entries?: number;
    total_detections?: number;
  }>("api/admin/stats");
}

export async function adminListUsers() {
  return apiGet<
    Array<{
      id: number;
      username: string;
      role: string;
      is_active: boolean | number;
      email?: string;
    }>
  >("api/admin/users");
}

export async function adminCreateAnalyst(username: string, password: string) {
  return apiPost("api/auth/register", {
    username,
    password,
    email: `${username}@logic.local`,
  });
}

export async function adminSetUserActive(userId: number, isActive: boolean) {
  const action = isActive ? "activate" : "deactivate";
  return apiPost(`api/admin/users/${userId}/${action}`, {});
}

export async function adminDeleteUser(userId: number) {
  return apiDelete(`api/admin/users/${userId}`);
}
