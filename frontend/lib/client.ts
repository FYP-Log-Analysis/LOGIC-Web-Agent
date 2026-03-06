import { apiGet, apiPost, apiDelete, apiUpload } from "./api";

// ── Data (rule matches, normalized logs, CRS) ─────────────────────────────────

export async function getRuleMatches() {
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
  }>("api/search/detections?limit=2000");
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

export async function getNormalizedLogs() {
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
  >("api/logs/entries?limit=5000");
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

export async function getCRSMatches(limit = 2000) {
  const data = await apiGet<{
    count: number;
    results: Array<{
      rule_id?: string;
      client_ip?: string;
      path?: string;
      timestamp?: string;
      status_code?: number;
    }>;
  }>(`api/search/detections?limit=${limit}`);
  return (data.results ?? []).map((r) => ({
    client_ip: r.client_ip,
    rule_id: r.rule_id,
    uri: r.path,
    anomaly_score: 0 as number,
    timestamp: r.timestamp,
    paranoia_level: 0 as number,
  }));
}

export async function getCRSStats() {
  const data = await apiGet<{
    total_detections?: number;
    detections_by_severity?: Record<string, number>;
    top_offending_ips?: Array<{ client_ip: string; hit_count: number }>;
  }>("api/search/stats");
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

export async function getGeoSummary(limit = 10) {
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
  }>(`api/search/geography/summary?limit=${limit}`);
}

// ── Analysis ─────────────────────────────────────────────────────────────────

export async function runAnalysis(params?: {
  mode?: string;
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

export async function getLogTimeRange() {
  return apiGet<{ start?: string; end?: string }>("api/logs/time-range");
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
}

export async function runBehavioralAnalysis(params?: BehavioralParams) {
  return apiPost<unknown>("api/analysis/behavioral", params ?? {});
}

export async function getBehavioralResults() {
  return apiGet<{
    request_rate_spikes?: unknown[];
    url_enumeration?: unknown[];
    status_code_spikes?: unknown[];
    visitor_rates?: unknown[];
    thresholds?: Record<string, number>;
  }>("api/analysis/behavioral/results");
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
