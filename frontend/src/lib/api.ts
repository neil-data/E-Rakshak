const API_BASE = ((import.meta as any).env?.VITE_API_BASE as string) || "http://localhost:8010/api";

export interface CaseSummary {
  sample_id: string;
  platform: string;
  file_type: string;
  risk_score: number;
  status: string;
  submitted_at: string;
}

export interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  confidence: number;
}

export interface CapabilityTag {
  capability: string;
  confidence: number;
  evidence: string[];
}

export interface YaraMatchDetail {
  rule_name: string;
  category: string;
  severity: string;
  description: string;
}

export interface PackingInfo {
  is_packed: boolean;
  packer_name: string | null;
  confidence: number;
  evidence: string[];
  unpack_attempted: boolean;
  unpack_succeeded: boolean;
  unpack_method: string | null;
  unpack_error: string | null;
  unpacked_sha256: string | null;
}

export interface ExplainedStringDetail {
  value: string;
  type: string;
  category: string;
  explanation: string;
  severity: string;
}

export interface GeoIocDetail {
  ip: string;
  country: string | null;
  country_iso: string | null;
  city: string | null;
  region: string | null;
  postal_code: string | null;
  timezone: string | null;
  latitude: number | null;
  longitude: number | null;
  accuracy_radius: number | null;
  asn: number | null;
  asn_org: string | null;
  isp: string | null;
  is_hosting: boolean | null;
  is_proxy: boolean | null;
  threat_level: string | null;
}

export interface CaseDetail {
  sample_id: string;
  platform: string;
  file_type: string;
  risk_score: number;
  status: string;
  mitre_techniques: MitreTechnique[];
  capability_tags: CapabilityTag[];
  narrative_summary: string;
  submitted_at: string;
  file_size_bytes?: number | null;
  sha256?: string | null;
  md5?: string | null;
  sha1?: string | null;
  yara_matches: YaraMatchDetail[];
  packing: PackingInfo | null;
  explained_strings: ExplainedStringDetail[];
  geo_iocs: GeoIocDetail[];
}

export interface HealthResponse {
  status: string;
  sandbox_online: boolean;
  version: string;
}

export interface CurrentUser {
  email: string;
  full_name: string;
  department: string;
  officer_id: string;
}

function getAuthHeaders(): HeadersInit {
  const token = localStorage.getItem("sentinel_access_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function login(email: string, password: string): Promise<string> {
  const formData = new URLSearchParams();
  formData.append("username", email);
  formData.append("password", password);

  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: formData.toString(),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || "Authentication failed. Invalid agency credentials.");
  }

  const data = await res.json();
  localStorage.setItem("sentinel_access_token", data.access_token);
  return data.access_token;
}

export function logout(): void {
  localStorage.removeItem("sentinel_access_token");
}

export function isAuthenticated(): boolean {
  return !!localStorage.getItem("sentinel_access_token");
}

export async function fetchCurrentUser(): Promise<CurrentUser> {
  const res = await fetch(`${API_BASE}/auth/me`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    if (res.status === 401) {
      logout();
      throw new Error("Session expired. Please log in again.");
    }
    throw new Error("Failed to fetch current user");
  }
  return res.json();
}

export async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error("Health check failed");
  return res.json();
}

export async function fetchCases(): Promise<CaseSummary[]> {
  const res = await fetch(`${API_BASE}/cases`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    if (res.status === 401) {
      logout();
      throw new Error("Session expired. Please log in again.");
    }
    throw new Error("Failed to fetch cases");
  }
  return res.json();
}

export async function searchCases(query: string): Promise<CaseSummary[]> {
  const res = await fetch(`${API_BASE}/cases/search?q=${encodeURIComponent(query)}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    if (res.status === 401) {
      logout();
      throw new Error("Session expired. Please log in again.");
    }
    throw new Error("Case search failed");
  }
  return res.json();
}

export async function fetchCaseDetail(sampleId: string): Promise<CaseDetail> {
  const res = await fetch(`${API_BASE}/cases/${sampleId}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    if (res.status === 401) {
      logout();
      throw new Error("Session expired. Please log in again.");
    }
    throw new Error(`Failed to fetch case detail for ${sampleId}`);
  }
  return res.json();
}

export async function uploadSample(file: File): Promise<CaseDetail> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_BASE}/cases/upload`, {
    method: "POST",
    headers: getAuthHeaders(),
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Sample analysis failed.");
  }

  return res.json();
}
