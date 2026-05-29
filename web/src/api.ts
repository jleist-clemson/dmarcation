export type Severity = "error" | "warning";

export interface Issue {
  severity: Severity;
  tag: string | null;
  message: string;
}

export interface ValidationData {
  valid: boolean;
  tags: Record<string, string>;
  issues: Issue[];
  errorCount: number;
  warningCount: number;
}

export interface ValidateResponse {
  record: string;
  validation: ValidationData;
}

export interface LookupQuery {
  name: string;
  count: number;
  records: string[];
}

export type PolicySource = "direct" | "organizational" | "none";

export interface LookupResponse {
  domain: string;
  source: PolicySource;
  policyDomain: string | null;
  record: string | null;
  found: boolean;
  inherited: boolean;
  multiple: boolean;
  multipleQuery: { name: string; records: string[] } | null;
  effectivePolicy: { policy: string; via: "sp" | "p" } | null;
  queries: LookupQuery[];
  validation: ValidationData | null;
}

/** Thrown for non-2xx API responses that return an { error } payload. */
export class ApiError extends Error {}

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url, init);
  } catch {
    throw new ApiError("could not reach the API server.");
  }

  const data = (await response.json().catch(() => null)) as
    | (T & { error?: string })
    | { error?: string }
    | null;

  if (!response.ok || data === null) {
    const message =
      data && "error" in data && data.error
        ? data.error
        : `request failed (${response.status}).`;
    throw new ApiError(message);
  }

  return data as T;
}

export function validateRecord(record: string): Promise<ValidateResponse> {
  return requestJson<ValidateResponse>("/api/validate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ record }),
  });
}

export function lookupDomain(
  domain: string,
  nameserver?: string
): Promise<LookupResponse> {
  const params = new URLSearchParams({ domain });
  if (nameserver) {
    params.set("ns", nameserver);
  }
  return requestJson<LookupResponse>(`/api/lookup?${params.toString()}`);
}
