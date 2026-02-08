const API_BASE = "/api/v1";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });

  if (!res.ok) {
    const body = await res.text();
    let message: string;
    try {
      message = JSON.parse(body).detail ?? body;
    } catch {
      message = body;
    }
    throw new ApiError(res.status, message);
  }

  if (res.status === 204) return undefined as T;
  return res.json();
}

export const api = {
  // Config
  getConfig: () => request<import("@/lib/types").ConfigStatus>("/config"),

  // Mods
  listMods: () => request<import("@/lib/types").ModSummary[]>("/mods"),
  getMod: (name: string) =>
    request<import("@/lib/types").ModDetail>(`/mods/${encodeURIComponent(name)}`),
  deleteMod: (name: string) =>
    request<void>(`/mods/${encodeURIComponent(name)}`, { method: "DELETE" }),
  getModDownloadUrl: (name: string) =>
    `${API_BASE}/mods/${encodeURIComponent(name)}/download`,
  getSpriteUrl: (modName: string, spritePath: string) =>
    `${API_BASE}/mods/${encodeURIComponent(modName)}/sprites/${spritePath}`,

  // Validation
  validate: (name: string) =>
    request<import("@/lib/types").ValidationResult>(`/validate?name=${encodeURIComponent(name)}`, {
      method: "POST",
    }),
  patch: (name: string, testLoadout = false) => {
    const params = new URLSearchParams({ name });
    if (testLoadout) params.set("test_loadout", "true");
    return request<import("@/lib/types").PatchResult>(`/patch?${params}`, {
      method: "POST",
    });
  },
  patchAndRun: (name: string, testLoadout = false) => {
    const params = new URLSearchParams({ name });
    if (testLoadout) params.set("test_loadout", "true");
    return request<import("@/lib/types").PatchResult>(`/patch-and-run?${params}`, {
      method: "POST",
    });
  },

  // Diagnostics
  diagnose: (name: string) =>
    request<import("@/lib/types").DiagnosticReport>(`/diagnose?name=${encodeURIComponent(name)}`, {
      method: "POST",
    }),
  getCrashReport: () =>
    request<import("@/lib/types").CrashReportResponse>("/crash-report"),

  // Generation (SSE)
  generateMod: (body: import("@/lib/types").GenerateRequest) => {
    return new EventSource(
      `${API_BASE}/generate?_body=${encodeURIComponent(JSON.stringify(body))}`,
    );
  },

  // Single item generation
  generateWeapon: (description: string) =>
    request<import("@/lib/types").WeaponBlueprint>("/generate/weapon", {
      method: "POST",
      body: JSON.stringify({ description }),
    }),
  generateDrone: (description: string) =>
    request<import("@/lib/types").DroneBlueprint>("/generate/drone", {
      method: "POST",
      body: JSON.stringify({ description }),
    }),
  generateEvent: (description: string) =>
    request<import("@/lib/types").EventBlueprint>("/generate/event", {
      method: "POST",
      body: JSON.stringify({ description }),
    }),
  generateAugment: (description: string) =>
    request<import("@/lib/types").AugmentBlueprint>("/generate/augment", {
      method: "POST",
      body: JSON.stringify({ description }),
    }),
  generateCrew: (description: string) =>
    request<import("@/lib/types").CrewBlueprint>("/generate/crew", {
      method: "POST",
      body: JSON.stringify({ description }),
    }),
};
