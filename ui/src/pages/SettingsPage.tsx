import { useConfig } from "@/api/hooks.ts";
import { CheckCircle, XCircle, AlertCircle } from "lucide-react";

function StatusBadge({ ok, warning }: { ok: boolean; warning?: boolean }) {
  if (ok) return <CheckCircle className="h-4 w-4 text-success" />;
  if (warning) return <AlertCircle className="h-4 w-4 text-warning" />;
  return <XCircle className="h-4 w-4 text-destructive" />;
}

export function SettingsPage() {
  const { data: config, isLoading, error } = useConfig();

  if (isLoading) {
    return <div className="py-20 text-center text-muted-foreground">Loading...</div>;
  }

  if (error) {
    return (
      <div className="py-20 text-center text-destructive">
        Failed to connect to backend: {error.message}
      </div>
    );
  }

  if (!config) return null;

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-muted-foreground">System configuration and status</p>
      </div>

      <div className="space-y-4">
        {/* LLM */}
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="mb-3 flex items-center gap-2">
            <StatusBadge ok={config.llm_key_configured} />
            <h2 className="font-medium">LLM Provider</h2>
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Provider</span>
              <span>{config.llm_provider}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Model</span>
              <span>{config.llm_model}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">API Key</span>
              <span>
                {config.llm_key_configured ? (
                  <span className="text-success">Configured</span>
                ) : (
                  <span className="text-destructive">Missing - set ANTHROPIC_API_KEY in .env</span>
                )}
              </span>
            </div>
          </div>
        </div>

        {/* Images */}
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="mb-3 flex items-center gap-2">
            <StatusBadge ok={config.image_key_configured} warning />
            <h2 className="font-medium">Image Generation</h2>
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Model</span>
              <span>{config.image_model}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">API Key</span>
              <span>
                {config.image_key_configured ? (
                  <span className="text-success">Configured</span>
                ) : (
                  <span className="text-warning">Missing - sprites will use placeholders</span>
                )}
              </span>
            </div>
          </div>
        </div>

        {/* Slipstream */}
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="mb-3 flex items-center gap-2">
            <StatusBadge ok={config.slipstream_available} warning />
            <h2 className="font-medium">Slipstream Mod Manager</h2>
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Status</span>
              <span>
                {config.slipstream_available ? (
                  <span className="text-success">Found</span>
                ) : (
                  <span className="text-warning">Not found - validate/patch disabled</span>
                )}
              </span>
            </div>
            {config.slipstream_path && (
              <div className="flex justify-between">
                <span className="text-muted-foreground">Path</span>
                <span className="truncate max-w-72">{config.slipstream_path}</span>
              </div>
            )}
          </div>
        </div>

        {/* Output */}
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="mb-3 flex items-center gap-2">
            <StatusBadge ok={true} />
            <h2 className="font-medium">Output</h2>
          </div>
          <div className="text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Directory</span>
              <span>{config.output_dir}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="rounded-md border border-border bg-card p-4 text-xs text-muted-foreground">
        Configuration is read from <code className="rounded bg-accent px-1 py-0.5">.env</code> in the project root.
        Restart the server after making changes.
      </div>
    </div>
  );
}
