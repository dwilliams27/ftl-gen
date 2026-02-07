import { Link } from "react-router-dom";
import { Sparkles, FolderOpen, Shuffle } from "lucide-react";
import { useMods, useConfig } from "@/api/hooks.ts";
import { formatDate } from "@/lib/utils.ts";

export function DashboardPage() {
  const { data: mods } = useMods();
  const { data: config } = useConfig();

  const recentMods = mods?.slice(0, 5) ?? [];

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground">FTL Mod Generator</p>
      </div>

      {/* Quick actions */}
      <div className="grid grid-cols-3 gap-4">
        <Link
          to="/generate"
          className="flex items-center gap-3 rounded-lg border border-border bg-card p-4 transition-colors hover:border-primary"
        >
          <Sparkles className="h-5 w-5 text-primary" />
          <div>
            <div className="font-medium">Generate Mod</div>
            <div className="text-sm text-muted-foreground">
              Create from a theme
            </div>
          </div>
        </Link>

        <Link
          to="/mods"
          className="flex items-center gap-3 rounded-lg border border-border bg-card p-4 transition-colors hover:border-primary"
        >
          <FolderOpen className="h-5 w-5 text-success" />
          <div>
            <div className="font-medium">Browse Mods</div>
            <div className="text-sm text-muted-foreground">
              {mods?.length ?? 0} mod{mods?.length === 1 ? "" : "s"}
            </div>
          </div>
        </Link>

        <Link
          to="/chaos"
          className="flex items-center gap-3 rounded-lg border border-border bg-card p-4 transition-colors hover:border-primary"
        >
          <Shuffle className="h-5 w-5 text-warning" />
          <div>
            <div className="font-medium">Chaos Mode</div>
            <div className="text-sm text-muted-foreground">
              Randomize vanilla ($0)
            </div>
          </div>
        </Link>
      </div>

      {/* System status */}
      {config && (
        <div className="rounded-lg border border-border bg-card p-4">
          <h2 className="mb-3 font-medium">System Status</h2>
          <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">LLM</span>
              <span>
                {config.llm_key_configured ? (
                  <span className="text-success">{config.llm_provider}</span>
                ) : (
                  <span className="text-destructive">Not configured</span>
                )}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Images</span>
              <span>
                {config.image_key_configured ? (
                  <span className="text-success">Gemini</span>
                ) : (
                  <span className="text-warning">Not configured</span>
                )}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Slipstream</span>
              <span>
                {config.slipstream_available ? (
                  <span className="text-success">Available</span>
                ) : (
                  <span className="text-warning">Not found</span>
                )}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Output</span>
              <span className="truncate max-w-48">{config.output_dir}</span>
            </div>
          </div>
        </div>
      )}

      {/* Recent mods */}
      {recentMods.length > 0 && (
        <div>
          <h2 className="mb-3 font-medium">Recent Mods</h2>
          <div className="space-y-2">
            {recentMods.map((mod) => (
              <Link
                key={mod.name}
                to={`/mods/${encodeURIComponent(mod.name)}`}
                className="flex items-center justify-between rounded-lg border border-border bg-card p-3 transition-colors hover:border-primary"
              >
                <div>
                  <div className="font-medium">{mod.name}</div>
                  <div className="flex gap-3 text-xs text-muted-foreground">
                    {mod.weapon_count > 0 && (
                      <span>{mod.weapon_count} weapons</span>
                    )}
                    {mod.drone_count > 0 && (
                      <span>{mod.drone_count} drones</span>
                    )}
                    {mod.event_count > 0 && (
                      <span>{mod.event_count} events</span>
                    )}
                    {mod.augment_count > 0 && (
                      <span>{mod.augment_count} augments</span>
                    )}
                    {mod.crew_count > 0 && (
                      <span>{mod.crew_count} crew</span>
                    )}
                  </div>
                </div>
                <span className="text-xs text-muted-foreground">
                  {formatDate(mod.created_at)}
                </span>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
