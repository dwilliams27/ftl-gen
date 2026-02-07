import { Link } from "react-router-dom";
import { useMods } from "@/api/hooks.ts";
import { formatBytes, formatDate } from "@/lib/utils.ts";
import { Swords, Crosshair, Shield, Users, MessageSquare, Image } from "lucide-react";

export function ModsPage() {
  const { data: mods, isLoading, error } = useMods();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20 text-muted-foreground">
        Loading mods...
      </div>
    );
  }

  if (error) {
    return (
      <div className="py-20 text-center text-destructive">
        Failed to load mods: {error.message}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Mods</h1>
          <p className="text-muted-foreground">
            {mods?.length ?? 0} generated mod{mods?.length === 1 ? "" : "s"}
          </p>
        </div>
        <Link
          to="/generate"
          className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
        >
          Generate New
        </Link>
      </div>

      {!mods?.length ? (
        <div className="rounded-lg border border-border bg-card p-12 text-center">
          <p className="text-muted-foreground">No mods generated yet.</p>
          <Link
            to="/generate"
            className="mt-2 inline-block text-primary hover:underline"
          >
            Create your first mod
          </Link>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {mods.map((mod) => (
            <Link
              key={mod.name}
              to={`/mods/${encodeURIComponent(mod.name)}`}
              className="rounded-lg border border-border bg-card p-4 transition-colors hover:border-primary"
            >
              <div className="mb-2 font-medium">{mod.name}</div>
              <div className="mb-3 flex flex-wrap gap-2">
                {mod.weapon_count > 0 && (
                  <span className="flex items-center gap-1 rounded bg-accent px-2 py-0.5 text-xs">
                    <Swords className="h-3 w-3" /> {mod.weapon_count}
                  </span>
                )}
                {mod.drone_count > 0 && (
                  <span className="flex items-center gap-1 rounded bg-accent px-2 py-0.5 text-xs">
                    <Crosshair className="h-3 w-3" /> {mod.drone_count}
                  </span>
                )}
                {mod.augment_count > 0 && (
                  <span className="flex items-center gap-1 rounded bg-accent px-2 py-0.5 text-xs">
                    <Shield className="h-3 w-3" /> {mod.augment_count}
                  </span>
                )}
                {mod.crew_count > 0 && (
                  <span className="flex items-center gap-1 rounded bg-accent px-2 py-0.5 text-xs">
                    <Users className="h-3 w-3" /> {mod.crew_count}
                  </span>
                )}
                {mod.event_count > 0 && (
                  <span className="flex items-center gap-1 rounded bg-accent px-2 py-0.5 text-xs">
                    <MessageSquare className="h-3 w-3" /> {mod.event_count}
                  </span>
                )}
                {mod.sprite_count > 0 && (
                  <span className="flex items-center gap-1 rounded bg-accent px-2 py-0.5 text-xs">
                    <Image className="h-3 w-3" /> {mod.sprite_count}
                  </span>
                )}
              </div>
              <div className="flex justify-between text-xs text-muted-foreground">
                <span>{formatDate(mod.created_at)}</span>
                <span>{formatBytes(mod.size_bytes)}</span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
