import { useParams, useNavigate } from "react-router-dom";
import { useState, useRef, useEffect } from "react";
import { useMod, useDeleteMod, useValidate, usePatch, usePatchAndRun } from "@/api/hooks.ts";
import { api } from "@/api/client.ts";
import { ArrowLeft, Download, Trash2, CheckCircle, Play, Rocket, ChevronDown, Terminal, Copy, X } from "lucide-react";
import { cn } from "@/lib/utils.ts";
import type { ModDetail, FtlLogResponse } from "@/lib/types.ts";

type Tab = "weapons" | "drones" | "augments" | "crew" | "events" | "sprites" | "xml";

function TabButton({ active, onClick, label, count }: {
  active: boolean; onClick: () => void; label: string; count: number;
}) {
  if (count === 0 && label !== "XML") return null;
  return (
    <button
      onClick={onClick}
      className={cn(
        "rounded-md px-3 py-1.5 text-sm transition-colors",
        active ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground",
      )}
    >
      {label} {count > 0 && <span className="text-xs opacity-70">({count})</span>}
    </button>
  );
}

function WeaponSpritePreview({ modName, weaponName, title }: { modName: string; weaponName: string; title: string }) {
  // Show just the first frame of the 12-frame strip (16px wide per frame)
  const frameWidth = 16;
  const url = api.getSpriteUrl(modName, `weapons/${weaponName.toLowerCase()}_strip12.png`);
  return (
    <div className="my-2 overflow-hidden" style={{ width: frameWidth * 3, height: 60 * 3, imageRendering: "pixelated" as const }}>
      <img
        src={url}
        alt={title}
        style={{ imageRendering: "pixelated", transform: "scale(3)", transformOrigin: "top left" }}
        className="max-w-none"
        width={frameWidth * 12}
        height={60}
      />
    </div>
  );
}

function hasSprite(mod: ModDetail, path: string): boolean {
  return mod.sprite_files.some((f) => f === path);
}

function WeaponsTab({ mod }: { mod: ModDetail }) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {mod.weapons.map((w) => (
        <div key={w.name} className="rounded-lg border border-border bg-card p-4">
          <div className="mb-1 flex items-center justify-between">
            <h3 className="font-medium">{w.title}</h3>
            <span className="rounded bg-accent px-2 py-0.5 text-xs">{w.type}</span>
          </div>
          {hasSprite(mod, `weapons/${w.name.toLowerCase()}_strip12.png`) && (
            <WeaponSpritePreview modName={mod.name} weaponName={w.name} title={w.title} />
          )}
          <p className="mb-3 text-sm text-muted-foreground">{w.desc}</p>
          <div className="grid grid-cols-3 gap-2 text-xs">
            <div><span className="text-muted-foreground">Damage:</span> {w.damage}</div>
            <div><span className="text-muted-foreground">Shots:</span> {w.shots}</div>
            <div><span className="text-muted-foreground">Cooldown:</span> {w.cooldown}s</div>
            <div><span className="text-muted-foreground">Power:</span> {w.power}</div>
            <div><span className="text-muted-foreground">Cost:</span> {w.cost}</div>
            <div><span className="text-muted-foreground">Rarity:</span> {w.rarity}</div>
            {w.fire_chance > 0 && <div><span className="text-warning">Fire:</span> {w.fire_chance * 10}%</div>}
            {w.breach_chance > 0 && <div><span className="text-destructive">Breach:</span> {w.breach_chance * 10}%</div>}
            {w.sp && <div><span className="text-primary">Pierce:</span> {w.sp}</div>}
            {w.ion && <div><span className="text-primary">Ion:</span> {w.ion}</div>}
            {w.length && <div><span className="text-muted-foreground">Length:</span> {w.length}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}

function DronesTab({ mod }: { mod: ModDetail }) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {mod.drones.map((d) => (
        <div key={d.name} className="rounded-lg border border-border bg-card p-4">
          <div className="mb-1 flex items-center justify-between">
            <h3 className="font-medium">{d.title}</h3>
            <span className="rounded bg-accent px-2 py-0.5 text-xs">{d.type}</span>
          </div>
          {hasSprite(mod, `drones/${d.name.toLowerCase()}_sheet.png`) && (
            <div className="my-2">
              <img
                src={api.getSpriteUrl(mod.name, `drones/${d.name.toLowerCase()}_sheet.png`)}
                alt={d.title}
                className="h-10 object-contain"
                style={{ imageRendering: "pixelated" }}
              />
            </div>
          )}
          <p className="mb-3 text-sm text-muted-foreground">{d.desc}</p>
          <div className="grid grid-cols-3 gap-2 text-xs">
            <div><span className="text-muted-foreground">Power:</span> {d.power}</div>
            <div><span className="text-muted-foreground">Cost:</span> {d.cost}</div>
            {d.cooldown && <div><span className="text-muted-foreground">Cooldown:</span> {d.cooldown}s</div>}
            {d.speed && <div><span className="text-muted-foreground">Speed:</span> {d.speed}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}

function AugmentsTab({ mod }: { mod: ModDetail }) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {mod.augments.map((a) => (
        <div key={a.name} className="rounded-lg border border-border bg-card p-4">
          <h3 className="mb-1 font-medium">{a.title}</h3>
          <p className="mb-3 text-sm text-muted-foreground">{a.desc}</p>
          <div className="flex gap-4 text-xs">
            <div><span className="text-muted-foreground">Cost:</span> {a.cost}</div>
            {a.value !== undefined && <div><span className="text-muted-foreground">Value:</span> {a.value}</div>}
            {a.stackable && <span className="text-success">Stackable</span>}
          </div>
        </div>
      ))}
    </div>
  );
}

function CrewTab({ mod }: { mod: ModDetail }) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {mod.crew.map((c) => (
        <div key={c.name} className="rounded-lg border border-border bg-card p-4">
          <h3 className="mb-1 font-medium">{c.title}</h3>
          <p className="mb-3 text-sm text-muted-foreground">{c.desc}</p>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div><span className="text-muted-foreground">Health:</span> {c.max_health}</div>
            <div><span className="text-muted-foreground">Speed:</span> {c.move_speed}</div>
            <div><span className="text-muted-foreground">Repair:</span> {c.repair_speed}</div>
            <div><span className="text-muted-foreground">Damage:</span> {c.damage_multiplier}x</div>
            <div><span className="text-muted-foreground">Cost:</span> {c.cost}</div>
            <div className="flex gap-2">
              {!c.can_burn && <span className="text-warning">Fire immune</span>}
              {!c.can_suffocate && <span className="text-primary">No O2</span>}
              {c.provide_power && <span className="text-success">+Power</span>}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function EventsTab({ mod }: { mod: ModDetail }) {
  return (
    <div className="space-y-4">
      {mod.events.map((e) => (
        <div key={e.name} className="rounded-lg border border-border bg-card p-4">
          <div className="mb-1 flex items-center gap-2">
            <h3 className="font-medium">{e.name}</h3>
            {e.unique && <span className="rounded bg-warning/20 px-2 py-0.5 text-xs text-warning">Unique</span>}
            {e.hostile && <span className="rounded bg-destructive/20 px-2 py-0.5 text-xs text-destructive">Hostile</span>}
          </div>
          <p className="mb-3 text-sm">{e.text}</p>
          {e.choices.length > 0 && (
            <div className="space-y-2">
              {e.choices.map((choice, i) => (
                <div key={i} className="rounded border border-border bg-background p-2 text-sm">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-primary">{i + 1}.</span>
                    <span>{choice.text}</span>
                    {choice.req && (
                      <span className="rounded bg-accent px-1.5 py-0.5 text-xs text-muted-foreground">
                        req: {choice.req}
                      </span>
                    )}
                  </div>
                  {choice.event?.text && (
                    <p className="mt-1 pl-5 text-xs text-muted-foreground">
                      {choice.event.text}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function SpritesTab({ mod }: { mod: ModDetail }) {
  if (!mod.sprite_files.length) {
    return <p className="text-muted-foreground">No sprites in this mod.</p>;
  }
  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-4">
      {mod.sprite_files.map((path) => (
        <div key={path} className="rounded-lg border border-border bg-card p-3 text-center">
          <img
            src={api.getSpriteUrl(mod.name, path)}
            alt={path}
            className="mx-auto mb-2 max-h-24 object-contain"
            style={{ imageRendering: "pixelated" }}
          />
          <div className="truncate text-xs text-muted-foreground">{path}</div>
        </div>
      ))}
    </div>
  );
}

function XmlTab({ mod }: { mod: ModDetail }) {
  const [tab, setTab] = useState<"blueprints" | "events" | "animations" | "metadata">("blueprints");
  const xmlContent: Record<string, string> = {
    blueprints: mod.blueprints_xml,
    events: mod.events_xml,
    animations: mod.animations_xml,
    metadata: mod.metadata_xml,
  };

  return (
    <div>
      <div className="mb-3 flex gap-2">
        {(["blueprints", "events", "animations", "metadata"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={cn(
              "rounded px-2 py-1 text-xs transition-colors",
              tab === t ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground",
            )}
          >
            {t}.xml
          </button>
        ))}
      </div>
      <pre className="max-h-[600px] overflow-auto rounded-lg border border-border bg-card p-4 text-xs">
        {xmlContent[tab] || "(empty)"}
      </pre>
    </div>
  );
}

function LaunchMonitor({ onClose }: { onClose: () => void }) {
  const [logData, setLogData] = useState<FtlLogResponse | null>(null);
  const [copied, setCopied] = useState(false);
  const logEndRef = useRef<HTMLDivElement>(null);

  // Poll GET /ftl-log every second
  useEffect(() => {
    let active = true;
    async function poll() {
      while (active) {
        try {
          const data = await api.getFtlLog();
          if (active) setLogData(data);
        } catch { /* ignore */ }
        await new Promise((r) => setTimeout(r, 1000));
      }
    }
    poll();
    return () => { active = false; };
  }, []);

  // Auto-scroll to bottom
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logData?.log_lines.length]);

  function copyToClipboard() {
    if (!logData) return;
    const text = [
      `FTL Launch Log${logData.mod_name ? ` - ${logData.mod_name}` : ""}`,
      `Process: ${logData.running ? "Running" : `Stopped (code ${logData.exit_code})`}`,
      "",
      logData.log_lines.join("\n"),
    ].join("\n");
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div className="rounded-md border border-primary/50 bg-card p-4">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-primary" />
          <h3 className="font-medium">Launch Monitor{logData?.mod_name ? `: ${logData.mod_name}` : ""}</h3>
          {logData && (
            <span className={cn(
              "flex items-center gap-1 rounded px-2 py-0.5 text-xs",
              logData.running ? "bg-success/10 text-success" : "bg-muted text-muted-foreground",
            )}>
              {logData.running && <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-success" />}
              {logData.running ? "Running" : `Stopped (${logData.exit_code ?? "?"})`}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={copyToClipboard}
            className="flex items-center gap-1 rounded border border-border px-2 py-1 text-xs transition-colors hover:bg-accent"
          >
            <Copy className="h-3 w-3" />
            {copied ? "Copied!" : "Copy"}
          </button>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      <pre className="max-h-72 overflow-auto rounded border border-border bg-background p-2 font-mono text-xs leading-relaxed">
        {logData?.log_lines.length
          ? logData.log_lines.map((line, i) => (
              <div key={i} className={cn(
                /error|exception|fatal|failed/i.test(line) && "text-destructive",
              )}>{line}</div>
            ))
          : <span className="text-muted-foreground">Waiting for FTL output...</span>}
        <div ref={logEndRef} />
      </pre>
    </div>
  );
}

export function ModDetailPage() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const { data: mod, isLoading, error } = useMod(name ?? "");
  const deleteMod = useDeleteMod();
  const validateMod = useValidate();
  const patchMod = usePatch();
  const patchAndRun = usePatchAndRun();
  const [tab, setTab] = useState<Tab>("weapons");
  const [testLoadout, setTestLoadout] = useState(true);
  const [launchMenuOpen, setLaunchMenuOpen] = useState(false);
  const [showLaunchMonitor, setShowLaunchMonitor] = useState(false);
  const launchMenuRef = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (launchMenuRef.current && !launchMenuRef.current.contains(e.target as Node)) {
        setLaunchMenuOpen(false);
      }
    }
    if (launchMenuOpen) document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [launchMenuOpen]);

  if (isLoading) {
    return <div className="py-20 text-center text-muted-foreground">Loading...</div>;
  }
  if (error || !mod) {
    return <div className="py-20 text-center text-destructive">Mod not found</div>;
  }

  // Pick default tab based on content
  const defaultTab = mod.weapons.length ? "weapons"
    : mod.drones.length ? "drones"
    : mod.augments.length ? "augments"
    : mod.crew.length ? "crew"
    : mod.events.length ? "events"
    : "xml";

  const activeTab = tab === "weapons" && !mod.weapons.length ? defaultTab : tab;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <button onClick={() => navigate("/mods")} className="text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-5 w-5" />
          </button>
          <div>
            <h1 className="text-2xl font-bold">{mod.name}</h1>
            {mod.description && (
              <p className="text-sm text-muted-foreground">{mod.description}</p>
            )}
          </div>
        </div>

        <div className="flex gap-2">
          <button
            onClick={() => validateMod.mutate(mod.name)}
            className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-sm transition-colors hover:bg-accent"
            disabled={validateMod.isPending}
          >
            <CheckCircle className="h-3.5 w-3.5" />
            {validateMod.isPending ? "..." : "Validate"}
          </button>
          <button
            onClick={() => patchMod.mutate({ name: mod.name, testLoadout })}
            className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-sm transition-colors hover:bg-accent"
            disabled={patchMod.isPending}
          >
            <Play className="h-3.5 w-3.5" />
            {patchMod.isPending ? "..." : "Patch"}
          </button>
          <div ref={launchMenuRef} className="relative flex">
            <button
              onClick={() => {
                patchAndRun.mutate({ name: mod.name, testLoadout }, {
                  onSuccess: () => setShowLaunchMonitor(true),
                });
              }}
              className="flex items-center gap-1.5 rounded-l-md bg-success px-3 py-1.5 text-sm text-white transition-colors hover:bg-success/90"
              disabled={patchAndRun.isPending}
            >
              <Rocket className="h-3.5 w-3.5" />
              {patchAndRun.isPending ? "..." : "Patch & Run"}
            </button>
            <button
              onClick={() => setLaunchMenuOpen((v) => !v)}
              className="flex items-center rounded-r-md border-l border-success/40 bg-success px-1.5 py-1.5 text-white transition-colors hover:bg-success/90"
              disabled={patchAndRun.isPending}
            >
              <ChevronDown className="h-3.5 w-3.5" />
            </button>
            {launchMenuOpen && (
              <div className="absolute right-0 top-full z-10 mt-1 w-56 rounded-md border border-border bg-card p-2 shadow-lg">
                <label className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm hover:bg-accent">
                  <input
                    type="checkbox"
                    checked={testLoadout}
                    onChange={(e) => setTestLoadout(e.target.checked)}
                    className="rounded"
                  />
                  Replace Kestrel weapon
                </label>
              </div>
            )}
          </div>
          {mod.has_ftl && (
            <a
              href={api.getModDownloadUrl(mod.name)}
              className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-sm transition-colors hover:bg-accent"
            >
              <Download className="h-3.5 w-3.5" />
              Download
            </a>
          )}
          <button
            onClick={() => {
              if (confirm(`Delete ${mod.name}?`)) {
                deleteMod.mutate(mod.name, { onSuccess: () => navigate("/mods") });
              }
            }}
            className="flex items-center gap-1.5 rounded-md border border-destructive/50 px-3 py-1.5 text-sm text-destructive transition-colors hover:bg-destructive/10"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Launch Monitor */}
      {showLaunchMonitor && (
        <LaunchMonitor onClose={() => setShowLaunchMonitor(false)} />
      )}

      {/* Status messages */}
      {validateMod.data && (
        <div className={cn("rounded-md p-3 text-sm", validateMod.data.ok ? "bg-success/10 text-success" : "bg-destructive/10 text-destructive")}>
          {validateMod.data.ok ? "Validation passed" : `Validation failed: ${validateMod.data.errors.join(", ")}`}
          {validateMod.data.warnings.length > 0 && (
            <div className="mt-1 text-warning">{validateMod.data.warnings.join(", ")}</div>
          )}
        </div>
      )}
      {patchMod.data && (
        <div className={cn("rounded-md p-3 text-sm", patchMod.data.success ? "bg-success/10 text-success" : "bg-destructive/10 text-destructive")}>
          {patchMod.data.success ? "Mod patched successfully" : patchMod.data.message}
        </div>
      )}
      {patchAndRun.data && (
        <div className={cn("rounded-md p-3 text-sm", patchAndRun.data.success ? "bg-success/10 text-success" : "bg-destructive/10 text-destructive")}>
          {patchAndRun.data.success ? "FTL launched with mod" : patchAndRun.data.message}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border pb-2">
        <TabButton active={activeTab === "weapons"} onClick={() => setTab("weapons")} label="Weapons" count={mod.weapons.length} />
        <TabButton active={activeTab === "drones"} onClick={() => setTab("drones")} label="Drones" count={mod.drones.length} />
        <TabButton active={activeTab === "augments"} onClick={() => setTab("augments")} label="Augments" count={mod.augments.length} />
        <TabButton active={activeTab === "crew"} onClick={() => setTab("crew")} label="Crew" count={mod.crew.length} />
        <TabButton active={activeTab === "events"} onClick={() => setTab("events")} label="Events" count={mod.events.length} />
        <TabButton active={activeTab === "sprites"} onClick={() => setTab("sprites")} label="Sprites" count={mod.sprite_files.length} />
        <TabButton active={activeTab === "xml"} onClick={() => setTab("xml")} label="XML" count={0} />
      </div>

      {/* Tab content */}
      {activeTab === "weapons" && <WeaponsTab mod={mod} />}
      {activeTab === "drones" && <DronesTab mod={mod} />}
      {activeTab === "augments" && <AugmentsTab mod={mod} />}
      {activeTab === "crew" && <CrewTab mod={mod} />}
      {activeTab === "events" && <EventsTab mod={mod} />}
      {activeTab === "sprites" && <SpritesTab mod={mod} />}
      {activeTab === "xml" && <XmlTab mod={mod} />}
    </div>
  );
}
