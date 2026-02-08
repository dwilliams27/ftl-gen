import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { BouncingDots } from "@/components/ui/BouncingDots.tsx";
import type { GenerationProgress } from "@/lib/types.ts";

const STEPS = ["concept", "weapons", "drones", "augments", "crew", "events", "sprites", "building"];

export function GeneratePage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [theme, setTheme] = useState("");
  const [name, setName] = useState("");
  const [weapons, setWeapons] = useState(3);
  const [events, setEvents] = useState(3);
  const [drones, setDrones] = useState(0);
  const [augments, setAugments] = useState(0);
  const [crew, setCrew] = useState(0);
  const [sprites, setSprites] = useState(true);
  const [chaosLevel, setChaosLevel] = useState<number | null>(null);

  const [generating, setGenerating] = useState(false);
  const [progress, setProgress] = useState<GenerationProgress[]>([]);
  const [error, setError] = useState<string | null>(null);

  const handleGenerate = useCallback(async () => {
    if (!theme.trim()) return;

    setGenerating(true);
    setProgress([]);
    setError(null);

    try {
      const body = {
        theme: theme.trim(),
        name: name.trim() || undefined,
        weapons,
        events,
        drones,
        augments,
        crew,
        sprites,
        cache_images: false,
        chaos_level: chaosLevel,
        unsafe: false,
        test_weapon: false,
        test_drone: false,
        test_augment: false,
      };

      const res = await fetch("/api/v1/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        const errText = await res.text();
        throw new Error(errText);
      }

      const reader = res.body?.getReader();
      const decoder = new TextDecoder();

      if (!reader) throw new Error("No response stream");

      let buffer = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (line.startsWith("data:")) {
            try {
              const data = JSON.parse(line.slice(5).trim()) as GenerationProgress;
              setProgress((prev) => [...prev, data]);

              if (data.step === "complete" && data.path) {
                queryClient.invalidateQueries({ queryKey: ["mods"] });
                const modName = data.path.split("/").pop()?.replace(".ftl", "") ?? "";
                setTimeout(() => navigate(`/mods/${encodeURIComponent(modName)}`), 500);
              }
              if (data.step === "error") {
                setError(data.detail ?? "Generation failed");
              }
            } catch {
              // ignore malformed SSE
            }
          }
        }
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setGenerating(false);
    }
  }, [theme, name, weapons, events, drones, augments, crew, sprites, chaosLevel, navigate, queryClient]);

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Generate Mod</h1>
        <p className="text-muted-foreground">Generate themed FTL mod from scratch</p>
      </div>

      <div className="space-y-4 rounded-lg border border-border bg-card p-6">
        {/* Theme */}
        <div>
          <label className="mb-1 block text-sm font-medium">Theme</label>
          <input
            type="text"
            value={theme}
            onChange={(e) => setTheme(e.target.value)}
            placeholder="A faction of rogue scientists with unstable laser weapons"
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:border-primary focus:outline-none"
            disabled={generating}
          />
        </div>

        {/* Name */}
        <div>
          <label className="mb-1 block text-sm font-medium">Name (optional)</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Auto-generated from theme"
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:border-primary focus:outline-none"
            disabled={generating}
          />
        </div>

        {/* Content counts */}
        <div className="grid grid-cols-5 gap-3">
          {([
            ["Weapons", weapons, setWeapons],
            ["Events", events, setEvents],
            ["Drones", drones, setDrones],
            ["Augments", augments, setAugments],
            ["Crew", crew, setCrew],
          ] as const).map(([label, value, setter]) => (
            <div key={label}>
              <label className="mb-1 block text-xs text-muted-foreground">{label}</label>
              <input
                type="number"
                min={0}
                max={10}
                value={value}
                onChange={(e) => (setter as (v: number) => void)(parseInt(e.target.value) || 0)}
                className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-center text-sm focus:border-primary focus:outline-none"
                disabled={generating}
              />
            </div>
          ))}
        </div>

        {/* Options */}
        <div className="flex items-center gap-6 text-sm">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={sprites}
              onChange={(e) => setSprites(e.target.checked)}
              className="rounded"
              disabled={generating}
            />
            Generate sprites
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={chaosLevel !== null}
              onChange={(e) => setChaosLevel(e.target.checked ? 0.5 : null)}
              className="rounded"
              disabled={generating}
            />
            Chaos mode
          </label>
          {chaosLevel !== null && (
            <div className="flex items-center gap-2">
              <input
                type="range"
                min={0}
                max={100}
                value={chaosLevel * 100}
                onChange={(e) => setChaosLevel(parseInt(e.target.value) / 100)}
                className="w-24"
                disabled={generating}
              />
              <span className="text-xs text-muted-foreground">{Math.round(chaosLevel * 100)}%</span>
            </div>
          )}
        </div>

        <button
          onClick={handleGenerate}
          disabled={generating || !theme.trim()}
          className="w-full rounded-md bg-primary py-2.5 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
        >
          {generating ? "Generating..." : "Generate Mod"}
        </button>
      </div>

      {/* Progress */}
      {progress.length > 0 && (
        <div className="rounded-lg border border-border bg-card p-4">
          <h3 className="mb-3 font-medium">Progress</h3>
          <div className="space-y-2">
            {STEPS.map((step) => {
              const events = progress.filter((p) => p.step === step);
              const started = events.some((e) => e.status === "started");
              const completed = events.some((e) => e.status === "completed");
              if (!started && !completed) return null;

              return (
                <div key={step} className="flex items-center gap-3 text-sm">
                  <span className={completed ? "text-success" : "text-primary"}>
                    {completed ? "done" : <BouncingDots />}
                  </span>
                  <span className="capitalize">{step}</span>
                  {events.find((e) => e.items_so_far)?.items_so_far && (
                    <span className="text-xs text-muted-foreground">
                      ({events.find((e) => e.items_so_far)?.items_so_far} items)
                    </span>
                  )}
                </div>
              );
            })}
            {progress.some((p) => p.step === "complete") && (
              <div className="flex items-center gap-3 text-sm text-success">
                <span>done</span>
                <span>Complete! Redirecting...</span>
              </div>
            )}
          </div>
        </div>
      )}

      {error && (
        <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
          {error}
        </div>
      )}
    </div>
  );
}
