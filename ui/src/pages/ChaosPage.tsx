import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { BouncingDots } from "@/components/ui/BouncingDots.tsx";
import type { GenerationProgress } from "@/lib/types.ts";

export function ChaosPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [level, setLevel] = useState(50);
  const [seed, setSeed] = useState("");
  const [name, setName] = useState("");
  const [unsafe, setUnsafe] = useState(false);

  const [generating, setGenerating] = useState(false);
  const [progress, setProgress] = useState<GenerationProgress[]>([]);
  const [error, setError] = useState<string | null>(null);

  const handleGenerate = useCallback(async () => {
    setGenerating(true);
    setProgress([]);
    setError(null);

    try {
      const body = {
        level: level / 100,
        seed: seed ? parseInt(seed) : undefined,
        unsafe,
        name: name.trim() || undefined,
        test_weapon: false,
        test_drone: false,
        test_augment: false,
      };

      const res = await fetch("/api/v1/chaos", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (!res.ok) throw new Error(await res.text());

      const reader = res.body?.getReader();
      const decoder = new TextDecoder();
      if (!reader) throw new Error("No stream");

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
                setError(data.detail ?? "Chaos generation failed");
              }
            } catch { /* ignore */ }
          }
        }
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setGenerating(false);
    }
  }, [level, seed, name, unsafe, navigate, queryClient]);

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Chaos Mode</h1>
        <p className="text-muted-foreground">Randomize all vanilla items - no LLM, $0.00 cost</p>
      </div>

      <div className="space-y-4 rounded-lg border border-border bg-card p-6">
        {/* Level slider */}
        <div>
          <label className="mb-1 flex justify-between text-sm">
            <span className="font-medium">Chaos Level</span>
            <span className="text-muted-foreground">{level}%</span>
          </label>
          <input
            type="range"
            min={0}
            max={100}
            value={level}
            onChange={(e) => setLevel(parseInt(e.target.value))}
            className="w-full"
            disabled={generating}
          />
          <div className="flex justify-between text-xs text-muted-foreground">
            <span>Subtle</span>
            <span>Extreme</span>
          </div>
        </div>

        {/* Name + Seed */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="mb-1 block text-sm text-muted-foreground">Mod Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={`ChaosMode_${level}`}
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:border-primary focus:outline-none"
              disabled={generating}
            />
          </div>
          <div>
            <label className="mb-1 block text-sm text-muted-foreground">Seed</label>
            <input
              type="text"
              value={seed}
              onChange={(e) => setSeed(e.target.value)}
              placeholder="Random"
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:border-primary focus:outline-none"
              disabled={generating}
            />
          </div>
        </div>

        {/* Unsafe toggle */}
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={unsafe}
            onChange={(e) => setUnsafe(e.target.checked)}
            className="rounded"
            disabled={generating}
          />
          Unsafe mode (remove safety bounds)
        </label>

        <button
          onClick={handleGenerate}
          disabled={generating}
          className="w-full rounded-md bg-warning py-2.5 text-sm font-medium text-black transition-colors hover:bg-warning/90 disabled:opacity-50"
        >
          {generating ? "Randomizing..." : "Generate Chaos Mod"}
        </button>
      </div>

      {/* Progress */}
      {progress.length > 0 && (
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="space-y-1 text-sm">
            {progress.map((p, i) => (
              <div key={i} className="flex items-center gap-3">
                <span className={p.status === "completed" ? "text-success" : "text-primary"}>
                  {p.status === "completed" ? "done" : <BouncingDots />}
                </span>
                <span className="capitalize">{p.step}</span>
                {p.detail && <span className="text-xs text-muted-foreground">{p.detail}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {error && (
        <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">{error}</div>
      )}
    </div>
  );
}
