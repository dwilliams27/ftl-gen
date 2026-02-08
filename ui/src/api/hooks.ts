import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "./client.ts";

export function useConfig() {
  return useQuery({
    queryKey: ["config"],
    queryFn: api.getConfig,
    staleTime: 60_000,
  });
}

export function useMods() {
  return useQuery({
    queryKey: ["mods"],
    queryFn: api.listMods,
    staleTime: 10_000,
  });
}

export function useMod(name: string) {
  return useQuery({
    queryKey: ["mods", name],
    queryFn: () => api.getMod(name),
    enabled: !!name,
  });
}

export function useDeleteMod() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api.deleteMod(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mods"] });
    },
  });
}

export function useValidate() {
  return useMutation({
    mutationFn: (name: string) => api.validate(name),
  });
}

export function usePatch() {
  return useMutation({
    mutationFn: ({ name, testLoadout }: { name: string; testLoadout?: boolean }) =>
      api.patch(name, testLoadout),
  });
}

export function usePatchAndRun() {
  return useMutation({
    mutationFn: ({ name, testLoadout }: { name: string; testLoadout?: boolean }) =>
      api.patchAndRun(name, testLoadout),
  });
}

