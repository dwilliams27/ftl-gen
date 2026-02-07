import { BrowserRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AppShell } from "@/components/layout/AppShell.tsx";
import { DashboardPage } from "@/pages/DashboardPage.tsx";
import { ModsPage } from "@/pages/ModsPage.tsx";
import { ModDetailPage } from "@/pages/ModDetailPage.tsx";
import { GeneratePage } from "@/pages/GeneratePage.tsx";
import { ChaosPage } from "@/pages/ChaosPage.tsx";
import { SettingsPage } from "@/pages/SettingsPage.tsx";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/mods" element={<ModsPage />} />
            <Route path="/mods/:name" element={<ModDetailPage />} />
            <Route path="/generate" element={<GeneratePage />} />
            <Route path="/chaos" element={<ChaosPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
