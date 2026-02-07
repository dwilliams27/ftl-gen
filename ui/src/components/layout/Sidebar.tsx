import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  FolderOpen,
  Sparkles,
  Shuffle,
  Settings,
} from "lucide-react";
import { cn } from "@/lib/utils.ts";
import { Logo } from "./Logo.tsx";

const NAV_ITEMS = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/mods", icon: FolderOpen, label: "Mods" },
  { to: "/generate", icon: Sparkles, label: "Generate" },
  { to: "/chaos", icon: Shuffle, label: "Chaos" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

export function Sidebar() {
  return (
    <aside className="flex h-screen w-56 flex-col border-r border-border bg-sidebar">
      <div className="flex h-14 items-center gap-2.5 border-b border-border px-4">
        <Logo className="h-6 w-6 text-primary" />
        <span className="text-lg font-bold tracking-tight">
          <span className="text-primary">FTL</span>
          <span className="text-foreground">-Gen</span>
        </span>
      </div>
      <nav className="flex-1 space-y-1 p-2">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === "/"}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                isActive
                  ? "bg-accent text-sidebar-active font-medium"
                  : "text-sidebar-foreground hover:bg-accent hover:text-foreground",
              )
            }
          >
            <item.icon className="h-4 w-4" />
            {item.label}
          </NavLink>
        ))}
      </nav>
      <div className="border-t border-border p-4 text-xs text-muted-foreground">
        v0.1.0
      </div>
    </aside>
  );
}
