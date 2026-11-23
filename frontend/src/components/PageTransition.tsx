import { useLocation } from "react-router-dom";
import type { ReactNode } from "react";

/**
 * Re-mounts (via a location key) and replays an entrance animation on every
 * route change, so navigating between pages feels like a smooth transition
 * rather than an instant swap. Disabled automatically under reduced-motion
 * (the keyframe collapses to ~0ms via the global media query).
 */
export function PageTransition({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  return (
    <div key={pathname} className="animate-fade-up">
      {children}
    </div>
  );
}
