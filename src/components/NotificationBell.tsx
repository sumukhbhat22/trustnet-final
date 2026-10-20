import { useCallback, useEffect, useState } from "react";
import { Bell } from "lucide-react";
import { mlBackendService } from "@/services/mlBackendService";

/** Shows the real unread count from GET /api/notifications/unread-count (no placeholder data). */
export default function NotificationBell() {
  const [count, setCount] = useState<number | null>(null);
  const [failed, setFailed] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const result = await mlBackendService.getUnreadNotificationCount();
      setCount(result.unread_count);
      setFailed(false);
    } catch {
      setFailed(true);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 30000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const markAll = async () => {
    try {
      const result = await mlBackendService.markNotificationRead();
      setCount(result.unread_count);
    } catch {
      setFailed(true);
    }
  };

  return (
    <button
      type="button"
      onClick={() => void markAll()}
      title={failed ? "Notifications unavailable" : "Mark all notifications read"}
      aria-label={`Notifications, ${count ?? "unknown"} unread`}
      className="relative inline-flex items-center px-2 py-1 rounded border border-border text-muted-foreground hover:text-foreground"
    >
      <Bell className="h-3.5 w-3.5" />
      {!failed && count !== null && count > 0 && (
        <span className="ml-1 text-[9px] font-mono text-foreground">{count}</span>
      )}
    </button>
  );
}
