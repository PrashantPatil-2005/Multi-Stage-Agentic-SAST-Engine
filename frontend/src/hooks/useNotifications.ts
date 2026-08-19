import { useCallback, useEffect, useState } from "react";

import {
  getNotifications,
  markNotificationRead,
  markAllNotificationsRead,
} from "../api/notifications";
import type { Notification, NotificationList } from "../api/notifications";

export interface NotificationsState {
  notifications: Notification[];
  unreadCount: number;
  loading: boolean;
  error: boolean;
  reload: () => void;
  markRead: (id: string) => Promise<void>;
  markAllRead: () => Promise<void>;
}

export function useNotifications(): NotificationsState {
  const [data, setData] = useState<NotificationList | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    getNotifications()
      .then((result) => {
        if (cancelled) return;
        setData(result);
        setLoading(false);
      })
      .catch(() => {
        if (cancelled) return;
        setError(true);
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const reload = useCallback(() => setAttempt((n) => n + 1), []);

  const markRead = useCallback(async (id: string) => {
    await markNotificationRead(id);
    setData((prev) => {
      if (!prev) return prev;
      const notifications = prev.notifications.map((n) =>
        n.id === id ? { ...n, read: true } : n,
      );
      return {
        notifications,
        unread_count: notifications.filter((n) => !n.read).length,
      };
    });
  }, []);

  const markAllRead = useCallback(async () => {
    await markAllNotificationsRead();
    setData((prev) => {
      if (!prev) return prev;
      return {
        notifications: prev.notifications.map((n) => ({ ...n, read: true })),
        unread_count: 0,
      };
    });
  }, []);

  return {
    notifications: data?.notifications ?? [],
    unreadCount: data?.unread_count ?? 0,
    loading,
    error,
    reload,
    markRead,
    markAllRead,
  };
}
