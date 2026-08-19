/* Typed API client for notifications. Mirrors the backend response models
   in app/api/notifications_models.py (GET /api/notifications). */

import { fetchJson } from "./dashboard";

export interface Notification {
  id: string;
  type: string;
  title: string;
  message: string;
  finding_id: string | null;
  created_at: string;
  read: boolean;
}

export interface NotificationList {
  notifications: Notification[];
  unread_count: number;
}

export function getNotifications(): Promise<NotificationList> {
  return fetchJson<NotificationList>("/api/notifications");
}

export function markNotificationRead(notificationId: string): Promise<void> {
  return fetch(`/api/notifications/${encodeURIComponent(notificationId)}/read`, {
    method: "POST",
  }).then((response) => {
    if (!response.ok) {
      throw new Error(`Failed to mark notification as read: ${response.status}`);
    }
  });
}

export function markAllNotificationsRead(): Promise<void> {
  return fetch("/api/notifications/read-all", {
    method: "POST",
  }).then((response) => {
    if (!response.ok) {
      throw new Error(`Failed to mark all notifications as read: ${response.status}`);
    }
  });
}
