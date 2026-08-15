import { useCallback, useEffect, useState } from "react";

import { getFindingDetail, isNotFoundError } from "../api/findingDetail";
import type { FindingDetail } from "../api/findingDetail";

export interface FindingDetailState {
  detail: FindingDetail | null;
  loading: boolean;
  notFound: boolean;
  failed: boolean;
  retry: () => void;
}

export function useFindingDetail(findingId: string | undefined): FindingDetailState {
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!findingId) return;
    let cancelled = false;
    setLoading(true);
    setNotFound(false);
    setFailed(false);
    getFindingDetail(findingId)
      .then((data) => {
        if (cancelled) return;
        setDetail(data);
        setLoading(false);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        if (isNotFoundError(error)) {
          setNotFound(true);
        } else {
          setFailed(true);
        }
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [findingId, attempt]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  return { detail, loading, notFound, failed, retry };
}
