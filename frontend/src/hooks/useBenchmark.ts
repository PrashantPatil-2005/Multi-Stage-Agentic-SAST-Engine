import { useCallback, useEffect, useRef, useState } from "react";

import {
  getBenchmarkList,
  getBenchmarkReport,
  runBenchmark as runBenchmarkApi,
} from "../api/benchmark";
import type { BenchmarkList, BenchmarkReport } from "../api/benchmark";

export interface BenchmarkState {
  list: BenchmarkList | null;
  report: BenchmarkReport | null;
  selectedId: string | null;
  loading: boolean;
  reportLoading: boolean;
  error: boolean;
  reportError: boolean;
  running: boolean;
  runError: boolean;
  reload: () => void;
  selectReport: (id: string) => void;
  runBenchmark: () => Promise<boolean>;
}

export function useBenchmark(): BenchmarkState {
  const [list, setList] = useState<BenchmarkList | null>(null);
  const [report, setReport] = useState<BenchmarkReport | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [reportLoading, setReportLoading] = useState(false);
  const [error, setError] = useState(false);
  const [reportError, setReportError] = useState(false);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const selectedIdRef = useRef<string | null>(null);
  const loadTokenRef = useRef(0);

  const loadReport = useCallback((id: string) => {
    const token = ++loadTokenRef.current;
    selectedIdRef.current = id;
    setSelectedId(id);
    setReportError(false);
    setReportLoading(true);
    return getBenchmarkReport(id)
      .then((data) => {
        if (token !== loadTokenRef.current) return;
        setReport(data);
      })
      .catch(() => {
        if (token !== loadTokenRef.current) return;
        setReportError(true);
        setReport(null);
      })
      .finally(() => {
        if (token !== loadTokenRef.current) return;
        setReportLoading(false);
      });
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    getBenchmarkList()
      .then((data) => {
        if (cancelled) return;
        setList(data);
        const target =
          selectedIdRef.current ?? data.reports[0]?.benchmark_id ?? null;
        if (target !== null) {
          return loadReport(target);
        }
        setReport(null);
        setReportLoading(false);
      })
      .catch(() => {
        if (cancelled) return;
        setError(true);
        setLoading(false);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [attempt, loadReport]);

  const reload = useCallback(() => setAttempt((n) => n + 1), []);

  const selectReport = useCallback(
    (id: string) => {
      if (id === selectedIdRef.current && !reportError) return;
      void loadReport(id);
    },
    [loadReport, reportError],
  );

  const runBenchmark = useCallback(async () => {
    setRunning(true);
    setRunError(false);
    try {
      const newReport = await runBenchmarkApi("vulnerable_python_app");
      selectedIdRef.current = newReport.benchmark_id;
      setSelectedId(newReport.benchmark_id);
      setReport(newReport);
      try {
        setList(await getBenchmarkList());
      } catch {
        // The run itself succeeded; a stale list is repaired on next load.
      }
      return true;
    } catch {
      setRunError(true);
      return false;
    } finally {
      setRunning(false);
    }
  }, []);

  return {
    list,
    report,
    selectedId,
    loading,
    reportLoading,
    error,
    reportError,
    running,
    runError,
    reload,
    selectReport,
    runBenchmark,
  };
}
