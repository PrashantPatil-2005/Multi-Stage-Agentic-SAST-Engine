import { useState } from "react";

import { BenchmarkDisclaimer } from "../components/benchmark/BenchmarkDisclaimer";
import { BenchmarkHistory } from "../components/benchmark/BenchmarkHistory";
import { BenchmarkStatus } from "../components/benchmark/BenchmarkStatus";
import { FindingsComparison } from "../components/benchmark/FindingsComparison";
import { GroundTruthCard } from "../components/benchmark/GroundTruthCard";
import { MetricsComparison } from "../components/benchmark/MetricsComparison";
import { ScannerMetricsCard } from "../components/benchmark/ScannerMetricsCard";
import { SemgrepMetricsCard } from "../components/benchmark/SemgrepMetricsCard";
import { statusFromSummary } from "../components/benchmark/benchmarkHelpers";
import "../components/benchmark/benchmark.css";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { useBenchmark } from "../hooks/useBenchmark";

function StatusSkeleton() {
  return (
    <Card>
      <div className="bmk-skeleton bmk-skeleton--kpi" aria-hidden="true" />
    </Card>
  );
}

function KpiGridSkeleton() {
  return (
    <div className="bmk-kpi-grid" aria-hidden="true">
      {[0, 1, 2].map((index) => (
        <div key={index} className="bmk-skeleton bmk-skeleton--kpi" />
      ))}
    </div>
  );
}

function ScannerGridSkeleton() {
  return (
    <div className="bmk-scanner-grid" aria-hidden="true">
      <div className="bmk-skeleton bmk-skeleton--metrics" />
      <div className="bmk-skeleton bmk-skeleton--metrics" />
    </div>
  );
}

function TableSkeleton({ title }: { title: string }) {
  return (
    <Card title={title}>
      <div className="bmk-skeleton bmk-skeleton--table" aria-hidden="true" />
    </Card>
  );
}

export function BenchmarkPage() {
  const {
    list,
    report,
    selectedId,
    loading,
    error,
    reportError,
    running,
    runError,
    reload,
    selectReport,
    runBenchmark,
  } = useBenchmark();
  const [confirmOpen, setConfirmOpen] = useState(false);

  const selectedSummary =
    list?.reports.find((r) => r.benchmark_id === selectedId) ??
    list?.reports[0] ??
    null;
  const status = running
    ? "Running"
    : selectedSummary !== null
      ? statusFromSummary(selectedSummary)
      : null;
  const reportReady = report !== null && report.benchmark_id === selectedId;
  const ourMetrics = report?.metrics.find((m) => m.tool === "our-sast") ?? null;
  const semgrepMetrics =
    report?.metrics.find((m) => m.tool === "semgrep") ?? null;

  const startRun = async () => {
    setConfirmOpen(false);
    await runBenchmark();
  };

  return (
    <div className="bmk-page">
      <PageHeader
        title="Security Benchmark"
        description="Controlled comparison of our scanner against Semgrep"
        actions={
          <>
            <Button
              variant="secondary"
              disabled={running}
              onClick={() => setConfirmOpen(true)}
            >
              {running ? "Running..." : "Run Benchmark"}
            </Button>
            <Button variant="secondary" onClick={reload}>
              Refresh
            </Button>
          </>
        }
      />

      {loading ? (
        <div aria-busy="true">
          <div className="bmk-section">
            <StatusSkeleton />
          </div>
          <div className="bmk-section">
            <KpiGridSkeleton />
          </div>
          <div className="bmk-section">
            <ScannerGridSkeleton />
          </div>
          <div className="bmk-section">
            <TableSkeleton title="Benchmark Comparison" />
          </div>
          <TableSkeleton title="Benchmark Runs" />
        </div>
      ) : error && list === null ? (
        <Card>
          <div
            className="dash-error"
            role="alert"
            aria-label="Benchmark data error"
          >
            <p className="dash-error__text">
              Unable to load benchmark results.
            </p>
            <Button variant="secondary" onClick={reload}>
              Retry
            </Button>
          </div>
        </Card>
      ) : !list?.has_reports ? (
        <Card aria-label="Benchmark empty state">
          <div className="risk-empty">
            <h2 className="risk-empty__title">No benchmark results</h2>
            <p className="risk-empty__text">
              Run the benchmark against the controlled fixture to generate
              comparison results.
            </p>
            <div className="bmk-run-confirm__actions">
              <Button
                variant="secondary"
                onClick={() => setConfirmOpen(true)}
              >
                Run Benchmark
              </Button>
            </div>
          </div>
        </Card>
      ) : (
        <>
          {runError ? (
            <Card>
              <div
                className="dash-error"
                role="alert"
                aria-label="Benchmark run error"
              >
                <p className="dash-error__text">
                  Unable to run the benchmark.
                </p>
              </div>
            </Card>
          ) : null}

          {status !== null ? (
            <div className="bmk-section">
              <BenchmarkStatus
                status={status}
                detail={selectedSummary?.semgrep_error ?? null}
              />
            </div>
          ) : null}
          <div className="bmk-section">
            <BenchmarkDisclaimer />
          </div>

          {reportReady ? (
            <>
              <div className="bmk-section">
                <GroundTruthCard
                  fixture={report.fixture}
                  groundTruthCases={report.ground_truth_count}
                  vulnerable={selectedSummary?.vulnerable_cases ?? null}
                  safe={selectedSummary?.safe_cases ?? null}
                />
              </div>
              <div className="bmk-section bmk-scanner-grid">
                <ScannerMetricsCard
                  title="Our Scanner"
                  metrics={ourMetrics}
                  result={report.our_result}
                />
                <SemgrepMetricsCard
                  result={report.semgrep_result}
                  metrics={semgrepMetrics}
                />
              </div>
              <div className="bmk-section">
                <MetricsComparison
                  our={ourMetrics}
                  semgrep={semgrepMetrics}
                  ourDuration={report.our_result.duration_ms}
                  semgrepDuration={report.semgrep_result.duration_ms}
                />
              </div>
              <div className="bmk-section">
                <FindingsComparison
                  comparison={report.comparison}
                  semgrepAvailable={report.semgrep_result.available}
                />
              </div>
            </>
          ) : (
            <>
              {reportError ? (
                <Card>
                  <div
                    className="dash-error"
                    role="alert"
                    aria-label="Benchmark report error"
                  >
                    <p className="dash-error__text">
                      Unable to load the selected benchmark report.
                    </p>
                    <Button
                      variant="secondary"
                      onClick={() => {
                        if (selectedId !== null) selectReport(selectedId);
                      }}
                    >
                      Retry
                    </Button>
                  </div>
                </Card>
              ) : (
                <>
                  <div className="bmk-section">
                    <KpiGridSkeleton />
                  </div>
                  <div className="bmk-section">
                    <ScannerGridSkeleton />
                  </div>
                  <div className="bmk-section">
                    <TableSkeleton title="Benchmark Comparison" />
                  </div>
                </>
              )}
            </>
          )}

          <div className="bmk-section">
            <BenchmarkHistory
              summaries={list.reports}
              selectedId={selectedId}
              onSelect={selectReport}
            />
          </div>
        </>
      )}

      {confirmOpen ? (
        <Card
          className="bmk-run-confirm"
          title="Run the benchmark against the controlled fixture?"
          aria-label="Run the benchmark against the controlled fixture?"
        >
          <ul className="bmk-run-confirm__list">
            <li>
              This is a controlled benchmark against the vulnerable_python_app
              fixture.
            </li>
            <li>
              Semgrep must already be installed in the backend environment.
            </li>
            <li>
              Results are fixture-specific and are not a claim of real-world
              accuracy.
            </li>
          </ul>
          <div className="bmk-run-confirm__actions">
            <Button
              variant="primary"
              disabled={running}
              onClick={() => void startRun()}
            >
              Run
            </Button>
            <Button
              variant="secondary"
              disabled={running}
              onClick={() => setConfirmOpen(false)}
            >
              Cancel
            </Button>
          </div>
        </Card>
      ) : null}
    </div>
  );
}
