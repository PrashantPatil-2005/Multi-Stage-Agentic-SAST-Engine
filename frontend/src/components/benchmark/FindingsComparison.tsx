import type { BenchmarkComparison, BenchmarkFinding } from "../../api/benchmark";
import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";

export interface FindingsComparisonProps {
  comparison: BenchmarkComparison;
  semgrepAvailable: boolean;
}

interface Section {
  key: string;
  title: string;
  status: string;
  tone: "neutral" | "success" | "warning" | "danger" | "info";
  findings: BenchmarkFinding[];
}

export function FindingsComparison({
  comparison,
  semgrepAvailable,
}: FindingsComparisonProps) {
  if (!semgrepAvailable) {
    return (
      <Card className="bmk-compare" aria-label="Findings Comparison">
        <p className="bmk-compare__unavailable">
          Comparison unavailable because Semgrep did not run.
        </p>
      </Card>
    );
  }

  const sections: Section[] = [
    {
      key: "shared",
      title: "Shared Findings",
      status: "Shared",
      tone: "success",
      findings: comparison.shared_findings,
    },
    {
      key: "ours-only",
      title: "Our Scanner Only",
      status: "Our Scanner Only",
      tone: "neutral",
      findings: comparison.ours_only,
    },
    {
      key: "semgrep-only",
      title: "Semgrep Only",
      status: "Semgrep Only",
      tone: "info",
      findings: comparison.semgrep_only,
    },
  ];

  return (
    <Card className="bmk-compare" aria-label="Findings Comparison">
      {comparison.shared_vulnerability_types.length > 0 ? (
        <p className="bmk-compare__note">
          Shared vulnerability types:{" "}
          <span className="bmk-compare__chips">
            {comparison.shared_vulnerability_types.map((type) => (
              <Badge key={type} tone="neutral">
                {type}
              </Badge>
            ))}
          </span>
        </p>
      ) : null}
      {comparison.safe_cases_detected_incorrectly.length > 0 ? (
        <p className="bmk-compare__note">
          Safe cases detected incorrectly:{" "}
          {comparison.safe_cases_detected_incorrectly.join(", ")}
        </p>
      ) : null}

      {sections.map((section) => (
        <section key={section.key} className="bmk-findings-section">
          <h4 className="bmk-findings-section__title">
            {section.title} ({section.findings.length})
          </h4>
          {section.findings.length === 0 ? (
            <p className="bmk-compare__note">None</p>
          ) : (
            <table className="bmk-table">
              <thead>
                <tr>
                  <th scope="col">Vulnerability</th>
                  <th scope="col">File</th>
                  <th scope="col">Line</th>
                  <th scope="col">Match Status</th>
                </tr>
              </thead>
              <tbody>
                {section.findings.map((finding) => (
                  <tr key={finding.fingerprint}>
                    <td>{finding.vulnerability_type}</td>
                    <td className="bmk-table__mono">{finding.file}</td>
                    <td className="bmk-table__mono">{finding.line}</td>
                    <td>
                      <Badge tone={section.tone}>{section.status}</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      ))}
    </Card>
  );
}
