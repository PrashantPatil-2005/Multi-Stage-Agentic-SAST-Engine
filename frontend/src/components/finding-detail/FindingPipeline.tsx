import type { FindingDetail } from "../../api/findingDetail";
import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import {
  approvalStatusLabel,
  formatTimestamp,
  proofStatusLabel,
  slaStatusLabel,
  verdictLabel,
} from "./detailHelpers";
import { formatConfidence } from "../findings/findingsHelpers";

export interface PipelineStage {
  name: string;
  state: string;
  result: string | null;
  timestamp: string | null;
  tone: "neutral" | "success" | "warning" | "danger" | "info";
}

function StageItem({ stage }: { stage: PipelineStage }) {
  const completed = stage.state !== "Not completed";
  return (
    <li className="fd-pipeline__stage" aria-label={`${stage.name} stage`}>
      <span className="fd-pipeline__marker" aria-hidden="true" />
      <div className="fd-pipeline__body">
        <div className="fd-pipeline__head">
          <span className="fd-pipeline__name">{stage.name}</span>
          <Badge tone={completed ? stage.tone : "neutral"}>{stage.state}</Badge>
          {stage.timestamp ? (
            <time className="fd-pipeline__time" dateTime={stage.timestamp ?? undefined}>
              {formatTimestamp(stage.timestamp)}
            </time>
          ) : null}
        </div>
        {stage.result ? (
          <p className="fd-pipeline__result">{stage.result}</p>
        ) : null}
      </div>
    </li>
  );
}

export function FindingPipeline({ detail }: { detail: FindingDetail }) {
  const dedup = detail.dedup;
  const risk = detail.risk;
  const sla = detail.sla;
  const validation = detail.validation;
  const proof = detail.proof;
  const approval = detail.approval;

  const stages: PipelineStage[] = [
    {
      name: "SCAN",
      state: "Detected",
      result: detail.vulnerability_type
        ? `${detail.source.file}:${detail.source.line} → ${detail.sink.file}:${detail.sink.line}`
        : null,
      timestamp: null,
      tone: "neutral",
    },
    dedup
      ? {
          name: "DEDUP",
          state: dedup.is_canonical ? "Canonical finding" : "Group member",
          result: `${dedup.occurrence_count} ${
            dedup.occurrence_count === 1 ? "occurrence" : "occurrences"
          }`,
          timestamp: null,
          tone: dedup.is_canonical ? "success" : "info",
        }
      : {
          name: "DEDUP",
          state: "Not completed",
          result: null,
          timestamp: null,
          tone: "neutral",
        },
    risk
      ? {
          name: "RISK / SLA",
          state: `Score ${risk.risk_score}`,
          result: sla
            ? `${risk.priority} · ${slaStatusLabel(sla.status)}${
                sla.status === "breached" ? " · SLA BREACHED" : ""
              }`
            : risk.priority,
          timestamp: sla?.started_at ?? risk.assessed_at ?? null,
          tone: risk.priority === "P0" || risk.priority === "P1" ? "danger" : "warning",
        }
      : {
          name: "RISK / SLA",
          state: "Not completed",
          result: null,
          timestamp: null,
          tone: "neutral",
        },
    validation
      ? {
          name: "VALIDATE",
          state: verdictLabel(validation.verdict),
          result: `Confidence ${formatConfidence(validation.confidence)}`,
          timestamp: validation.validated_at,
          tone:
            validation.verdict === "true_positive"
              ? "success"
              : validation.verdict === "false_positive"
                ? "info"
                : "warning",
        }
      : {
          name: "VALIDATE",
          state: "Not completed",
          result: null,
          timestamp: null,
          tone: "neutral",
        },
    proof
      ? {
          name: "PROVE",
          state: proofStatusLabel(proof.status),
          result: proof.summary || null,
          timestamp: proof.created_at,
          tone: proof.status === "verified" ? "success" : "warning",
        }
      : {
          name: "PROVE",
          state: "Not completed",
          result: null,
          timestamp: null,
          tone: "neutral",
        },
    approval
      ? {
          name: "APPROVAL",
          state: approvalStatusLabel(approval.status),
          result: approval.requested_by
            ? `Requested by ${approval.requested_by}`
            : null,
          timestamp: approval.requested_at,
          tone:
            approval.status === "approved"
              ? "success"
              : approval.status === "rejected"
                ? "danger"
                : "warning",
        }
      : {
          name: "APPROVAL",
          state: "Not completed",
          result: null,
          timestamp: null,
          tone: "neutral",
        },
  ];

  return (
    <Card title="Security Pipeline">
      <ol className="fd-pipeline">
        {stages.map((stage) => (
          <StageItem key={stage.name} stage={stage} />
        ))}
      </ol>
      <p className="fd-pipeline__note">
        Pipeline steps without recorded data show “Not completed” — they are
        never assumed to have happened.
      </p>
    </Card>
  );
}
