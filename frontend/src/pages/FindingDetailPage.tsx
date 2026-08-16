import { Link, useParams } from "react-router-dom";

import { useFindingDetail } from "../hooks/useFindingDetail";
import { useProveFinding } from "../hooks/useProveFinding";
import { useRiskActions } from "../hooks/useRiskActions";
import { useValidateFinding } from "../hooks/useValidateFinding";
import { ApprovalPanel } from "../components/finding-detail/ApprovalPanel";
import { CodeEvidence } from "../components/finding-detail/CodeEvidence";
import { DeduplicationPanel } from "../components/finding-detail/DeduplicationPanel";
import { FindingHeader } from "../components/finding-detail/FindingHeader";
import { FindingPipeline } from "../components/finding-detail/FindingPipeline";
import { ProofPanel } from "../components/finding-detail/ProofPanel";
import { RawFindingData } from "../components/finding-detail/RawFindingData";
import { RiskPanel } from "../components/finding-detail/RiskPanel";
import { SlaPanel } from "../components/finding-detail/SlaPanel";
import { ValidationPanel } from "../components/finding-detail/ValidationPanel";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import "../components/finding-detail/finding-detail.css";

function DetailSkeleton() {
  return (
    <div className="fd-page" aria-busy="true" aria-label="Loading finding detail">
      <div>
        <div className="fd-skeleton" style={{ height: 34, width: "40%" }} />
        <div className="fd-skeleton" style={{ height: 14, width: "25%", marginTop: 12 }} />
        <div className="fd-skeleton" style={{ height: 56, marginTop: 12 }} />
      </div>
      <div className="fd-layout">
        <div className="fd-layout__main">
          <Card title="Security Pipeline">
            <div className="fd-skeleton" style={{ height: 22 }} />
            <div className="fd-skeleton" style={{ height: 22, marginTop: 8 }} />
            <div className="fd-skeleton" style={{ height: 22, marginTop: 8 }} />
            <div className="fd-skeleton" style={{ height: 22, marginTop: 8 }} />
          </Card>
          <Card title="Code Evidence">
            <div className="fd-skeleton" style={{ height: 120 }} />
          </Card>
          <Card title="Validation">
            <div className="fd-skeleton" style={{ height: 80 }} />
          </Card>
        </div>
        <div className="fd-layout__side">
          <Card title="Risk">
            <div className="fd-skeleton" style={{ height: 90 }} />
          </Card>
          <Card title="SLA">
            <div className="fd-skeleton" style={{ height: 70 }} />
          </Card>
        </div>
      </div>
    </div>
  );
}

export function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { detail, loading, notFound, failed, retry } = useFindingDetail(id);
  const riskActions = useRiskActions();
  const validateActions = useValidateFinding();
  const proveActions = useProveFinding();

  async function handleAssessRisk() {
    if (!detail) return;
    if (await riskActions.assess(detail.finding_id)) {
      retry();
    }
  }

  async function handleStartSla() {
    if (!detail) return;
    if (await riskActions.startSla(detail.finding_id)) {
      retry();
    }
  }

  async function handleCheckSla() {
    if (!detail) return;
    if (await riskActions.checkSla(detail.finding_id)) {
      retry();
    }
  }

  async function handleValidateFinding() {
    if (!detail) return;
    if (await validateActions.runValidation(detail.finding_id)) {
      retry();
    }
  }

  async function handleProveFinding() {
    if (!detail) return;
    if (await proveActions.proveFinding(detail.finding_id)) {
      retry();
    }
  }

  if (loading) {
    return <DetailSkeleton />;
  }

  if (notFound) {
    return (
      <Card>
        <div className="fd-error" role="alert" aria-label="Finding not found">
          <p className="fd-error__text">Finding not found</p>
          <Link
            className="ui-button ui-button--secondary ui-button--md"
            to="/findings"
          >
            Back to Findings
          </Link>
        </div>
      </Card>
    );
  }

  if (failed || detail === null) {
    return (
      <Card>
        <div className="fd-error" role="alert" aria-label="Finding load error">
          <p className="fd-error__text">Unable to load finding.</p>
          <Button variant="secondary" onClick={retry}>
            Retry
          </Button>
        </div>
      </Card>
    );
  }

  return (
    <div className="fd-page">
      <FindingHeader detail={detail} />
      <div className="fd-layout">
        <div className="fd-layout__main">
          <FindingPipeline detail={detail} />
          <CodeEvidence detail={detail} />
          <ValidationPanel
            detail={detail}
            onValidate={handleValidateFinding}
            validating={validateActions.validating}
            validateError={validateActions.error}
          />
          <ProofPanel
            detail={detail}
            onProve={handleProveFinding}
            proving={proveActions.proving}
            proveError={proveActions.error}
          />
        </div>
        <div className="fd-layout__side">
          <RiskPanel
            detail={detail}
            onAssess={handleAssessRisk}
            assessing={riskActions.risk.loading}
            riskError={riskActions.risk.error}
          />
          <SlaPanel
            detail={detail}
            onStartSla={handleStartSla}
            slaLoading={riskActions.sla.loading}
            slaError={riskActions.sla.error}
            onCheckSla={handleCheckSla}
            checking={riskActions.check.loading}
            checkError={riskActions.check.error}
          />
          <ApprovalPanel detail={detail} onApprovalChanged={retry} />
          <DeduplicationPanel detail={detail} />
          <RawFindingData detail={detail} />
        </div>
      </div>
    </div>
  );
}
