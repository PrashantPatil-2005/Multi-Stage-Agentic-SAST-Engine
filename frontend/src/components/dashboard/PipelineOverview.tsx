import type { DashboardPipelineStage } from "../../api/dashboard";
import { Card } from "../ui/Card";
import "./dashboard.css";

export interface PipelineOverviewProps {
  stages: DashboardPipelineStage[];
}

export function PipelineOverview({ stages }: PipelineOverviewProps) {
  return (
    <Card title="Pipeline">
      <ol className="dash-pipeline">
        {stages.map((stage, index) => (
          <li className="dash-pipeline__item" key={stage.stage}>
            {index > 0 ? (
              <span
                className="dash-pipeline__arrow"
                aria-hidden="true"
                data-mobile-label="next stage"
              >
                →
              </span>
            ) : null}
            <div className="dash-pipeline__stage">
              <div className="dash-pipeline__name">
                <span
                  className={`dash-pipeline__dot${
                    stage.count === null ? " dash-pipeline__dot--empty" : ""
                  }`}
                  aria-hidden="true"
                />
                {stage.stage}
              </div>
              <div className="dash-pipeline__count">
                {stage.count_label ?? "Not available"}
              </div>
              <div className="dash-pipeline__description">
                {stage.description}
              </div>
            </div>
          </li>
        ))}
      </ol>
    </Card>
  );
}