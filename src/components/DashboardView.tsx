import { AlertList } from "./AlertList";
import { ConnectionControls } from "./ConnectionControls";
import { ConnectionTable } from "./ConnectionTable";
import { EstablishedConnectionsPanel } from "./EstablishedConnectionsPanel";
import { SummaryCard } from "./SummaryCard";
import type {
  ConnectionFilter,
  MonitorDirectionFilter,
  MonitorSort,
  MonitorStateFilter
} from "../lib/monitoring";
import type { AlertRecord, ConnectionEvent, SummaryStats } from "../types";

interface DashboardViewProps {
  summary: SummaryStats;
  activeFilter: ConnectionFilter;
  onToggleSummaryFilter: (filter: ConnectionFilter) => void;
  onRiskFilterChange: (filter: ConnectionFilter) => void;
  onClearFilter: () => void;
  monitorQuery: string;
  onMonitorQueryChange: (value: string) => void;
  stateFilter: MonitorStateFilter;
  onStateFilterChange: (value: MonitorStateFilter) => void;
  directionFilter: MonitorDirectionFilter;
  onDirectionFilterChange: (value: MonitorDirectionFilter) => void;
  sortMode: MonitorSort;
  onSortModeChange: (value: MonitorSort) => void;
  alerts: AlertRecord[];
  selectedAlertId: string | null;
  onSelectAlert: (alert: AlertRecord) => void;
  establishedConnections: ConnectionEvent[];
  selectedConnectionId: string | null;
  onSelectConnection: (connection: ConnectionEvent) => void;
  onOpenEstablishedModal: () => void;
  liveConnections: ConnectionEvent[];
}

export function DashboardView({
  summary,
  activeFilter,
  onToggleSummaryFilter,
  onRiskFilterChange,
  onClearFilter,
  monitorQuery,
  onMonitorQueryChange,
  stateFilter,
  onStateFilterChange,
  directionFilter,
  onDirectionFilterChange,
  sortMode,
  onSortModeChange,
  alerts,
  selectedAlertId,
  onSelectAlert,
  establishedConnections,
  selectedConnectionId,
  onSelectConnection,
  onOpenEstablishedModal,
  liveConnections
}: DashboardViewProps) {
  return (
    <>
      <section className="summary-grid">
        <SummaryCard
          label="Secure"
          value={summary.safe}
          tone="safe"
          detail={activeFilter === "safe" ? "Filter active" : "Allowed or learned traffic"}
          active={activeFilter === "safe"}
          onClick={() => onToggleSummaryFilter("safe")}
        />
        <SummaryCard
          label="Unidentified"
          value={summary.unknown}
          tone="unknown"
          detail={activeFilter === "unknown" ? "Filter active" : "Needs analyst review"}
          active={activeFilter === "unknown"}
          onClick={() => onToggleSummaryFilter("unknown")}
        />
        <SummaryCard
          label="Suspicious"
          value={summary.suspicious}
          tone="suspicious"
          detail={
            activeFilter === "suspicious" ? "Filter active" : "Requires immediate review"
          }
          active={activeFilter === "suspicious"}
          onClick={() => onToggleSummaryFilter("suspicious")}
        />
        <SummaryCard
          label="Total"
          value={summary.total}
          tone="neutral"
          detail={activeFilter === "all" ? "Current snapshot" : "Click to clear filter"}
          active={activeFilter === "all"}
          onClick={onClearFilter}
        />
      </section>

      <ConnectionControls
        riskFilter={activeFilter}
        onRiskFilterChange={onRiskFilterChange}
        stateFilter={stateFilter}
        onStateFilterChange={onStateFilterChange}
        directionFilter={directionFilter}
        onDirectionFilterChange={onDirectionFilterChange}
        sortMode={sortMode}
        onSortModeChange={onSortModeChange}
        query={monitorQuery}
        onQueryChange={onMonitorQueryChange}
        searchPlaceholder="Search process, PID, IP, port or reason"
      />

      <section className="monitor-workspace">
        <AlertList
          alerts={alerts}
          selectedAlertId={selectedAlertId}
          onSelect={onSelectAlert}
        />
        <EstablishedConnectionsPanel
          connections={establishedConnections}
          selectedId={selectedConnectionId}
          onSelect={onSelectConnection}
          onOpenModal={onOpenEstablishedModal}
        />
        <ConnectionTable
          connections={liveConnections}
          selectedId={selectedConnectionId}
          onSelect={onSelectConnection}
        />
      </section>
    </>
  );
}
