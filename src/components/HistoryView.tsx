import { ActivityHistoryPanel } from "./ActivityHistoryPanel";
import { HistoryControls } from "./HistoryControls";
import type {
  ConnectionFilter,
  MonitorDirectionFilter,
  MonitorSort,
  MonitorStateFilter
} from "../lib/monitoring";
import type { ActivityEvent } from "../types";

interface HistoryViewProps {
  riskFilter: ConnectionFilter;
  onRiskFilterChange: (value: ConnectionFilter) => void;
  stateFilter: MonitorStateFilter;
  onStateFilterChange: (value: MonitorStateFilter) => void;
  directionFilter: MonitorDirectionFilter;
  onDirectionFilterChange: (value: MonitorDirectionFilter) => void;
  sortMode: MonitorSort;
  onSortModeChange: (value: MonitorSort) => void;
  query: string;
  onQueryChange: (value: string) => void;
  events: ActivityEvent[];
  selectedId: string | null;
  onSelect: (event: ActivityEvent) => void;
}

export function HistoryView({
  riskFilter,
  onRiskFilterChange,
  stateFilter,
  onStateFilterChange,
  directionFilter,
  onDirectionFilterChange,
  sortMode,
  onSortModeChange,
  query,
  onQueryChange,
  events,
  selectedId,
  onSelect
}: HistoryViewProps) {
  return (
    <>
      <HistoryControls
        riskFilter={riskFilter}
        onRiskFilterChange={onRiskFilterChange}
        stateFilter={stateFilter}
        onStateFilterChange={onStateFilterChange}
        directionFilter={directionFilter}
        onDirectionFilterChange={onDirectionFilterChange}
        sortMode={sortMode}
        onSortModeChange={onSortModeChange}
        query={query}
        onQueryChange={onQueryChange}
      />
      <ActivityHistoryPanel events={events} selectedId={selectedId} onSelect={onSelect} />
    </>
  );
}
