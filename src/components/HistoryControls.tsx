import type {
  ConnectionFilter,
  MonitorDirectionFilter,
  MonitorSort,
  MonitorStateFilter
} from "../lib/monitoring";

interface HistoryControlsProps {
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
}

export function HistoryControls({
  riskFilter,
  onRiskFilterChange,
  stateFilter,
  onStateFilterChange,
  directionFilter,
  onDirectionFilterChange,
  sortMode,
  onSortModeChange,
  query,
  onQueryChange
}: HistoryControlsProps) {
  return (
    <section className="monitor-controls">
      <label className="monitor-controls__field">
        <span className="detail-label">Risk</span>
        <select
          value={riskFilter}
          onChange={(event) => onRiskFilterChange(event.target.value as ConnectionFilter)}
        >
          <option value="all">All risk levels</option>
          <option value="safe">Secure</option>
          <option value="unknown">Unidentified</option>
          <option value="suspicious">Suspicious</option>
        </select>
      </label>
      <label className="monitor-controls__field">
        <span className="detail-label">State</span>
        <select
          value={stateFilter}
          onChange={(event) => onStateFilterChange(event.target.value as MonitorStateFilter)}
        >
          <option value="all">All states</option>
          <option value="active">Active</option>
          <option value="passive">Passive</option>
          <option value="established">Established</option>
          <option value="listening">Listening</option>
          <option value="closed">Closed / cleanup</option>
        </select>
      </label>
      <label className="monitor-controls__field">
        <span className="detail-label">Direction</span>
        <select
          value={directionFilter}
          onChange={(event) =>
            onDirectionFilterChange(event.target.value as MonitorDirectionFilter)
          }
        >
          <option value="all">All directions</option>
          <option value="incoming">Incoming</option>
          <option value="outgoing">Outgoing</option>
          <option value="listening">Listening</option>
          <option value="closing">Closing</option>
          <option value="closed">Closed</option>
        </select>
      </label>
      <label className="monitor-controls__field">
        <span className="detail-label">Sort</span>
        <select
          value={sortMode}
          onChange={(event) => onSortModeChange(event.target.value as MonitorSort)}
        >
          <option value="recent">Most recent</option>
          <option value="risk">Highest risk</option>
          <option value="process">Process</option>
          <option value="remote">Remote endpoint</option>
          <option value="local">Local endpoint</option>
          <option value="score">Risk score</option>
          <option value="confidence">Confidence</option>
        </select>
      </label>
      <label className="monitor-controls__field monitor-controls__field--search">
        <span className="detail-label">Search</span>
        <input
          type="search"
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          placeholder="Search process, change type, IP, port or reason"
        />
      </label>
    </section>
  );
}
