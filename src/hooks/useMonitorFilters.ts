import { useMemo, useState } from "react";
import {
  computeSummary,
  isEstablishedTcp,
  matchesActivityQuery,
  matchesAlertDirectionFilter,
  matchesAlertQuery,
  matchesAlertStateFilter,
  matchesConnectionQuery,
  matchesDirectionFilter,
  matchesStateFilter,
  sortActivityEventsByMode,
  sortAlertsByMode,
  sortConnectionsByMode,
  type ConnectionFilter,
  type MonitorDirectionFilter,
  type MonitorSort,
  type MonitorStateFilter
} from "../lib/monitoring";
import type { ActivityEvent, AlertRecord, ConnectionEvent } from "../types";

export function useMonitorFilters(
  connections: ConnectionEvent[],
  alerts: AlertRecord[],
  activity: ActivityEvent[]
) {
  const [activeFilter, setActiveFilter] = useState<ConnectionFilter>("all");
  const [monitorQuery, setMonitorQuery] = useState("");
  const [historyQuery, setHistoryQuery] = useState("");
  const [stateFilter, setStateFilter] = useState<MonitorStateFilter>("all");
  const [directionFilter, setDirectionFilter] = useState<MonitorDirectionFilter>("all");
  const [sortMode, setSortMode] = useState<MonitorSort>("risk");
  const [historyStateFilter, setHistoryStateFilter] = useState<MonitorStateFilter>("all");
  const [historyDirectionFilter, setHistoryDirectionFilter] =
    useState<MonitorDirectionFilter>("all");
  const [historyRiskFilter, setHistoryRiskFilter] = useState<ConnectionFilter>("all");
  const [historySortMode, setHistorySortMode] = useState<MonitorSort>("recent");

  const summary = useMemo(() => computeSummary(connections), [connections]);

  const searchedConnections = useMemo(
    () => connections.filter((connection) => matchesConnectionQuery(connection, monitorQuery)),
    [connections, monitorQuery]
  );

  const riskFilteredConnections = useMemo(
    () =>
      searchedConnections.filter((connection) =>
        activeFilter === "all" ? true : connection.riskLevel === activeFilter
      ),
    [activeFilter, searchedConnections]
  );

  const tabFilteredConnections = useMemo(() => {
    const filtered = riskFilteredConnections.filter(
      (connection) =>
        matchesStateFilter(connection, stateFilter) &&
        matchesDirectionFilter(connection, directionFilter)
    );

    return sortConnectionsByMode(filtered, sortMode);
  }, [directionFilter, riskFilteredConnections, sortMode, stateFilter]);

  const filteredConnections = useMemo(() => tabFilteredConnections, [tabFilteredConnections]);

  const filteredAlerts = useMemo(
    () =>
      sortAlertsByMode(
        alerts.filter(
          (alert) =>
            (activeFilter === "all" ? true : alert.riskLevel === activeFilter) &&
            matchesAlertQuery(alert, monitorQuery) &&
            matchesAlertStateFilter(alert, stateFilter) &&
            matchesAlertDirectionFilter(alert, directionFilter)
        ),
        sortMode
      ),
    [activeFilter, alerts, directionFilter, monitorQuery, sortMode, stateFilter]
  );

  const tabFilteredAlerts = useMemo(
    () =>
      sortAlertsByMode(
        alerts.filter(
          (alert) =>
            matchesAlertQuery(alert, monitorQuery) &&
            matchesAlertStateFilter(alert, stateFilter) &&
            matchesAlertDirectionFilter(alert, directionFilter)
        ),
        sortMode
      ),
    [alerts, directionFilter, monitorQuery, sortMode, stateFilter]
  );

  const establishedConnections = useMemo(
    () => filteredConnections.filter((connection) => isEstablishedTcp(connection)),
    [filteredConnections]
  );
  const tabEstablishedConnections = useMemo(
    () => tabFilteredConnections.filter((connection) => isEstablishedTcp(connection)),
    [tabFilteredConnections]
  );

  const historyEvents = useMemo(
    () =>
      sortActivityEventsByMode(
        activity.filter(
          (event) =>
            (historyRiskFilter === "all"
              ? true
              : event.connection.riskLevel === historyRiskFilter) &&
            matchesActivityQuery(event, historyQuery) &&
            matchesStateFilter(event.connection, historyStateFilter) &&
            matchesDirectionFilter(event.connection, historyDirectionFilter)
        ),
        historySortMode
      ),
    [
      activity,
      historyDirectionFilter,
      historyQuery,
      historyRiskFilter,
      historySortMode,
      historyStateFilter
    ]
  );

  return {
    summary,
    activeFilter,
    setActiveFilter,
    monitorQuery,
    setMonitorQuery,
    historyQuery,
    setHistoryQuery,
    stateFilter,
    setStateFilter,
    directionFilter,
    setDirectionFilter,
    sortMode,
    setSortMode,
    historyStateFilter,
    setHistoryStateFilter,
    historyDirectionFilter,
    setHistoryDirectionFilter,
    historyRiskFilter,
    setHistoryRiskFilter,
    historySortMode,
    setHistorySortMode,
    filteredConnections,
    filteredAlerts,
    tabFilteredAlerts,
    tabFilteredConnections,
    establishedConnections,
    tabEstablishedConnections,
    historyEvents
  };
}
