import type { ConnectionEvent } from "../types";

function hasReason(connection: ConnectionEvent, code: string) {
  return connection.reasons.some((reason) => reason.code === code);
}

function normalizeState(state: string) {
  return state.replace(/[^a-z0-9]/gi, "").toLowerCase();
}

function isRecentlyClosed(connection: ConnectionEvent) {
  return normalizeState(connection.state) === "timewait";
}

function isClosing(connection: ConnectionEvent) {
  return normalizeState(connection.state) === "closewait";
}

export function getConnectionRiskLabel(connection: ConnectionEvent) {
  if (isRecentlyClosed(connection)) {
    return "Closed";
  }

  if (hasReason(connection, "legitimate_windows_listener")) {
    return "Legitimate";
  }

  if (isClosing(connection) && connection.riskLevel !== "suspicious") {
    return "Closing";
  }

  if (connection.riskLevel === "safe") {
    return "Secure";
  }

  if (connection.riskLevel === "unknown") {
    return "Unidentified";
  }

  return "Suspicious";
}

export function getConnectionIdentitySummary(connection: ConnectionEvent) {
  if (hasReason(connection, "no_active_process_owner_available")) {
    return "No active process owner available";
  }

  if (hasReason(connection, "windows_system_service_rpc")) {
    return "Windows system service (RPC)";
  }

  if (hasReason(connection, "kernel_managed_service_binding")) {
    return "Kernel-managed service binding";
  }

  if (hasReason(connection, "trusted_svchost_services")) {
    return "Hosted Windows services";
  }

  if (hasReason(connection, "trusted_windows_process_baseline")) {
    return "Trusted Windows process";
  }

  if (connection.process.serviceContextPending || connection.process.metadataPending) {
    return "Resolving...";
  }

  return connection.process.signer ?? (connection.process.isSigned ? "Signed" : "Unsigned");
}

export function getConnectionIdentityStatus(connection: ConnectionEvent) {
  if (hasReason(connection, "no_active_process_owner_available")) {
    return "No active process owner is available for this closed TCP entry.";
  }

  if (hasReason(connection, "kernel_managed_service_binding")) {
    return "Kernel-managed service binding.";
  }

  if (hasReason(connection, "system_listener_metadata_expected")) {
    return "Kernel/system metadata is limited by design for this listener type.";
  }

  if (hasReason(connection, "windows_system_service_rpc")) {
    return "Windows system service using a normal RPC listener pattern.";
  }

  if (hasReason(connection, "trusted_svchost_services")) {
    return `Hosted services: ${connection.process.hostedServices.join(", ")}.`;
  }

  if (connection.process.serviceContextPending) {
    return "Hosted Windows services are still being resolved.";
  }

  if (connection.process.metadataPending) {
    return "Signature and file hash are still being resolved.";
  }

  return connection.process.signer ?? (connection.process.isSigned ? "Signed executable" : "Unsigned executable");
}

export function getConnectionExplanation(connection: ConnectionEvent) {
  if (isRecentlyClosed(connection)) {
    return "This entry is in TIME_WAIT state, which usually means the TCP connection has already been closed and is being temporarily retained by the operating system. PID 0 or a missing path can be expected because there may no longer be an active owning process.";
  }

  if (hasReason(connection, "dynamic_rpc_endpoint")) {
    return "This is a Windows system process using a dynamic RPC port. High-numbered ports in LISTENING state are commonly used for internal service communication and do not indicate malicious activity.";
  }

  if (
    connection.pid === 4 &&
    hasReason(connection, "legitimate_windows_listener") &&
    connection.direction === "listening"
  ) {
    return `This socket is a standard Windows listening endpoint. PID 4 represents the kernel/system networking stack. Port ${connection.localPort} is commonly used by ${describeWindowsPort(connection.localPort)}. Missing executable path is expected for this type of system-owned listener.`;
  }

  if (hasReason(connection, "trusted_svchost_services")) {
    return `This svchost instance is hosting expected Windows services: ${connection.process.hostedServices.join(", ")}. A passive listener on this process is typically part of normal Windows service communication.`;
  }

  if (hasReason(connection, "windows_service_host_listener")) {
    return `This listener matches an expected Windows service host pattern. Port ${connection.localPort} is commonly used by ${describeWindowsPort(connection.localPort)}. A listening socket without a remote peer is normal for this type of service endpoint.`;
  }

  if (hasReason(connection, "listening_socket_no_peer")) {
    return "This is a passive listening socket with no remote peer attached. Review it as a service endpoint rather than as an outbound connection.";
  }

  if (isClosing(connection) && connection.riskLevel !== "suspicious") {
    return "This socket is in CLOSE_WAIT, which usually indicates a stale or technical shutdown state. It is not suspicious on its own.";
  }

  return null;
}

export function getConnectionDestinationSummary(connection: ConnectionEvent) {
  if (!connection.destination) {
    return connection.remoteAddress ? "No DNS/ASN enrichment available yet." : "Listener / n/a";
  }

  const parts = [
    connection.destination.hostname,
    connection.destination.organization,
    connection.destination.asn
  ].filter(Boolean);

  if (parts.length === 0) {
    return `Scope: ${connection.destination.scope}`;
  }

  return parts.join(" | ");
}

export function formatUserContext(user: string | null) {
  if (!user) {
    return "User context unavailable";
  }

  const normalized = user.toLowerCase();
  if (normalized.includes("s-1-5-18") || normalized === "system" || normalized.endsWith("\\system")) {
    return "SYSTEM";
  }

  if (normalized.includes("s-1-5-19") || normalized.includes("local service")) {
    return "LOCAL SERVICE";
  }

  if (normalized.includes("s-1-5-20") || normalized.includes("network service")) {
    return "NETWORK SERVICE";
  }

  return user;
}

function describeWindowsPort(port: number) {
  if (port === 53) {
    return "DNS";
  }

  if (port === 135) {
    return "RPC endpoint mapping";
  }

  if (port === 139) {
    return "NetBIOS session service";
  }

  if (port === 445) {
    return "SMB";
  }

  return "a core Windows service";
}
