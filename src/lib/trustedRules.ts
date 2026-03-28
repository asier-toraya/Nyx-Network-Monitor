import type { AllowRule } from "../types";

export interface RuleDraft {
  label: string;
  processName: string;
  remotePattern: string;
  protocol: string;
  direction: string;
  port: string;
  signer: string;
  exePath: string;
  sha256: string;
  notes: string;
}

export function formatRulePort(rule: AllowRule) {
  return rule.port ? `Port ${rule.port}` : "Any port";
}

export function formatRuleSummary(rule: AllowRule) {
  return [
    rule.processName ?? "Any process",
    rule.remotePattern ?? "Any target",
    rule.protocol ?? "Any protocol",
    rule.direction ?? "Any direction"
  ].join(" | ");
}

export function matchesRuleQuery(rule: AllowRule, query: string) {
  const normalizedQuery = query.trim().toLowerCase();

  if (!normalizedQuery) {
    return true;
  }

  const haystack = [
    rule.label,
    rule.processName,
    rule.remotePattern,
    rule.protocol,
    rule.direction,
    rule.signer,
    rule.exePath,
    rule.sha256,
    rule.notes,
    rule.port?.toString(),
    rule.enabled ? "enabled" : "disabled"
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  return haystack.includes(normalizedQuery);
}

export function toRuleDraft(rule: AllowRule): RuleDraft {
  return {
    label: rule.label,
    processName: rule.processName ?? "",
    remotePattern: rule.remotePattern ?? "",
    protocol: rule.protocol ?? "",
    direction: rule.direction ?? "",
    port: rule.port?.toString() ?? "",
    signer: rule.signer ?? "",
    exePath: rule.exePath ?? "",
    sha256: rule.sha256 ?? "",
    notes: rule.notes ?? ""
  };
}
