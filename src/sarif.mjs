import { lintConfig } from './engine.mjs';

/** Accept a configuration, never a caller-provided result or output path. */
export function exportSarif(config) {
  const report = lintConfig(config);
  const ids = [...new Set(report.findings.map((finding) => finding.ruleId))];
  const levels = { error: 'error', warning: 'warning', info: 'note' };
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: {
        name: 'mcp-configlint',
        version: '0.1.0',
        rules: ids.map((id) => ({ id, shortDescription: { text: id } })),
      } },
      results: report.findings.map((finding) => ({
        ruleId: finding.ruleId,
        ruleIndex: ids.indexOf(finding.ruleId),
        level: levels[finding.severity] ?? 'warning',
        message: { text: finding.message },
        locations: [{ logicalLocations: [{
          name: finding.location.server,
          kind: 'module',
        }] }],
        properties: {
          field: finding.location.field,
          remediation: finding.remediation,
          ai_generated: false,
        },
      })),
      properties: {
        ai_generated: false,
        disclaimer: report.disclaimer,
        rulesetVersion: report.rulesetVersion,
      },
    }],
  };
}

export const export_sarif = exportSarif;
