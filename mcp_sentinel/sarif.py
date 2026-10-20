"""
SARIF v2.1.0 report generation for GitHub Code Scanning and CI/CD security tabs.
"""

from typing import List, Dict, Any
import json
from .scanner import Finding


def generate_sarif_report(findings: List[Finding], tool_version: str = "0.2.0") -> Dict[str, Any]:
    """Converts Sentinel findings into a standard OASIS SARIF v2.1.0 document."""
    rules_map: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        if f.rule_id not in rules_map:
            sarif_level = "error" if f.severity in ["CRITICAL", "HIGH"] else "warning"
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id.replace("_", " ").title().replace(" ", ""),
                "shortDescription": {"text": f.description},
                "defaultConfiguration": {
                    "level": sarif_level
                }
            }

        level = "error" if f.severity in ["CRITICAL", "HIGH"] else "warning"
        uri = f.file_path.replace("\\", "/") if f.file_path else "unknown"

        results.append({
            "ruleId": f.rule_id,
            "level": level,
            "message": {
                "text": f"{f.description} (Pattern match: {f.matched_snippet})"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": uri
                        },
                        "region": {
                            "startLine": f.line_number,
                            "startColumn": 1
                        }
                    }
                }
            ]
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-sentinel",
                        "informationUri": "https://github.com/businesscanva12-tech/mcp-sentinel",
                        "semanticVersion": tool_version,
                        "rules": list(rules_map.values())
                    }
                },
                "results": results
            }
        ]
    }

    return sarif_doc
