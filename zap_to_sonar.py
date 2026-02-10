import json, os, sys

def convert(input_file, output_file, project_base):
    if not os.path.exists(input_file):
        print(f"⚠️ Skip: {input_file} not found.")
        return

    with open(input_file, 'r') as f:
        data = json.load(f)

    sonar_issues = {"issues": []}
    # Map ZAP risks to Sonar severities
    severity_map = {"3": "CRITICAL", "2": "MAJOR", "1": "MINOR", "0": "INFO"}

    for site in data.get('site', []):
        for alert in site.get('alerts', []):
            issue = {
                "engineId": "OWASP-ZAP",
                "ruleId": alert.get('pluginid', 'zap-issue'),
                "severity": severity_map.get(alert.get('riskcode'), "MAJOR"),
                "type": "VULNERABILITY",
                "primaryLocation": {
                    "message": f"{alert.get('alert')}: {alert.get('desc')[:500]}",
                    # Attach to pom.xml as a placeholder since ZAP tests URLs, not files
                    "filePath": f"{project_base}/pom.xml" 
                }
            }
            sonar_issues["issues"].append(issue)

    with open(output_file, 'w') as f:
        json.dump(sonar_issues, f, indent=2)
    print(f"✅ Converted {input_file} -> {output_file}")

if __name__ == "__main__":
    # Usage: python zap_to_sonar.py <input> <output> <submodule_folder>
    convert(sys.argv[1], sys.argv[2], sys.argv[3])