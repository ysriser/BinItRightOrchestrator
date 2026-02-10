import json, sys, os

def convert(input_path, output_path, project_dir):
    if not os.path.exists(input_path):
        print(f"⚠️ {input_path} not found. Skipping.")
        return
    
    with open(input_path, 'r') as f:
        zap_data = json.load(f)
    
    sonar_issues = {"issues": []}
    severity_map = {"3": "CRITICAL", "2": "MAJOR", "1": "MINOR", "0": "INFO"}

    for site in zap_data.get('site', []):
        for alert in site.get('alerts', []):
            sonar_issues["issues"].append({
                "engineId": "OWASP-ZAP",
                "ruleId": alert.get('pluginid', 'zap-vuln'),
                "severity": severity_map.get(alert.get('riskcode'), "MAJOR"),
                "type": "VULNERABILITY",
                "primaryLocation": {
                    "message": f"{alert.get('alert')}: {alert.get('desc')[:500]}",
                    "filePath": f"{project_dir}/pom.xml" # Map to pom.xml as placeholder
                }
            })

    with open(output_path, 'w') as f:
        json.dump(sonar_issues, f, indent=2)
    print(f"✅ Converted {input_path} -> {output_path}")

if __name__ == "__main__":
    convert(sys.argv[1], sys.argv[2], sys.argv[3])