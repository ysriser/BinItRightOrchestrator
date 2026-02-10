import json, sys, os

def convert_zap_to_sonar(input_path, output_path, project_dir):
    if not os.path.exists(input_path):
        print(f"⚠️ Warning: {input_path} not found. Skipping.")
        return
    
    with open(input_path, 'r') as f:
        zap_data = json.load(f)
    
    sonar_issues = {"issues": []}
    # Map ZAP risk levels (0-3) to Sonar severities
    severity_map = {"3": "BLOCKER", "2": "HIGH", "1": "MEDIUM", "0": "INFO"}

    for site in zap_data.get('site', []):
        for alert in site.get('alerts', []):
            sonar_issues["issues"].append({
                "engineId": "OWASP-ZAP",
                "ruleId": alert.get('pluginid', 'zap-vulnerability'),
                "severity": severity_map.get(alert.get('riskcode'), "HIGH"),
                "type": "VULNERABILITY",
                "primaryLocation": {
                    "message": f"{alert.get('alert')}: {alert.get('desc')[:500]}",
                    "filePath": f"{project_dir}/pom.xml" 
                }
            })

    with open(output_path, 'w') as f:
        json.dump(sonar_issues, f, indent=2)
    print(f"✅ Converted {input_path} -> {output_path}")

if __name__ == "__main__":
    convert_zap_to_sonar(sys.argv[1], sys.argv[2], sys.argv[3])