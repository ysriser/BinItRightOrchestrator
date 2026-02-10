import json, sys, os

def convert_zap_to_sonar(input_path, output_path, project_dir):
    if not os.path.exists(input_path):
        print(f"⚠️ {input_path} not found. Skipping.")
        return
    
    with open(input_path, 'r') as f:
        zap_data = json.load(f)
    
    # This structure follows the NEW Sonar Generic Issue format
    sonar_issues = {"issues": []}
    
    # Mapping to the NEW impact-based severities
    # Possible values per your image: BLOCKER, HIGH, MEDIUM, LOW, INFO
    impact_map = {
        "3": "HIGH",
        "2": "MEDIUM",
        "1": "LOW",
        "0": "INFO"
    }

    for site in zap_data.get('site', []):
        for alert in site.get('alerts', []):
            risk_code = str(alert.get('riskcode', '1'))
            severity_value = impact_map.get(risk_code, "MEDIUM")

            sonar_issues["issues"].append({
                "engineId": "OWASP-ZAP",
                "ruleId": alert.get('pluginid', 'zap-vulnerability'),
                "cleanCodeAttribute": "IDENTIFICATION", # Required for the new format
                "impacts": [
                    {
                        "softwareQuality": "SECURITY",
                        "severity": severity_value
                    }
                ],
                "primaryLocation": {
                    "message": f"{alert.get('alert')}: {alert.get('desc')[:500]}",
                    "filePath": f"{project_dir}/pom.xml" 
                }
            })

    with open(output_path, 'w') as f:
        json.dump(sonar_issues, f, indent=2)
    print(f"✅ Created {output_path} using the NEW impacts format.")

if __name__ == "__main__":
    convert_zap_to_sonar(sys.argv[1], sys.argv[2], sys.argv[3])