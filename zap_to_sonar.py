import json, sys, os

def convert_zap_to_sonar(input_path, output_path, project_dir):
    if not os.path.exists(input_path):
        print(f"⚠️ {input_path} not found. Skipping.")
        return
    
    with open(input_path, 'r') as f:
        zap_data = json.load(f)
    
    sonar_issues = {"issues": []}
    
    # 1. Map for the old 'severity' field (Required by your current scanner)
    old_severity_map = {"3": "CRITICAL", "2": "MAJOR", "1": "MINOR", "0": "INFO"}
    
    # 2. Map for the new 'impacts' field (Required for the new format)
    new_impact_map = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}

    for site in zap_data.get('site', []):
        for alert in site.get('alerts', []):
            risk_code = str(alert.get('riskcode', '1'))
            
            sonar_issues["issues"].append({
                "engineId": "OWASP-ZAP",
                "ruleId": alert.get('pluginid', 'zap-vulnerability'),
                # HYBRID FIX: Provide BOTH fields
                "severity": old_severity_map.get(risk_code, "MAJOR"), 
                "impacts": [
                    {
                        "softwareQuality": "SECURITY",
                        "severity": new_impact_map.get(risk_code, "MEDIUM")
                    }
                ],
                "primaryLocation": {
                    "message": f"{alert.get('alert')}: {alert.get('desc')[:500]}",
                    "filePath": f"{project_dir}/pom.xml" 
                }
            })

    with open(output_path, 'w') as f:
        json.dump(sonar_issues, f, indent=2)
    print(f"✅ Created Hybrid Report: {output_path}")

if __name__ == "__main__":
    convert_zap_to_sonar(sys.argv[1], sys.argv[2], sys.argv[3])