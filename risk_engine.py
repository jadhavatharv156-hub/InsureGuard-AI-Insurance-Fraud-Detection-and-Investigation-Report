import json

def analyze_claim_risk(data):
    """
    Evaluates claim parameters and outputs risk score, prediction, 
    and human-readable explainable risk drivers.
    """
    claim_amount = float(data.get('claim_amount', 0))
    severity = data.get('incident_severity', '')
    policy_age = int(data.get('policy_age_months', 12))
    authorities = data.get('authorities_contacted', 'None')
    
    score = 0.10
    factors = []

    # 1. Exposure Value Anomaly Check
    if claim_amount > 25000:
        score += 0.35
        factors.append({
            "factor": "High Exposure Value", 
            "impact": "+35%", 
            "detail": f"Claim amount (${claim_amount:,.2f}) exceeds normal policy baseline."
        })
    elif claim_amount > 10000:
        score += 0.20
        factors.append({
            "factor": "Elevated Exposure Value", 
            "impact": "+20%", 
            "detail": f"Claim amount (${claim_amount:,.2f}) is above average."
        })

    # 2. Incident Severity Factor
    if severity in ['Major Damage', 'Total Loss']:
        score += 0.25
        factors.append({
            "factor": "High Incident Severity", 
            "impact": "+25%", 
            "detail": f"Incident classified as {severity}."
        })

    # 3. Early Claim Pattern (Inception Timing)
    if policy_age < 3:
        score += 0.30
        factors.append({
            "factor": "Rapid Claim After Policy Inception", 
            "impact": "+30%", 
            "detail": f"Policy opened only {policy_age} month(s) ago."
        })

    # 4. Authority Reporting Discrepancy
    if authorities == 'None' and severity != 'Minor Damage':
        score += 0.15
        factors.append({
            "factor": "Unreported Major Incident", 
            "impact": "+15%", 
            "detail": "No official authorities contacted for a major loss."
        })

    risk_score = min(round(score, 4), 0.99)
    prediction = 1 if risk_score >= 0.50 else 0

    return {
        'risk_score': risk_score,
        'prediction': prediction,
        'risk_factors': json.dumps(factors)
    }