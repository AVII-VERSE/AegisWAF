from flask import Blueprint, request, jsonify, Response
import io
import csv
import json
import logging
from src.aegis_waf.utils.signature_checker import check_signature, get_signature_rules_count
from src.aegis_waf.utils.preprocessor import extract_features, calculate_risk_score
from src.aegis_waf.utils.ml_checker import check_ml_prediction
from src.aegis_waf.database import log_threat, get_analytics_summary, get_logs, get_all_logs_for_export

api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

# Fallback logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('aegis_waf')

@api_bp.route('/inspect', methods=['POST'])
def inspect_request():
    data = request.get_json() or {}
    
    user_input = data.get("user_request", "").strip()
    if not user_input:
        user_input = data.get("uri", "") or data.get("post_data", "") or "/"
        
    method = data.get("method", "GET").upper()
    uri = data.get("uri", user_input)
    get_data = data.get("get_data", "")
    post_data = data.get("post_data", "")
    client_ip = request.remote_addr or "127.0.0.1"

    # --- Layer 1: Signature-Based Threat Scan ---
    sig_verdict, attack_category = check_signature(user_input)
    features = extract_features(uri, get_data, post_data)

    ml_verdict = "none"
    final_status = "SAFE"
    remediation = "No malicious payload detected. Request passed all security checks."

    if sig_verdict == "malicious":
        final_status = "BLOCKED"
        risk_score = calculate_risk_score(features, sig_verdict, 0)
        remediation = f"Known attack signature detected [{attack_category}]. Immediately dropped by Layer-1 WAF."
        
    elif sig_verdict == "obfuscated":
        # --- Layer 2: ML Anomaly Detection Engine ---
        ml_pred = check_ml_prediction(features)
        ml_verdict = "malicious" if ml_pred == 1 else "valid"
        
        if ml_pred == 1:
            final_status = "ANOMALY"
            attack_category = "Obfuscated Attack Vector"
            risk_score = calculate_risk_score(features, sig_verdict, 1)
            remediation = "Obfuscated request pattern detected. Flagged & neutralized by Layer-2 AI Anomaly Detector."
        else:
            final_status = "SAFE"
            attack_category = "Clean Request"
            risk_score = calculate_risk_score(features, sig_verdict, 0)
            remediation = "Suspicious encoding passed deep statistical feature inspection by Layer-2 AI Engine."
    else:
        final_status = "SAFE"
        attack_category = "Clean Request"
        risk_score = calculate_risk_score(features, sig_verdict, 0)

    # Persist log to SQLite database
    log_id = log_threat(
        client_ip=client_ip,
        method=method,
        uri=uri,
        user_input=user_input,
        signature_verdict=sig_verdict,
        ml_verdict=ml_verdict,
        final_status=final_status,
        attack_type=attack_category,
        risk_score=risk_score,
        features=features
    )

    feature_map = {
        "URI_Length": features[0],
        "GET_Length": features[1],
        "POST_Length": features[2],
        "URI_Entropy": features[3],
        "GET_Entropy": features[4],
        "POST_Entropy": features[5],
        "Numeric_Text_Ratio": features[6],
        "Special_Char_Count": features[7]
    }

    return jsonify({
        "log_id": log_id,
        "status": final_status,
        "attack_type": attack_category,
        "risk_score": risk_score,
        "remediation": remediation,
        "layer_analysis": {
            "signature_layer": sig_verdict,
            "ai_anomaly_layer": ml_verdict
        },
        "extracted_features": feature_map,
        "timestamp": request.date or None
    })

@api_bp.route('/analytics', methods=['GET'])
def get_analytics():
    summary = get_analytics_summary()
    return jsonify(summary)

@api_bp.route('/logs', methods=['GET'])
def get_threat_logs():
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 20))
    status_filter = request.args.get('status', 'ALL')
    search_query = request.args.get('search', '')
    
    result = get_logs(page=page, limit=limit, status_filter=status_filter, search=search_query)
    return jsonify(result)

@api_bp.route('/export/csv', methods=['GET'])
def export_csv():
    logs = get_all_logs_for_export()
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['ID', 'Timestamp', 'Client IP', 'Method', 'URI', 'User Input', 'Signature Verdict', 'ML Verdict', 'Final Status', 'Attack Type', 'Risk Score'])
    
    for row in logs:
        writer.writerow([
            row['id'],
            row['timestamp'],
            row['client_ip'],
            row['method'],
            row['uri'],
            row['user_input'],
            row['signature_verdict'],
            row['ml_verdict'],
            row['final_status'],
            row['attack_type'],
            row['risk_score']
        ])
        
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=aegis_waf_threat_logs.csv"}
    )

@api_bp.route('/rules', methods=['GET'])
def get_rules():
    rule_stats = get_signature_rules_count()
    return jsonify({
        "engine_name": "AegisWAF Dual-Layer Engine",
        "signature_rules": rule_stats,
        "ai_model": {
            "name": "Random Forest / Extra Trees Anomaly Classifier",
            "feature_vector_size": 8,
            "metrics": ["Shannon Entropy", "Length Ratio", "Numeric Density", "Special Char Frequency"]
        }
    })
