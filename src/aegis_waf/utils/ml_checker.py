import os

try:
    import joblib
except ImportError:
    joblib = None

# Path to trained model file inside aegis_waf/models/
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "ml_model.pkl")

# Load trained scikit-learn model if joblib is available
ml_model = None
if joblib is not None and os.path.exists(MODEL_PATH):
    try:
        ml_model = joblib.load(MODEL_PATH)
    except Exception:
        ml_model = None

def check_ml_prediction(features: list) -> int:
    """
    Predicts anomaly status based on 8 extracted features.
    Returns 1 for malicious anomaly and 0 for valid request.
    """
    if ml_model is not None:
        try:
            prediction = ml_model.predict([features])[0]
            return int(prediction)
        except Exception:
            pass
            
    # Intelligent Fallback Heuristic if ML model or joblib is unavailable
    # Features: [URI_Len, GET_Len, POST_Len, URI_Entropy, GET_Entropy, POST_Entropy, Num_Ratio, Special_Chars]
    uri_entropy = features[3] if len(features) > 3 else 0
    special_chars = features[7] if len(features) > 7 else 0
    num_ratio = features[6] if len(features) > 6 else 0
    
    if uri_entropy > 4.2 or special_chars >= 4 or num_ratio > 0.8:
        return 1
    return 0
