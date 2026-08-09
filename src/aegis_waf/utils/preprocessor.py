import math

def compute_length(text: str) -> int:
    return len(text) if text else 0

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    frequency = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1
    entropy = 0.0
    for freq in frequency.values():
        p = freq / len(text)
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def numeric_text_ratio(text: str) -> float:
    if not text:
        return 0.0
    numeric_count = sum(c.isdigit() for c in text)
    alpha_count = sum(c.isalpha() for c in text)
    if alpha_count == 0:
        return float(numeric_count)
    return round(numeric_count / alpha_count, 4)

def special_char_count(text: str) -> int:
    special_chars = ["'", '"', "{", "}", "[", "]", "--", ";", "/", "\\", "=", "<", ">", "%", "$", "(", ")"]
    count = 0
    for sp in special_chars:
        count += text.count(sp)
    return count

def extract_features(uri: str, get_data: str, post_data: str) -> list:
    """
    Extracts 8 statistical and structural features from the request components:
      [URI_Length, GET_Length, POST_Length, URI_Entropy, GET_Entropy, POST_Entropy,
       Numeric_Text_Ratio, Special_Char_Count]
    """
    uri_len = compute_length(uri)
    get_len = compute_length(get_data)
    post_len = compute_length(post_data)
    
    uri_ent = shannon_entropy(uri)
    get_ent = shannon_entropy(get_data)
    post_ent = shannon_entropy(post_data)
    
    combined = (uri or "") + (get_data or "") + (post_data or "")
    num_ratio = numeric_text_ratio(combined)
    sp_count = special_char_count(combined)
    
    return [
        uri_len,
        get_len,
        post_len,
        uri_ent,
        get_ent,
        post_ent,
        num_ratio,
        sp_count
    ]

def calculate_risk_score(features: list, signature_verdict: str, ml_prediction: int) -> float:
    """Computes a normalized risk score from 0.0% to 100.0%."""
    if signature_verdict == "malicious":
        return round(95.0 + (features[7] % 5), 1)
        
    score = 10.0
    # Entropy contribution
    if features[3] > 4.0:
        score += (features[3] - 4.0) * 12.0
    # Special char count contribution
    score += min(features[7] * 4.0, 30.0)
    # ML model contribution
    if ml_prediction == 1:
        score += 45.0
        
    return min(round(score, 1), 99.9)
