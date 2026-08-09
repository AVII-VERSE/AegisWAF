import re

# Comprehensive Known Malicious Threat Signatures
MALICIOUS_PATTERNS = [
    # SQL Injection Signatures
    r"(?:\bunion\b|\bselect\b|\binsert\b|\bdelete\b|\bdrop\b|\bupdate\b).*?\bfrom\b",
    r"(?i)union\s+select", r"(?i)drop\s+table", r"(?i)or\s+1=1", r"--", 
    r"' or '1'='1", r"1' or '1'='1", r"1' or 1=1--", r"(?i)admin'--", r"#",
    r"/\*.*\*/", r"' and '1'='1", r"' and sleep\(", r"(?i)or\s+sleep\(",
    r"'; drop table users;--", r"'; exec xp_cmdshell\(", r"(?i)or\s+1=1--", 
    r"(?i)waitfor\s+delay", r"(?i)select\s+\*", r"';shutdown --", 
    r"' union all select", r"' and benchmark\(", r"' having 1=1--", 
    r"' and ascii\(", r"' group by columnnames having 1=1--", 
    r"' and extractvalue\(", r"(?i)or\s+'a'='a", r"(?i)1 or 1=1", 
    r"(?i)order by \d+", r"convert\(int,", r"(?i)select username", 
    r"(?i)select password", r"'; waitfor delay '0:0:10'--", 
    r"' OR '1'='1'--", r"(?i)select\s+@@version", r"(?i)select\s+@@datadir", 
    r"(?i)select\s+load_file", r"(?i)select\s+user\(\)", 
    r"(?i)select\s+database\(\)", r"\" OR \"1\"=\"1", r"\' OR \'1\'=\'1",
    
    # XSS Signatures
    r"(\bscript\b|<script>)", r"(\balert\b|\bconsole\.log\b)",
    r"(?i)<script>", r"(?i)<img src=", r"(?i)onerror=", r"(?i)alert\(", 
    r"(?i)document\.cookie", r"javascript:", r"(?i)<iframe>", r"(?i)<svg>", 
    r"(?i)onmouseover=", r"(?i)onload=", r"(?i)eval\(", r"settimeout\(", 
    r"setinterval\(", r"(?i)innerhtml=", r"(?i)srcdoc=", 
    r"(?i)<link rel=stylesheet href=", r"fetch\(", r"xhr\.open\(", 
    r"window\.location=", r"self\.location=", r"(?i)prompt\(", 
    r"constructor\.constructor\(", r"String\.fromCharCode\(", r"&#x", 
    r"&lt;script&gt;", r"(?i)<body onload=", r"onfocus=", r"onblur=", 
    r"onclick=", r"onkeydown=", r"onkeyup=", r"src=javascript:", 
    r"data:text/html;base64", r"(?i)<embed>", r"(?i)confirm\(",
    
    # Remote Code Execution (RCE) / Command Injection Signatures
    r";\s*(?:cat|ls|whoami|pwd|id|uname|curl|wget|bash|sh|nc|netcat|ncat)\b",
    r"\|\s*(?:cat|ls|whoami|pwd|id|uname|curl|wget|bash|sh|nc)\b",
    r"`\s*(?:cat|ls|whoami|pwd|id|uname|curl|wget)\b",
    r"\$\((?:cat|ls|whoami|pwd|id|uname|curl|wget)\)",
    r"(?i)\bexec\(|\bsystem\(|\bpassthru\(|\bshell_exec\(|\bpopen\(",
    r"\b/bin/sh\b|\b/bin/bash\b|\bcmd\.exe\b|\bpowershell\.exe\b",

    # Path Traversal Signatures
    r"\.\./\.\./", r"\.\.\\\.\.\\", r"/etc/passwd", r"/etc/shadow", r"c:\\windows\\system32",
    
    # Log4j / JNDI Injection
    r"\$\{\s*jndi\s*:",

    # SSRF Signatures
    r"file://", r"gopher://", r"ftp://", r"http://127\.0\.0\.1", 
    r"http://localhost", r"169\.254\.", r"metadata\.google\.internal",
    r"169\.254\.169\.254", r"0x7f000001", r"file:/etc/passwd"
]

# Obfuscation Patterns (Suspicious structures needing ML Anomaly Inspection)
OBFUSCATION_PATTERNS = [
    r"(%[0-9A-Fa-f]{2})+",  # URL encoding
    r"(\\x[0-9A-Fa-f]{2})+",  # Hex encoding
    r"(\bchar\b|\bconcat\b|\bsubstr\b)",  # SQL obfuscation functions
    r"(\bbase64_decode\b|\bbase64_encode\b)",  # Base64 encoding
    r"(\\u[0-9A-Fa-f]{4})+",  # Unicode escape sequences
    r"(\bfromCharCode\b)",  # JavaScript obfuscation
    r"(\bROT13\b)",  # ROT13 encoding
    r"(\bdecodeURIComponent\b|\bencodeURIComponent\b)",  # URI encoding
    r"(\bhexToInt\b|\bcharCodeAt\b)",  # Character conversion tricks
    r"(\\bXOR\\b|\bXOR\b)",  # XOR encoding
    r"(\bmd5\b|\bsha1\b|\bsha256\b)",  # Hash-based obfuscation
    r"(\bblind_sql\b|\btime_delay\b)",  # Blind SQL injection techniques
    r"(\bcase when\b|\bcase\b|\bthen\b)",  # SQL CASE obfuscation
    r"(?:--)|(/\*.*?\*/)|(#.*?\n)",  # Comment-based SQL obfuscation
]

def classify_attack_category(text: str) -> str:
    """Helper to determine attack label from signature match."""
    t = text.lower()
    if any(k in t for k in ['select', 'union', 'drop', 'insert', 'delete', 'update', "' or '", "or 1=1", "--"]):
        return "SQL Injection"
    if any(k in t for k in ['<script', 'javascript:', 'onerror=', 'alert(', 'document.cookie', '<svg']):
        return "Cross-Site Scripting (XSS)"
    if any(k in t for k in ['/etc/passwd', '../', '..\\', 'system32']):
        return "Path Traversal"
    if any(k in t for k in ['http://127.', '169.254', 'file://', 'gopher://']):
        return "SSRF Attack"
    if any(k in t for k in ['exec(', 'system(', '/bin/sh', 'cmd.exe', 'whoami', 'cat /etc']):
        return "Command Injection"
    return "Malicious Request"

def check_signature(user_input: str):
    """
    Scans user input against signatures.
    Returns:
      - ("malicious", attack_category)
      - ("obfuscated", "Obfuscated Attack")
      - ("valid", "Clean Request")
    """
    normalized_input = " ".join(user_input.split())
    
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, normalized_input, re.IGNORECASE):
            category = classify_attack_category(normalized_input)
            return "malicious", category
            
    for pattern in OBFUSCATION_PATTERNS:
        if re.search(pattern, normalized_input, re.IGNORECASE):
            return "obfuscated", "Obfuscated Attack"

    return "valid", "Clean Request"

def get_signature_rules_count():
    return {
        "malicious_patterns": len(MALICIOUS_PATTERNS),
        "obfuscation_patterns": len(OBFUSCATION_PATTERNS),
        "categories_covered": ["SQL Injection", "XSS", "RCE / Command Injection", "Path Traversal", "SSRF", "Log4j JNDI"]
    }
