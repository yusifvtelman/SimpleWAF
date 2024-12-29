import re
import html
import urllib.parse

xss_regex = re.compile(
    r"(?i)<(script|iframe|img|svg|object|embed|style|link|base|meta)[^>]*>|on[a-z]+\s*=|javascript:|data:text/html|&#x[0-9a-f]+;"
)

def decode_input(input_data):
    payload = input_data.strip()
    payload = urllib.parse.unquote(payload)
    payload = html.escape(payload)
    return payload

def waf_check(payload):
    if xss_regex.search(payload):
        return True, "XSS"
    return False, "Clean"

test_payloads = [
    '<script>alert("XSS")</script>',         
    '<img src="x" onerror="alert(1)">',      
    'javascript:alert("XSS")',              
    '<svg><script>alert("XSS")</script></svg>',
    '<a href="data:text/html;base64,...">',  
    'Hello, world!',                         
    'onload=alert(1)',                      
    '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',
]

for idx, payload in enumerate(test_payloads, start=1):
    decoded_payload = decode_input(payload)
    is_xss, attack_type = waf_check(decoded_payload)
    print(f"Test {idx}: {'XSS Detected' if is_xss else 'Clean'} - {attack_type} - {decoded_payload}")
