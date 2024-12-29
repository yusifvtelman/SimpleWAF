import re
import html
import urllib.parse

xss_regex = re.compile(
    r"(?i)<(script|iframe|img|svg|object|embed|style|link|base|meta)[^>]*>|on[a-z]+\s*=|javascript:|data:text/html|&#x[0-9a-f]+;"
)

def decoder(input):

    payload = urllib.parse.unquote(input)
    payload = html.unescape(payload)
    print(f"Decoded Payload: {payload}")
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

for ipayload in test_payloads:
    print(f"Testing payload: {ipayload}")
    decoder(ipayload)
   