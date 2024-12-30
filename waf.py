import re
import html
import urllib.parse

xss_regex = re.compile(
    r'''(?i)
    (<script|<script |javascript:|on\w+=|eval\(|alert\(|prompt\(|confirm\(|document\.|location\.|window\.|this\.)|
    (<[^>]+style=[\'"]?.*expression.*[\'"]?[^>]*>)|
    (<[^>]+on\w+=[\'"]?.*[\'"]?[^>]*>)|
    (<[^>]+src=(?:\'|\"|\s*)?javascript:.*(?:\"|\'|\s*))|
    (<object[^>]+data=(?:\'|\"|\s*)?javascript:.*(?:\"|\'|\s*))|
    (<embed[^>]+src=(?:\'|\"|\s*)?javascript:.*(?:\"|\'|\s*))|
    (%3Cscript|javascript:|on\w+%3D|eval%28|alert%28|prompt%28|confirm%28|document\.|location\.|window\.|this\.)
    ''', 
    re.VERBOSE | re.IGNORECASE
)

def decoder(input):
    payload = input
    for i in range(5):
        payload = urllib.parse.unquote(payload)
        payload = html.unescape(payload)
        if not ('%' in payload or '&' in payload):  
            break
    return payload

def waf_check(payload):
    if xss_regex.search(payload):
        return True, "XSS"
    return False, "Clean"

def read_payloads():
    with open("payloads.txt", "r") as f:
        payloads = [line.strip() for line in f.readlines()]
    return payloads 

def test():
    payloads = read_payloads()
    n = 0
    for payload in payloads:
        payload = decoder(payload)
        result, message = waf_check(payload)

        if result == False:
            n += 1
            print(f"Payload no {n}: {payload} => {message} Detected: {result}")
        
if __name__ == "__main__":
    test()
