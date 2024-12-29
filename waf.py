import re
import html
import urllib.parse

xss_regex = re.compile(
    r"(?i)<(script|iframe|img|svg|object|embed|style|link|base|meta|form|input|textarea|button|a)[^>]*>"
    r"|on[a-z]+\s*="
    r"|javascript:"
    r"|data:text/html"
    r"|&#[xX]?[0-9a-fA-F]+;"  
    r"|[\\x00-\\x1F\\x7F]"    
    r"|<!--.*-->"               
    r"|<.*?[^a-zA-Z0-9]>.*?"  
)

def decoder(input):
    payload = urllib.parse.unquote(input)
    payload = html.unescape(payload)
    return payload

def waf_check(payload):
    if xss_regex.search(payload):
        return True, "XSS"
    return False, "Clean"

def read_payloads():
    with open("payloads.txt", "r") as f:
        payloads = f.readlines()
    return payloads 

def test():
    payloads = read_payloads()
    n = 0
    for payload in payloads:
        payload = decoder(payload)
        result, message = waf_check(payload)

        if result==False:
            n=n+1
            print(f"Payload no {n}: {payload} => {message} Detected: {result}")

if __name__ == "__main__":
    test()