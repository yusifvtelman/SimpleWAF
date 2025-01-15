import re
import html
import urllib.parse

import re

xss_regex = re.compile(
    r'''(?ix)
    # Script tags and variations
    <[^>]*?script[\s\S]*?>[\s\S]*?</script>|
    <[^>]*?script[\s\S]*?>|
    
    # Dangerous inline events
    \bon(?:abort|blur|change|click|dblclick|drag|drop|error|focus|keydown|keypress|keyup|load|mousedown|mousemove|mouseout|mouseover|mouseup|move|reset|resize|select|submit|unload)\s*=[\s\S]*?[("']|
    
    # JavaScript functions and protocols
    (?:
        javascript:|
        vbscript:|
        livescript:|
        data:text/(?:html|javascript)
    )|
    
    # Dangerous functions
    \b(?:
        eval|
        alert|
        prompt|
        confirm|
        settimeout|
        setinterval|
        function|
        execscript|
        execute|
        mshtml|
        expression
    )\s*\(|
    
    # DOM manipulation
    (?:
        document\.|
        window\.|
        location\.|
        history\.|
        navigator\.|
        cookie|
        innerhtml|
        outerhtml|
        createelement|
        execcommand|
        setattribute|
        javascript:void
    )|
    
    # Dangerous attributes
    (?:src|href|data|action)\s*=\s*(?:["'\s])*(?:
        javascript:|
        data:|
        vbscript:|
        about:|
        file:|
        &\{|
        mocha:
    )|
    
    # Style attacks
    style\s*=\s*["']\s*(?:
        expression|
        behavior|
        javascript:|
        vbscript:|
        url\s*\(|
        @import
    )|
    
    # Dangerous tags
    <(?:
        iframe|
        object|
        embed|
        applet|
        meta|
        xml|
        blink|
        link|
        style|
        form|
        base|
        frameset
    )\s+[^>]*>|
    
    # Encoded attacks
    (?:
        &#[xX]?(?:0{0,8}(?:1?[1-9a-f]|[10-9a-f]|[0-9]{2}|1ff));?|
        %(?:22|27|3c|3e|3f|60)|
        \\[0-9a-f]{1,6}|
        \\\w{2,6}
    )|
    
    # Other dangerous patterns
    \[\s*constructor\s*\]|
    -moz-binding[\s\S]*?:|
    @import\s*["']|
    <!entity\s+[\s\S]*?>|
    <!\[cdata\[
    ''',
    re.VERBOSE | re.IGNORECASE
)

def waf_check(payload):
    # Normalize and decode input
    try:
        # URL decode
        decoded = urllib.parse.unquote(payload)
        while decoded != payload:
            payload = decoded
            decoded = urllib.parse.unquote(payload)
            
        # HTML entity decode
        payload = html.unescape(payload)
        
        # Basic normalization
        payload = payload.replace('\0', '')
        payload = payload.replace('<WBR>', '')
        payload = re.sub(r'\s+', ' ', payload)
        
        # Remove common evasion techniques
        payload = re.sub(r'&#(?:x[0-9a-f]+|[0-9]+);?', 
                        lambda m: html.unescape(m.group()), 
                        payload, 
                        flags=re.IGNORECASE)
        
        # Check for XSS
        if xss_regex.search(payload):
            return True, "XSS"
        return False, "Clean"
        
    except Exception as e:
        # If any error occurs during processing, treat as suspicious
        return True, "XSS"

def decoder(input):
    payload = input
    for _ in range(5):
        payload = urllib.parse.unquote(payload)
        payload = html.unescape(payload)
        if not ('%' in payload or '&' in payload):
            break
    return payload

def read_payloads():
    with open("payloads.txt", "r") as f:
        return [line.strip() for line in f.readlines()]

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
