import re
import html
import urllib.parse

import re

xss_regex = re.compile(
    r'''(?i)
    (<script.*?>.*?</script>)              # Match <script> tags
    |(<iframe.*?>.*?</iframe>)             # Match <iframe> tags
    |(<object.*?>.*?</object>)             # Match <object> tags
    |(<embed.*?>)                          # Match <embed> tags
    |(<applet.*?>.*?</applet>)             # Match <applet> tags
    |(<form.*?>.*?</form>)                 # Match <form> tags
    |(<input.*?>)                          # Match <input> tags
    |(<textarea.*?>.*?</textarea>)         # Match <textarea> tags
    |(<button.*?>.*?</button>)             # Match <button> tags
    |(<a.*?href=["']?javascript:.*?["'].*?>)  # Match <a> tags with javascript: in href
    |(on\w+\s*=\s*["']?[^"'>]*javascript:.*?["']) # Match inline event handlers with javascript
    |(eval\([^\)]*\))                      # Match eval() usage
    |(alert\([^\)]*\))                     # Match alert() usage
    |(prompt\([^\)]*\))                    # Match prompt() usage
    |(confirm\([^\)]*\))                   # Match confirm() usage
    |(document\.)                          # Match document object
    |(location\.)                          # Match location object
    |(window\.)                            # Match window object
    |(this\.)                              # Match this object
    |(<[^>]+style=["']?.*expression.*["']?[^>]*>)  # Match inline styles with expression()
    |(<[^>]+on\w+\s*=\s*["']?.*["']?[^>]*>)  # Match inline event handlers like onclick, etc.
    |(<[^>]+src=["']?\s*javascript:.*?["'])   # Match <img>, <script> etc. with javascript: in src
    |(<[^>]+src=["']?\s*data:text/html;base64,.*)  # Match data URIs with base64 encoding
    |(<[^>]+href=["']?.*?;.*?>)               # Match malformed href attributes with a semicolon
    |(<[^>]+href=["']?\s*[^>]*?://.*)          # Match suspicious URLs starting with //
    |(<[^>]+style=["']?[^>]*?behavior:.*?url\()  # Match behavior URL used in style attribute
    |(<[^>]+style=["']?[^>]*?binding:.*?url\()  # Match binding URL used in style attribute
    |(<[^>]+datafld=["']?[^>]*?xss.*?["'])    # Match suspicious data attributes related to XSS
    |(<[^>]+dataformatas=["']?[^>]*?xss.*?["'])  # Match suspicious data attributes related to XSS
    |(<[^>]+datasrc=["']?[^>]*?xss.*?["'])      # Match suspicious data attributes related to XSS
    |(<!--.*?-->)                            # Match HTML comments
    |(<.*?<?xml.*?>)                         # Match XML-related attacks
    |(<[^>]+style=["']?[^>]*?(url|import|attr)\s*\()  # Match CSS injection vectors
    |(<[^>]+style=["']?[^>]*?:\s*expression\s*\()     # Match CSS expression attacks
    |(javascript\s*:)                                  # Match javascript: protocol
    |(\bdata:(?!image\/)\w+\/\w+;)                    # Match dangerous data: URIs (except images)
    |(&{.*?})                                         # Match IE conditional comments
    |(\[\s*constructor\s*\])                          # Match prototype pollution attempts
    |(__proto__|constructor\s*\.|prototype\s*\.)      # Match prototype chain attacks
    |(<[^>]*\s+dynsrc\s*=)                           # Match dangerous dynsrc attribute
    |(<[^>]*\s+lowsrc\s*=)                           # Match dangerous lowsrc attribute
    |(\bimport\s*\(|new\s+Function\b)                # Match dynamic code execution
    |(\b(?:set|clear)(?:Timeout|Interval)|requestAnimationFrame)  # Match timing-based attacks
    |(\bfetch\s*\(|\bxmlhttp)                        # Match suspicious AJAX calls
    |(\bwebsocket\b|\bws:\/\/|\bwss:\/\/)           # Match WebSocket usage
    |(\bpostMessage\b|\bmessageChannel\b)            # Match cross-window communication
    |(\bStorage\b|\bindexedDB\b|\bwebSQL\b)         # Match client-side storage access
    |(<\s*script\b[^>]*?\bsrc\s*=\s*['"]?[^'">\s]*['"]?[^>]*>)  # Better script src detection
    |(<\s*script\b[^>]*>.*?</\s*script\s*>)                      # Better script tag detection
    |(<\s*script\b[^>]*>)                                        # Catch unclosed script tags
    |(<\s*iframe\b[^>]*?\bsrc\s*=\s*['"]?[^'">\s]*['"]?[^>]*>)  # Better iframe detection
    |(<[^>]*\s+src\s*=\s*['"]?\s*(?:https?:)?//[^'">\s]*['"]?)  # Catch src with protocol
    |(@\s*import\s*['"]?\s*(?:https?:)?//[^'">\s]*['"]?)        # Better @import detection
    |(<[^>]*\s+data(?:fld|formatas|src)\s*=\s*['"][^'"]*['"])   # Better data attribute detection
    |((?:\\x[0-9a-f]{2}|\\[0-9]{3}|&#x?[0-9a-f]+);?)          # Catch encoded characters
    |(<[^>]*\s*=\s*[`'"].*?[`'"].*?>)                          # Catch malformed attributes
    |(<[^>]*\s+style\s*=\s*['"][^'"]*@import[^'"]*['"])        # Catch style with @import
    |(<\s*img\b[^>]*\bsrc\s*=\s*['"]?\s*(?:javascript|jav\s*a\s*script):)  # Catch malformed img src
    |(<[^>]*\s*=\s*[^>]*[<>][^>]*>)                           # Catch embedded brackets
    |(&#[xX]?[0-9a-fA-F]+;?)                                  # Catch HTML entities
    |(\b(?:javascript|jscript|livescript|vbscript):)          # Catch script protocols
    ''',
    re.VERBOSE | re.IGNORECASE | re.DOTALL
)

def waf_check(payload):
    # Remove common evasion characters
    payload = payload.replace(';', '')  # Remove semicolons used for evasion
    payload = payload.replace('<WBR>', '')  # Remove word break tags
    payload = re.sub(r'\s+', ' ', payload)  # Normalize whitespace
    payload = payload.replace('\0', '')  # Remove null bytes
    
    # Decode HTML entities before checking
    payload = html.unescape(payload)
    
    if xss_regex.search(payload):
        return True, "XSS"
    return False, "Clean"


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
