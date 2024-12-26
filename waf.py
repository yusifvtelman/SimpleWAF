import re

XSS_PATTERN = "<script>"

def wafCheck(input):
    print("WAF Check: ", input)