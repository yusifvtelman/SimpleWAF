<?php
function wafCheck($input) {
    // Regex to detect event handlers with dangerous functions like alert, eval, etc.
    $pattern = '/<.*?\b(on\w+)\s*=\s*["\'][^"\']*(alert|eval|prompt|confirm|open|document).*?["\'].*?>/i';
    
    // Check if the input matches the XSS pattern
    if (preg_match($pattern, $input)) {
        return true;
    }
    return false;
}

// Example Usage
echo "Enter input to check for XSS: ";
$input = trim(fgets(STDIN));  // Get input from user

if (wafCheck($input)) {
    echo "Potential XSS payload detected!\n";
} else {
    echo "No XSS payload detected.\n";
}
?>
