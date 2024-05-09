import re
from typing import Union

class XSSHandler:
    def _init_(self):
        self.metacharacters = r'[\\^$.*+?{}()|[\]]'
        
    def safe_unicode(self, string: Union[str, bytes]) -> str:
        """
        Safely handle Unicode characters.
        """
        if isinstance(string, bytes):
            new_string = string.decode('unicode_escape')
            for char in new_string:
                if ord(char) > 32 and ord(char) <= 1114111:  # Unicode characters have code points > 32 and <= 1114111
                    new_string = new_string.replace(char, r'\u{:04x}'.format(ord(char)))
            return new_string
        return string

    def is_xss_attack(self, input_string: str) -> bool:
        """
        Check if a string is potentially an XSS attack.
        """
        xss_patterns = [
            r"<script>",
            r"</script>",
            r"onload=",
            r"onerror=",
            r"onclick=",
            r"onmouseover=",
            r"onmouseout=",
            r"onkeydown=",
            r"onkeyup=",
            r"onkeypress=",
            r"javascript:",
            r"vbscript:",
            r"data:text/html",
            r"&#",
            r"%3C",
            r"%3E"
        ]
        for pattern in xss_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True
        return False

# Instantiate the XSSHandler class
handler = XSSHandler()

# Take any input from the user
user_input = input("Enter your input: ")

# Check if the input is potentially an XSS attack
if handler.is_xss_attack(user_input):
    print("Warning: The input is potentially an XSS attack.")
else:
    print("The input is safe.")
