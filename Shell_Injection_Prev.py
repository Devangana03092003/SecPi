import re
from typing import Union

class SafeHandler:
    def _init_(self):
        self.metacharacters = r'[\\^$.*+?{}()|[\]]'
        
    def escape_metacharacters(self, string: str) -> str:
        """
        Escape metacharacters in a string.
        """
        new_string = string
        for char in string:
            if re.search(self.metacharacters, char):
                new_string = re.sub(self.metacharacters, r'\\\g<0>', new_string)
        return new_string

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

    def is_potentially_unsafe(self, query: str) -> bool:
        """
        Check if a string is potentially an SQL Injection attack.
        """
        # Decode the query if it's a Unicode string
        decoded_query = bytes(query, "utf-8").decode("unicode_escape")

        # A very basic check for some common SQL injection techniques
        patterns = [
            r"'.+--",
            r"'.+;",
            r"'.+\/\*",
            r"'.+\*\/",
            r"'.+union.+select",
            r"'.+drop",
            r"'.+delete",
            r"'.+update",
            r"'.+insert",
            r"'.+alter",
            r"'.+exec",
            r"'.+execute",
            r"'.+truncate",
            r"'.+declare",
            r"\bOR\b",
            r"\bAND\b"
        ]
        for pattern in patterns:
            if re.search(pattern, decoded_query, re.IGNORECASE):
                return True
        return False

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

    def is_csrf_attack(self, input_string: str) -> bool:
        """
        Check if a string is potentially a CSRF attack.
        """
        csrf_patterns = [
            r"<img src=",
            r"<iframe src=",
            r"<form action=",
            r"<input type=\"hidden\"",
            r"<body onload=",
            r"<script src=",
            r"<link href=",
            r"<meta http-equiv=",
            r"<object data=",
            r"<embed src=",
            r"<applet code=",
            r"<base href=",
            r"<video src=",
            r"<audio src=",
            r"<source src=",
            r"<track src=",
            r"<frame src=",
            r"<frameset rows=",
            r"<bgsound src=",
            r"<marquee loop=",
            r"<keygen autofocus>",
            r"<textarea autofocus>",
            r"<isindex type=",
            r"<style>@import",
            r"<style>body:before",
            r"<style>:target"
        ]
        for pattern in csrf_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True
        return False

# Instantiate the SafeHandler class
handler = SafeHandler()

# Take any input from the user
user_input = input("Enter your input: ")

# Check if the input is potentially unsafe
if handler.is_potentially_unsafe(user_input):
    print("Warning: The input is potentially unsafe due to SQL Injection.")
elif handler.is_xss_attack(user_input):
    print("Warning: The input is potentially an XSS attack.")
elif handler.is_csrf_attack(user_input):
    print("Warning: The input is potentially a CSRF attack.")
else:
    print("The input is safe.")