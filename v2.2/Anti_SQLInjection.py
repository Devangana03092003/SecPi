import re
from typing import Union

class SQLInjectionHandler:
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

# Instantiate the SQLInjectionHandler class
handler = SQLInjectionHandler()

# Take any input from the user
user_input = input("Enter your input: ")

# Check if the input is potentially unsafe
if handler.is_potentially_unsafe(user_input):
    print("Warning: The input is potentially unsafe due to SQL Injection.")
else:
    print("The input is safe.")
