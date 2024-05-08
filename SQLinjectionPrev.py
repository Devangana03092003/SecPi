import re
from typing import Union

class SafeHandler:
    def __init__(self):
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

    def safe_sql(self, query: str, *params) -> str:
        """
        Create a safe SQL query by escaping metacharacters and handling Unicode in parameters.
        """
        safe_params = [self.safe_unicode(self.escape_metacharacters(p)) for p in params]
        return query.format(*safe_params)

    def is_potentially_unsafe(self, query: str) -> bool:
        """
        Check if a SQL query or a decoded Unicode string is potentially unsafe.
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
            r"\bAND\b",
            r"==",
            r"--"
        ]
        for pattern in patterns:
            if re.search(pattern, decoded_query, re.IGNORECASE):
                return True
        return False

# Instantiate the SafeHandler class
handler = SafeHandler()

# Take a SQL query or a Unicode string as input from the user
user_input = input("Enter a SQL query or a Unicode string: ")

# Check if the input is potentially unsafe
if handler.is_potentially_unsafe(user_input):
    print("Warning: The input is potentially unsafe.")
else:
    print("The input is safe.")