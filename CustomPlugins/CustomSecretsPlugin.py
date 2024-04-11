from detect_secrets.plugins.base import BasePlugin


class CustomSecretsPlugin(BasePlugin):
    def analyze_string(self, string, *args):
        if self.is_api_key(string):
            return True
        elif self.is_password(string):
            return True
        elif self.is_cryptographic_key(string):
            return True
        return False

    def is_api_key(self, string):
        # Assuming API keys are 32-character alphanumeric strings
        if len(string) == 32 and string.isalnum():
            return True
        return False

    def is_password(self, string):
        # Assuming passwords are at least 8 characters long and contain a mix of alphanumeric and special characters
        if len(string) >= 8 and any(char.isalpha() for char in string) and any(char.isdigit() for char in string):
            return True
        return False

    def is_cryptographic_key(self, string):
        # Assuming cryptographic keys are 64-character alphanumeric strings
        if len(string) == 64 and string.isalnum():
            return True
        return False
