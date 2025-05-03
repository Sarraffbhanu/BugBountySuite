from urllib.parse import urlparse, parse_qs
import re

class ParameterDiscover:
    @staticmethod
    def from_url(url):
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())

    @staticmethod
    def from_response(response_text):
        forms = re.findall(r'<form.*?</form>', response_text, re.DOTALL)
        params = []
        for form in forms:
            params += re.findall(r'name=["\'](.*?)["\']', form)
        return list(set(params))
