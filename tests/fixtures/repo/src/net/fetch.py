"""Outbound fetch (fixture)."""

def fetch(url):
    # NOTE (fixture): user-supplied url reaches requests.get -> SSRF / CWE-918.
    return http.get(url)
