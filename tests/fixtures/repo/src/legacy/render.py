"""Legacy renderer (fixture) — OUT OF SCOPE (/legacy/)."""

def render(template, data):
    return template.format(**data)  # would be XSS-ish but legacy is out of scope
