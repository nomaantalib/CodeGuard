# Seeded flaw: swallowed exception
def read_configuration(path: str):
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        pass
    return None
