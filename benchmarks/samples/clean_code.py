# Clean control code with safe practices
import os

def get_config_value(key: str, default: str = "") -> str:
    return os.environ.get(key, default)

def add_numbers(a: int, b: int) -> int:
    return a + b
