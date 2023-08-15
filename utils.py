from typing import Any


def set_nested(d: dict[Any, Any], keys: list[Any], value: Any):
    for key in keys[:-1]:  # all keys but the last
        d = d.setdefault(key, {})
    d[keys[-1]] = value
