from . import posthog


__all__ = [
    "Tracer",
    "get_global_tracer",
    "posthog",
    "set_global_tracer",
]


def __getattr__(name: str) -> object:
    if name in {"Tracer", "get_global_tracer", "set_global_tracer"}:
        from .tracer import Tracer, get_global_tracer, set_global_tracer

        exported = {
            "Tracer": Tracer,
            "get_global_tracer": get_global_tracer,
            "set_global_tracer": set_global_tracer,
        }
        return exported[name]

    raise AttributeError(f"module 'strix.telemetry' has no attribute {name!r}")
