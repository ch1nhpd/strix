import importlib
import os
from typing import Any


LITELLM_ENV_DEFAULTS = {
    "LITELLM_LOCAL_MODEL_COST_MAP": "True",
}


def configure_litellm_environment() -> None:
    for key, value in LITELLM_ENV_DEFAULTS.items():
        os.environ.setdefault(key, value)


def import_litellm() -> Any:
    configure_litellm_environment()
    return importlib.import_module("litellm")
