from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path
from typing import Iterable, List, Sequence, Type

from opsec_sentinel_ai.core.plugin import ScannerPlugin


def instantiate_plugins(plugin_types: Iterable[Type[ScannerPlugin]]) -> List[ScannerPlugin]:
    return [plugin_type() for plugin_type in plugin_types]


def load_plugin_types(paths: Sequence[str]) -> List[Type[ScannerPlugin]]:
    discovered: List[Type[ScannerPlugin]] = []
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            continue
        if path.is_file() and path.suffix == ".py":
            module = _load_module_from_path(path)
            discovered.extend(_plugin_types_from_module(module))
            continue
        for plugin_file in sorted(path.glob("*.py")):
            module = _load_module_from_path(plugin_file)
            discovered.extend(_plugin_types_from_module(module))
    return discovered


def _load_module_from_path(path: Path):
    module_name = f"opsec_dynamic_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load plugin module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _plugin_types_from_module(module) -> List[Type[ScannerPlugin]]:
    types: List[Type[ScannerPlugin]] = []
    for attr in dir(module):
        candidate = getattr(module, attr)
        if isinstance(candidate, type) and issubclass(candidate, ScannerPlugin) and candidate is not ScannerPlugin:
            types.append(candidate)
    return types
