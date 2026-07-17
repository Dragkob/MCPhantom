"""
Automatically discovers and loads all plugins.
"""

from importlib import import_module
from pathlib import Path
import inspect


def load_plugins():

    plugins = []

    plugin_dir = Path(__file__).parent / "plugins"

    for file in plugin_dir.glob("*.py"):

        #
        # Skip non-plugins
        #

        if file.stem.startswith("_"):
            continue

        if file.stem == "base":
            continue

        module = import_module(f"audit.plugins.{file.stem}")

        for _, obj in inspect.getmembers(module, inspect.isclass):

            #
            # Ignore imported classes
            #

            if obj.__module__ != module.__name__:
                continue

            #
            # Ignore the abstract base class
            #

            if obj.__name__ == "Plugin":
                continue

            plugins.append(obj())

    #
    # Deterministic ordering
    #

    plugins.sort(key=lambda p: p.name)

    return plugins