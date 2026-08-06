# Copyright 2026 Vladislav Vostrykh, Technica Engineering GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Plugin discovery and instantiation.

Follows the ``_build_middleware`` idiom from ``doip_edgenode/server.py``: the
YAML ``params:`` mapping becomes constructor keyword arguments, and anything
that goes wrong with one plugin is logged and skipped rather than taking the
process down.  ``plugins.strict: true`` turns a load failure into a hard
startup error, which is what you want in CI.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import os
import re
import sys
from typing import List

from testecu.config import PluginSpec
from testecu.plugin import Plugin

logger = logging.getLogger("testecu.loader")


def load_plugins(specs: List[PluginSpec], strict: bool = False) -> List[Plugin]:
    """
    Import every spec and instantiate the ``Plugin`` subclasses it defines.

    ``load_index`` is assigned from the position in ``specs``, so the resolved
    ordering key ``(priority, load_index, name)`` is stable across runs.
    """
    plugins: List[Plugin] = []

    for index, spec in enumerate(specs):
        if not spec.enabled:
            logger.info("plugins: %s disabled by config — skipping", spec.label)
            continue
        try:
            module = _import_spec(spec)
        except Exception:
            logger.exception("plugins: failed to import %s — skipping", spec.label)
            if strict:
                raise
            continue

        try:
            classes = _plugin_classes(module)
            if not classes:
                logger.warning(
                    "plugins: %s defines no Plugin subclass — skipping", spec.label
                )
                continue
            for cls in classes:
                obj = cls(**spec.params)
                if spec.priority is not None:
                    obj.priority = spec.priority
                obj.load_index = index
                plugins.append(obj)
                logger.info(
                    "plugins: loaded %s (priority=%d) from %s",
                    obj.name, obj.priority, spec.label,
                )
        except Exception:
            logger.exception("plugins: failed to instantiate %s — skipping", spec.label)
            if strict:
                raise

    return plugins


def _plugin_classes(module) -> List[type]:
    """
    Plugin subclasses *defined by* this module.

    The ``__module__`` check keeps a re-imported base class (``from testecu
    import Plugin``, or a shared base imported from a sibling file) from being
    instantiated a second time.
    """
    found = [
        obj for obj in vars(module).values()
        if isinstance(obj, type)
        and issubclass(obj, Plugin)
        and obj is not Plugin
        and getattr(obj, "__module__", None) == module.__name__
    ]
    return sorted(found, key=lambda cls: cls.__name__)


def _import_spec(spec: PluginSpec):
    if spec.module:
        return importlib.import_module(spec.module)

    path = spec.file or ""
    if not os.path.isfile(path):
        raise ImportError("plugin file %r does not exist" % path)

    stem = os.path.splitext(os.path.basename(path))[0]
    mod_name = "testecu_plugin_" + re.sub(r"\W", "_", stem)

    ispec = importlib.util.spec_from_file_location(mod_name, path)
    if ispec is None or ispec.loader is None:
        raise ImportError("cannot build an import spec for %r" % path)

    module = importlib.util.module_from_spec(ispec)
    # Register before exec_module: dataclasses and typing resolve annotations
    # via sys.modules, and a plugin that fails halfway must not leave a
    # half-built module behind.
    sys.modules[mod_name] = module
    try:
        ispec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(mod_name, None)
        raise
    return module
