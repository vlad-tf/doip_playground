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

"""Plugin discovery, instantiation, params, ordering, and error isolation."""

from __future__ import annotations

import os
import textwrap

import pytest

from conftest import BASE_CONFIG, merge
from testecu.config import PluginSpec, parse_config
from testecu.core import EcuCore
from testecu.loader import load_plugins

REPO_TEST_ECU = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GOOD = textwrap.dedent("""
    from testecu import Plugin, read_did

    class Good(Plugin):
        name = "Good"

        def __init__(self, marker="default", **params):
            super().__init__(marker=marker, **params)

        @read_did(0x1234)
        def value(self, req, ctx):
            return self.marker.encode()
""")

BROKEN_SYNTAX = "this is not python at all ((("

BROKEN_INIT = textwrap.dedent("""
    from testecu import Plugin

    class Exploding(Plugin):
        def __init__(self, **params):
            raise RuntimeError("cannot construct me")
""")

NO_PLUGIN = "VALUE = 42\n"

TWO_PLUGINS = textwrap.dedent("""
    from testecu import Plugin, on_service

    class Bravo(Plugin):
        @on_service(0x31)
        def handle(self, req, ctx):
            return None

    class Alpha(Plugin):
        @on_service(0x22)
        def handle(self, req, ctx):
            return None
""")


def write(tmp_path, name, body):
    path = tmp_path / name
    path.write_text(body)
    return str(path)


def spec(path, **kwargs):
    return PluginSpec(label=os.path.basename(path), file=path, **kwargs)


class TestLoadingByPath:
    def test_a_plugin_file_is_loaded_and_instantiated(self, tmp_path):
        plugins = load_plugins([spec(write(tmp_path, "good.py", GOOD))])
        assert [p.name for p in plugins] == ["Good"]

    def test_params_become_constructor_arguments(self, tmp_path):
        plugins = load_plugins([spec(write(tmp_path, "good.py", GOOD),
                                     params={"marker": "from-yaml"})])
        assert plugins[0].marker == "from-yaml"

    def test_priority_from_config_overrides_the_class_attribute(self, tmp_path):
        plugins = load_plugins([spec(write(tmp_path, "good.py", GOOD), priority=7)])
        assert plugins[0].priority == 7

    def test_disabled_specs_are_skipped(self, tmp_path):
        assert load_plugins([spec(write(tmp_path, "good.py", GOOD),
                                  enabled=False)]) == []

    def test_a_missing_file_is_skipped(self, tmp_path):
        assert load_plugins([spec(str(tmp_path / "absent.py"))]) == []

    def test_several_classes_in_one_file_load_in_name_order(self, tmp_path):
        plugins = load_plugins([spec(write(tmp_path, "two.py", TWO_PLUGINS))])
        assert [p.name for p in plugins] == ["Alpha", "Bravo"]


class TestLoadingByModule:
    def test_an_importable_module_name_works(self):
        plugins = load_plugins([PluginSpec(label="example_engine",
                                           module="plugins.example_engine")])
        assert any(p.name == "EngineEcu" for p in plugins)


class TestErrorIsolation:
    def test_a_syntactically_broken_plugin_is_skipped(self, tmp_path):
        specs = [spec(write(tmp_path, "bad.py", BROKEN_SYNTAX)),
                 spec(write(tmp_path, "good.py", GOOD))]
        assert [p.name for p in load_plugins(specs)] == ["Good"]

    def test_a_plugin_that_cannot_be_constructed_is_skipped(self, tmp_path):
        specs = [spec(write(tmp_path, "boom.py", BROKEN_INIT)),
                 spec(write(tmp_path, "good.py", GOOD))]
        assert [p.name for p in load_plugins(specs)] == ["Good"]

    def test_strict_mode_re_raises_an_import_error(self, tmp_path):
        with pytest.raises(Exception):
            load_plugins([spec(write(tmp_path, "bad.py", BROKEN_SYNTAX))], strict=True)

    def test_a_module_with_no_plugin_class_is_warned_about(self, tmp_path, caplog):
        assert load_plugins([spec(write(tmp_path, "empty.py", NO_PLUGIN))]) == []
        assert any("no Plugin subclass" in record.message for record in caplog.records)

    def test_the_base_class_is_never_instantiated(self, tmp_path):
        body = "from testecu import Plugin\n"
        assert load_plugins([spec(write(tmp_path, "reexport.py", body))]) == []

    def test_a_broken_plugin_does_not_stop_the_ecu_from_answering(self, tmp_path):
        specs = [spec(write(tmp_path, "bad.py", BROKEN_SYNTAX))]
        config = parse_config(merge(BASE_CONFIG, {}))
        ecu = EcuCore(config, plugins=load_plugins(specs))
        assert ecu.plugins == []
        assert ecu.dispatcher.describe() == []


class TestOrdering:
    def test_load_index_follows_the_spec_order(self, tmp_path):
        first = spec(write(tmp_path, "a.py", GOOD))
        second = spec(write(tmp_path, "b.py", GOOD.replace('"Good"', '"Second"')))
        plugins = load_plugins([first, second])
        assert [p.load_index for p in plugins] == [0, 1]

    def test_ordering_is_stable_across_runs(self, tmp_path):
        specs = [spec(write(tmp_path, "a.py", GOOD)),
                 spec(write(tmp_path, "b.py", TWO_PLUGINS))]
        first = [(p.name, p.priority, p.load_index) for p in load_plugins(specs)]
        second = [(p.name, p.priority, p.load_index) for p in load_plugins(specs)]
        assert first == second


class TestShippedPlugins:
    def test_the_example_plugins_load_from_the_shipped_config(self):
        from testecu.config import load_config
        config = load_config(os.path.join(REPO_TEST_ECU, "config.yaml"))
        ecu = EcuCore(config)
        names = sorted(p.name for p in ecu.plugins)
        assert names == ["EngineEcu", "RawFaults", "SimpleDtcs"]
        assert ecu.dispatcher.describe()
