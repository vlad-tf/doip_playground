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

"""F17 portable signal handling and bounded real-process SIGTERM tests."""

import asyncio
import os
from pathlib import Path
import signal
import subprocess
import sys
import textwrap
from unittest.mock import AsyncMock, Mock, patch

import pytest

import main


def test_signal_handlers_restore_previous_values_after_normal_return():
    async def scenario():
        previous = {signal.SIGINT: signal.SIG_DFL, signal.SIGTERM: signal.SIG_IGN}
        installed = dict(previous)
        def install(signum, handler):
            old = installed[signum]
            installed[signum] = handler
            return old
        with patch.object(signal, "getsignal", side_effect=lambda s: installed[s]), \
             patch.object(signal, "signal", side_effect=install) as setter:
            await main._run(Mock(start=AsyncMock()))
        assert installed == previous
        assert setter.call_count == 4
    asyncio.run(scenario())


def test_first_signal_schedules_cancel_and_repeats_cannot_cancel_teardown():
    async def scenario():
        entered, closing, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        installed = {}
        async def start():
            entered.set()
            try:
                await asyncio.Future()
            finally:
                closing.set()
                await release.wait()
        loop = asyncio.get_running_loop()
        original = loop.call_soon_threadsafe
        def install(signum, handler):
            installed[signum] = handler
        with patch.object(signal, "signal", side_effect=install), \
             patch.object(signal, "getsignal", return_value=signal.SIG_DFL), \
             patch.object(loop, "call_soon_threadsafe", wraps=original) as schedule:
            task = asyncio.create_task(main._run(Mock(start=start)))
            try:
                await asyncio.wait_for(entered.wait(), 1)
                handler = installed[signal.SIGTERM]
                handler(signal.SIGTERM, None)
                await asyncio.wait_for(closing.wait(), 1)
                handler(signal.SIGINT, None)
                handler(signal.SIGTERM, None)
                await asyncio.sleep(0)
                assert schedule.call_count == 1 and not task.done()
                release.set()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 1)
            finally:
                release.set()
                await asyncio.gather(task, return_exceptions=True)
    asyncio.run(scenario())


def test_main_signal_cancellation_has_success_exit_status():
    def cancelled(coro):
        coro.close()
        raise asyncio.CancelledError
    with patch.object(main, "load_config", return_value=object()), \
         patch.object(main, "DoIPServer", return_value=Mock()), \
         patch.object(main.asyncio, "run", side_effect=cancelled), \
         patch.object(sys, "argv", ["main.py"]):
        with pytest.raises(SystemExit) as exc:
            main.main()
    assert exc.value.code == 0


def test_real_sigterm_process_runs_cleanup_before_successful_exit(tmp_path):
    ready, cleaned = tmp_path / "ready", tmp_path / "cleaned"
    script = textwrap.dedent("""
        import asyncio, pathlib, sys
        import main
        main.load_config = lambda _: object()
        args = sys.argv[1:]
        sys.argv = ['main.py']
        original = pathlib.Path
        class Process:
            async def start(self):
                original(args[0]).write_text('ready')
                try:
                    await asyncio.Future()
                finally:
                    await asyncio.sleep(0.02)
                    original(args[1]).write_text('cleaned')
        main.DoIPServer = lambda _: Process()
        main.main()
    """)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.Popen([sys.executable, "-c", script, str(ready), str(cleaned)],
                            cwd=Path(__file__).resolve().parents[1], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        import time
        deadline = time.monotonic() + 4
        while not ready.exists() and proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready.exists(), "child did not install handlers and reach startup"
        proc.send_signal(signal.SIGTERM)
        stdout, stderr = proc.communicate(timeout=5)
        assert proc.returncode == 0, (stdout, stderr)
        assert cleaned.read_text() == "cleaned"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=1)
