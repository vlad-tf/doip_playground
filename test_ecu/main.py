#!/usr/bin/env python3
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
Entry shim so ``python3 main.py`` works from this directory.

The canonical invocation is ``python3 -m testecu``; this file exists because
that is what the echo ECU's Dockerfile and the README's muscle memory expect.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from testecu.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
