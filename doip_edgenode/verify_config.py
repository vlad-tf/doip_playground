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
Phase 1 verification script.  Run from the doip_edgenode/ directory:

    python3 verify_config.py

Loads config.yaml and prints the routing table.
"""
import sys
import os

# Allow running from the doip_edgenode/ directory
sys.path.insert(0, os.path.dirname(__file__))

from config import load_config
from routing import RoutingTable

cfg = load_config("config.yaml")
rt = RoutingTable(cfg.routing_table)

print(f"Loaded config OK")
print(f"  VIN       : {cfg.doip.vin}")
print(f"  EID       : {cfg.doip.eid}")
print(f"  GID       : {cfg.doip.gid}")
print(f"  TLS ver   : {cfg.tls.tls_version}")
print(f"  Max bytes : {cfg.doip.max_payload_bytes}")
print()
print("Routing table:")
for e in rt.all_entries():
    print(
        f"  tester 0x{e.tester_logical_addr:04X} -> "
        f"ECU 0x{e.ecu_logical_addr:04X}  "
        f"[{e.ecu_ipv6}%{e.ecu_interface}]  "
        f"plain={e.ecu_port_plain}  tls={e.ecu_port_tls}  "
        f"sni={e.ecu_sni!r}"
    )
