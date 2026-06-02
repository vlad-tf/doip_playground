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
