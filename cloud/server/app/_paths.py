"""sys.path set-up: the core (svidetel_v4, anchor) is IMPORTED from the project root; wa_profile from cloud/contract.
Overrides for a container: DW_CORE_DIR (dir that holds svidetel_v4/ and anchor/), DW_CONTRACT_DIR (dir that holds wa_profile.py).
0.2: cloud/contract/v02 (wq_profile, DW_CONTRACT02_DIR) and cloud/lib/dlp (dw_dlp of task 03, DW_DLP_DIR) are importable too.
0.2.27: cloud/node2 (package node2: the open code of node 2, DW_NODE2_DIR)."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.dirname(HERE)
CLOUD = os.path.dirname(SERVER)
CORE_DIR = os.environ.get("DW_CORE_DIR") or os.path.dirname(CLOUD)
CONTRACT_DIR = os.environ.get("DW_CONTRACT_DIR") or os.path.join(CLOUD, "contract")
CONTRACT02_DIR = os.environ.get("DW_CONTRACT02_DIR") or os.path.join(CLOUD, "contract", "v02")
DLP_DIR = os.environ.get("DW_DLP_DIR") or os.path.join(CLOUD, "lib", "dlp")
NODE2_DIR = os.environ.get("DW_NODE2_DIR") or os.path.join(CLOUD, "node2")      # 0.2.27: holds the package node2/ (cosign, attest, amd)
WEB_DIR_DEFAULT = os.path.join(CLOUD, "web")
for p in (CONTRACT_DIR, CORE_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)
for p in (CONTRACT02_DIR, DLP_DIR, NODE2_DIR):        # appended: a module of theirs never shadows the server's own packages
    if p not in sys.path:
        sys.path.append(p)
