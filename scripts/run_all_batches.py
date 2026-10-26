#!/usr/bin/env python3
"""Master Orchestrator to Execute All 81 High-Quality Contributions."""

import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

def main():
    print("================================================================")
    print("  Generating 81 Production-Grade GitHub Contributions")
    print("================================================================")
    
    # Run Batch 1
    print("\n--- [1/4] Running Batch 1: Sigma Detection Rules (18 Commits) ---")
    subprocess.run([sys.executable, str(BASE_DIR / "scripts" / "generate_batch1.py")], check=True)
    
    # Run Batch 2
    print("\n--- [2/4] Running Batch 2: SOAR Handlers Expansion (11 Commits) ---")
    subprocess.run([sys.executable, str(BASE_DIR / "scripts" / "generate_batch2.py")], check=True)
    
    # Run Batch 3
    print("\n--- [3/4] Running Batch 3: SOAR Utilities and Unit Tests (22 Commits) ---")
    subprocess.run([sys.executable, str(BASE_DIR / "scripts" / "generate_batch3.py")], check=True)
    
    # Run Batch 4
    print("\n--- [4/4] Running Batch 4: Atomic Red Team, Playbooks, Terraform & Web (30 Commits) ---")
    subprocess.run([sys.executable, str(BASE_DIR / "scripts" / "generate_batch4.py")], check=True)

    print("\n================================================================")
    print("  All 81 Commits Created Successfully!")
    print("================================================================")

if __name__ == "__main__":
    main()
