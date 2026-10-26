"""Atomic Red Team Unified Cloud Attack Simulation Runner."""

import argparse
import json
from simulations.atomic_red_team.art_t1071_ec2 import emulate_ec2_c2_ingress
from simulations.atomic_red_team.art_t1098_iam import emulate_iam_privilege_escalation
from simulations.atomic_red_team.art_t1485_kms import emulate_kms_scheduled_deletion
from simulations.atomic_red_team.art_t1496_crypto import emulate_cryptomining_finding
from simulations.atomic_red_team.art_t1530_s3 import emulate_s3_public_exposure
from simulations.atomic_red_team.art_t1555_secrets import emulate_secrets_manager_dump
from simulations.atomic_red_team.art_t1562_cloudtrail import emulate_cloudtrail_stop_logging


def run_all_simulations():
    """Runs all 7 Atomic Red Team cloud attack vectors."""
    print("=== Launching Atomic Red Team Cloud Threat Suite ===")
    tests = [
        emulate_iam_privilege_escalation(),
        emulate_s3_public_exposure(),
        emulate_ec2_c2_ingress(),
        emulate_cloudtrail_stop_logging(),
        emulate_cryptomining_finding(),
        emulate_kms_scheduled_deletion(),
        emulate_secrets_manager_dump(),
    ]
    for t in tests:
        print(f"[TEST] {t['technique']} - {t['name']} -> EMULATED")
    print(f"=== Successfully executed {len(tests)} adversary techniques ===")


if __name__ == "__main__":
    run_all_simulations()
