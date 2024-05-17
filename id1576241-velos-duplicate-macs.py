#!/usr/bin/env python3

# v1.0 - 2024-05-16 - initial version

from collections import namedtuple
from itertools import combinations
import json
import logging
from typing import Dict, List
import subprocess
import sys


logger = logging.getLogger(__name__)

# Cache mapping of partition IDs to the controller on which their services are active.
PARTITION_ACTIVE_CONTROLLER = {}
# Partition ID<>name mappings
PARTITION_ID_NAME_MAP = {}

CONFD_CLI_PARAMS = ["-u", "system", "-g", "admin", "-C"]

PartitionData = namedtuple(
    "PartitionData", "allocated total lacp lags tenants all_macs overlap_macs"
)


def execute(cmd: List[str], input: str = None) -> dict:
    """Run a command, pass it the specified input, and parse the response as JSON"""

    # Commands written on standard input to the confd CLI need to end with a newline
    # so that they're recognized as commands and executed; closing the input stream
    # doesn't count/isn't sufficient.
    if isinstance(input, str) and not input.endswith("\n"):
        input = f"{input}\n"

    logger.debug("Running %s and passing to stdin '%r'", cmd, input)
    output = subprocess.check_output(cmd, input=input, universal_newlines=True)

    logger.debug("Output from running %r: %s", input, output)
    return json.loads(output)


def controller_cmd(cmd: str):
    """Run an F5OS CLI (confd) command (e.g. "show system version") on the controller"""
    return execute(
        ["/var/lib/controller/confd_cli", *CONFD_CLI_PARAMS],
        f"{cmd} | display json\n",
    )


def partition_cmd(cmd: str, partition: int):
    """Run an F5OS CLI (confd) command (e.g. "show system status") in a partition"""

    command = [
        "docker",
        "exec",
        "-i",
        f"partition{partition}_manager",
        "/confd/bin/confd_cli",
        *CONFD_CLI_PARAMS,
    ]

    partition_controller = partition_active_controller(partition)
    if current_controller() != partition_controller:
        # prepend an "ssh <other controller>" to the command to run
        command = [
            "ssh",
            # Sigh
            "-o",
            "UserKnownHostsFile /dev/null",
            "-o",
            "StrictHostKeyChecking no",
            f"controller-{partition_controller}.chassis.local",
            *command,
        ]

    return execute(command, f"{cmd} | display json\n")


def current_controller() -> int:
    """Return the ID (1 or 2) of the local controller"""

    with open("/etc/PLATFORM", encoding="utf-8") as fp:
        for line in fp:
            if line.startswith("Slot:"):
                return int(line.split()[1])

    raise RuntimeError("Could not determine ID of current controller")


def is_controller_active():
    """Return true if running on the active controller, otherwise false."""

    output = controller_cmd("show system redundancy state current-active")
    active_cc = output["data"]["openconfig-system:system"][
        "f5-system-redundancy:redundancy"
    ]["state"]["current-active"]
    return active_cc == f"controller-{current_controller()}"


def populate_partition_data():
    output = controller_cmd("show partitions partition")
    for partition in output["data"]["f5-system-partition:partitions"]["partition"]:
        part_id = partition["state"]["id"]
        name = partition["name"]

        PARTITION_ID_NAME_MAP[name] = part_id
        PARTITION_ID_NAME_MAP[part_id] = name

        # Find the active controller
        found = None
        for controller in partition["state"]["controllers"]["controller"]:
            if controller["partition-status"] == "running-active":
                # controller ID
                found = controller["controller"]

        if found is None:
            logger.debug(
                "Did not find running-active system controller for partition %s (%d)",
                name,
                part_id,
            )
        else:
            logger.debug(
                "Found that partition %s (%d) is active on controller %d",
                name,
                part_id,
                found,
            )
            PARTITION_ACTIVE_CONTROLLER[part_id] = found


def partition_name(partition: int) -> str:
    return f"Partition ID {partition} ({PARTITION_ID_NAME_MAP[partition]})"


def partition_active_controller(partition: int) -> int:
    """
    Determine the ID of the controller on which the partition services for the
    specified partition are active.
    """
    if partition in PARTITION_ACTIVE_CONTROLLER:
        return PARTITION_ACTIVE_CONTROLLER[partition]

    populate_partition_data()
    if partition not in PARTITION_ACTIVE_CONTROLLER:
        raise RuntimeError(
            f"Could not determine ID of controller running services for partition {partition}"
        )
    return PARTITION_ACTIVE_CONTROLLER[partition]


def partition_macs(partition: int):
    """Query the partition for its allocated MACs (LACP, LAGs, tenants)"""

    # Overall counts
    output = partition_cmd("show system mac-allocation state", partition)
    counts = output["data"]["openconfig-system:system"][
        "f5-system-mac-allocation:mac-allocation"
    ]["state"]

    total_allocated_mac_count: int = counts["total-allocated-mac-count"]
    total_mac_count: int = counts["total-mac-count"]

    all_macs = set()
    overlap_macs = set()

    # LACP system ID
    output = partition_cmd("show lacp state system-id-mac", partition)
    lacp_mac: str = output["data"]["openconfig-lacp:lacp"]["state"][
        "f5-lacp:system-id-mac"
    ]
    all_macs.add(lacp_mac)

    # LAGs
    # ID1319357: 'show interfaces interface aggregation | display json' generates invalid JSON
    output = partition_cmd("show interfaces", partition)
    lag_macs: List[str] = []
    for interface in (
        output["data"].get("openconfig-interfaces:interfaces", {}).get("interface", [])
    ):
        if "openconfig-if-aggregate:aggregation" not in interface:
            continue
        mac = interface["openconfig-if-aggregate:aggregation"]["state"][
            "f5-if-aggregate:mac-address"
        ]
        lag_macs.append(mac)

        # Look for use of duplicate MACs within the partition
        if mac in all_macs:
            overlap_macs.add(mac)
        else:
            all_macs.add(mac)

    # Tenants
    output = partition_cmd("show tenants tenant state mac-data", partition)
    tenant_macs: Dict[str, set] = {}

    for tenant in output["data"].get("f5-tenants:tenants", {}).get("tenant", []):
        name = tenant["name"]
        # [{'mac': '14:a9:d0:42:47:42'}, ...]
        block = tenant["state"]["mac-data"]["f5-tenant-l2-inline:mac-block"]
        tenant_macs[name] = {item["mac"] for item in block}

        # Look for use of duplicate MACs within the partition
        overlap = all_macs.intersection(tenant_macs[name])
        if overlap:
            overlap_macs.update(overlap)
        all_macs.update(tenant_macs[name])

    return PartitionData(
        total_allocated_mac_count,
        total_mac_count,
        lacp_mac,
        lag_macs,
        tenant_macs,
        all_macs,
        overlap_macs,
    )


def partitions_macs():
    result: Dict[int, PartitionData] = {}
    populate_partition_data()
    for part_id in sorted(PARTITION_ACTIVE_CONTROLLER.keys()):
        result[part_id] = partition_macs(part_id)

    return result


def controller_macs():
    """Query the system controller for its state of allocated MACs"""

    result: Dict[int, set] = {}

    output = controller_cmd("show system chassis-macs")
    for partition in (
        output["data"]["openconfig-system:system"][
            "f5-system-chassis-macs:chassis-macs"
        ]
        .get("partitions", {})
        .get("partition", [])
    ):
        part_id = partition["identifier"]

        allocated_macs = {item["mac-address"] for item in partition["macs"]["mac"]}
        result[part_id] = allocated_macs

    output = controller_cmd("show system mac-allocation")
    total_allocated_mac_count: int = output["data"]["openconfig-system:system"][
        "f5-system-mac-allocation:mac-allocation"
    ]["state"]["total-allocated-mac-count"]

    return total_allocated_mac_count, result


def check():
    everything_okay = True

    # The system controller view of the world
    chassis_total_allocated_macs, controller_state = controller_macs()

    # The running partitions' views of the world
    partition_state = partitions_macs()

    # The total number of allocated MACs according to the controller should match
    # the total number of MACs (not just 'allocated') according to all partitions
    partition_total_macs = sum(part.total for part in partition_state.values())
    if chassis_total_allocated_macs != partition_total_macs:
        everything_okay = False

        print("ERROR: Chassis allocated and partition total MAC counts do not match!")
        print(f"Chassis allocated MAC count: {chassis_total_allocated_macs}")
        print(f"Partition total MAC count: {partition_total_macs}")
        for part_id, part in partition_state.items():
            print(f"    {partition_name(part_id)} total mac count: {part.total}")

        print()

    # No partition should have found overlap *in its own data* (i.e. two tenants using the same MACs)
    for part_id, part in partition_state.items():
        if part.overlap_macs:
            everything_okay = False

            print(
                "ERROR: Duplicate MACs in use by multiple objects (tenants, LAGs, "
                f"LACP system ID) in {partition_name(part_id)}:"
            )
            print(f"    {sorted(part.overlap_macs)}")
            print()

    # Every MAC seen in the partition data should _also_ be seen in the partition
    # data on the system controller.
    for part_id, part in partition_state.items():
        if part_id not in controller_state:
            everything_okay = False
            print(
                f"ERROR: System controller missing data for {partition_name(part_id)}"
            )
            print()
            continue

        controller_part = controller_state[part_id]

        # There should be no MACs present in the partition data that aren't
        # also in the controller state data.
        missing_from_controller = sorted(part.all_macs - controller_part)
        if missing_from_controller:
            everything_okay = False
            print(
                f"ERROR: {partition_name(part_id)} is using MACs not known in "
                "system controller state:"
            )
            print(f"    {missing_from_controller}")
            print()

    # No partition should have overlap with another partition
    # This loops over all combinations of distinct partitions without repeats
    for part_id_a, part_id_b in combinations(sorted(partition_state.keys()), r=2):
        part_a = partition_state[part_id_a]
        part_b = partition_state[part_id_b]

        # There should be no overlap in the MACs present in the partitions.
        overlap = sorted(part_a.all_macs & part_b.all_macs)
        if overlap:
            everything_okay = False
            print(
                f"ERROR: {partition_name(part_id_a)} and {partition_name(part_id_b)} "
                "are incorrectly using the same MACs:"
            )
            print(f"    {overlap}")
            print()

    return everything_okay


if __name__ == "__main__":
    from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

    parser = ArgumentParser(
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--log-level",
        choices=("debug", "info", "warning", "error"),
        default="info",
        help="Log level for this script",
    )
    parser.add_argument(
        "--exit-status",
        action="store_true",
        help="Exit script with non-zero status when issues are detected",
    )
    args = parser.parse_args()
    logging.basicConfig(
        format="%(levelname)s %(asctime)s %(name)s %(message)s",
        level=logging.getLevelName(args.log_level.upper()),
    )

    if not is_controller_active():
        print("Controller is standby. Please run this on the active controller.")
        sys.exit(0)

    result = check()
    if result:
        print("No problems found")
    if args.exit_status:
        sys.exit(0 if result else 1)
