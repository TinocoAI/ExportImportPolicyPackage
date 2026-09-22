import os
import time

import sys

from importing.import_objects import import_objects, add_tag_to_object_payload
from utils import debug_log, generate_import_error_report, count_global_layers, compare_versions, \
    generate_prerequisites_report


def check_import_prerequisites_from_tar(tar_file_path):
    """Inspect the tar package for import prerequisites, whether via a bundled
    import_prerequisites.json or by dynamic scan of exported access-role files."""
    import tarfile
    import json
    import csv

    prereqs = {"ldap_account_units": {}, "gateway_clusters": []}

    try:
        with tarfile.open(tar_file_path, "r:*") as tf:
            # First check for the pre-generated prerequisites file
            try:
                member = tf.getmember("import_prerequisites.json")
                f = tf.extractfile(member)
                if f:
                    loaded = json.load(f)
                    # Backfill gateway_clusters if the file was generated with an older version
                    if "gateway_clusters" not in loaded:
                        loaded["gateway_clusters"] = []
                        sc_members = [m for m in tf.getmembers() if "simple-cluster" in m.name and m.name.endswith(".json")]
                        for sc_member in sc_members:
                            sf = tf.extractfile(sc_member)
                            if sf:
                                try:
                                    sc_data = json.load(sf)
                                    sc_objs = sc_data if isinstance(sc_data, list) else list(sc_data.values())[0]
                                    from utils import analyze_import_prerequisites
                                    sc_prereqs = analyze_import_prerequisites({"simple-cluster": sc_objs})
                                    loaded["gateway_clusters"] = sc_prereqs.get("gateway_clusters", [])
                                except Exception:
                                    pass
                    return loaded
            except KeyError:
                pass

            # Fallback: dynamically scan access-role and simple-cluster files inside the tar
            data_for_analysis = {}
            ar_members = [m for m in tf.getmembers() if "add-access-role" in m.name and m.name.endswith(".json")]
            for member in ar_members:
                f = tf.extractfile(member)
                if f:
                    try:
                        data = json.load(f)
                        roles = data if isinstance(data, list) else list(data.values())[0]
                        data_for_analysis["access-role"] = roles
                    except Exception:
                        pass
            sc_members = [m for m in tf.getmembers() if "simple-cluster" in m.name and m.name.endswith(".json")]
            for sc_member in sc_members:
                sf = tf.extractfile(sc_member)
                if sf:
                    try:
                        sc_data = json.load(sf)
                        sc_objs = sc_data if isinstance(sc_data, list) else list(sc_data.values())[0]
                        data_for_analysis["simple-cluster"] = sc_objs
                    except Exception:
                        pass
            if data_for_analysis:
                from utils import analyze_import_prerequisites
                return analyze_import_prerequisites(data_for_analysis)
    except Exception:
        pass

    return prereqs


def import_package(client, args):

    if not os.path.isfile(args.file):
        debug_log("No file named " + args.file + " found!", True, True)
        sys.exit(1)

    # Check for import prerequisites before anything else
    prereqs = check_import_prerequisites_from_tar(args.file)
    if prereqs.get("ldap_account_units") or prereqs.get("gateway_clusters"):
        report = generate_prerequisites_report(prereqs)
        print(report)

    if prereqs.get("ldap_account_units") and not args.force:
        print("Please verify that the above prerequisites are configured on the destination Management Server.")
        print("1. Prerequisites are met - Continue with import")
        print("2. Cancel import to resolve prerequisites")
        choice = ""
        chosen = False
        while not chosen:
            choice = input()
            if choice not in ["1", "2"]:
                print("Please enter either '1' or '2'")
            else:
                chosen = True
        if choice == "2":
            print("Import cancelled by user.")
            sys.exit(0)

    # Cluster fallback: ask how to handle clusters that cannot be imported via API
    cluster_fallback = "dummy"  # default: create dummy host placeholders
    if prereqs.get("gateway_clusters") and not args.force:
        print("Gateway/Cluster objects listed above cannot be imported via the Management API.")
        print("How should rules referencing these objects be handled?")
        print("1. Create dummy host placeholders (import completes, recreate manually later in SmartConsole)")
        print("2. Skip entirely (rules referencing these objects will fail to import)")
        choice = ""
        chosen = False
        while not chosen:
            choice = input()
            if choice not in ["1", "2"]:
                print("Please enter either '1' or '2'")
            else:
                chosen = True
        cluster_fallback = "dummy" if choice == "1" else "skip"

    # Store decision so import_objects can consult it
    import importing.import_objects as _io
    _io.cluster_fallback_mode = cluster_fallback
    _io.unimportable_cluster_names = set(c["export_name"] for c in prereqs.get("gateway_clusters", []))

    timestamp = time.strftime("%Y_%m_%d_%H_%M")

    if not args.name:
        try:
            package = '__'.join(args.file.split('__')[2:-1])
        except (KeyError, ValueError):
            package = "Imported_Package_" + timestamp
    else:
        package = args.name

    if len(package) == 0:
        debug_log("A package name for import was not provided!", True, True)
        sys.exit(1)

    debug_log("Checking if package already exists...")
    show_package = client.api_call("show-package", {"name": package, "details-level": "full"})
    if "code" in show_package.data and "not_found" in show_package.data["code"]:
        debug_log("Creating a Policy Package named [" + package + "]", True)
        package_payload = {"name": package, "access": True, "threat-prevention": True}
        if args.tag_objects_on_import != "":
            add_tag_to_object_payload(args.tag_objects_on_import, package_payload, "package", client)
        client.api_call("add-package", package_payload)
        client.api_call("publish", wait_for_task=True)
    else:
        if not args.force:
            print("A package named " + package + " already exists. Are you sure you want to import?")
            print("1.Yes")
            print("2.No")
            choice = ""
            chosen = False
            while not chosen:
                choice = input()
                if choice not in ["1", "2"]:
                    print("Please enter either '1' or '2'")
                else:
                    chosen = True
            if choice == '2':
                exit(0)

    debug_log("Importing general objects", True)
    machine_version = client.api_version
    layers_to_attach = import_objects(args.file, client, {}, package, None, args)

    num_global_access, num_global_threat = count_global_layers(client, package)

    access_layer_position = num_global_access + 1
    threat_layer_position = num_global_threat + 3

    access_layers = []
    threat_layers = []

    for access_layer in layers_to_attach["access"]:
        access_layers.append({"name": access_layer, "position": access_layer_position})
        access_layer_position += 1

    for threat_layer in layers_to_attach["threat"]:
        threat_layers.append({"name": threat_layer, "position": threat_layer_position})
        threat_layer_position += 1

    set_package_payload = {"name": package, "access-layers": {"add": access_layers},
                           "threat-layers": {"add": threat_layers}}

    if "https" in layers_to_attach and len(layers_to_attach["https"]) > 0:
        # If the imported package's version < 2
        if compare_versions(client.api_version, '2') == -1:
            outbound_layer_name = layers_to_attach["https"][0]
            # If the version of the machine importing the package < 2
            if compare_versions(machine_version, '2') == -1:
                set_package_payload["https-layer"] = outbound_layer_name

        else:
            inbound_layer_name = layers_to_attach["https"][0]
            outbound_layer_name = layers_to_attach["https"][1]
            set_package_payload["https-inspection-layers"] = {"inbound-https-layer": inbound_layer_name,
                                                              "outbound-https-layer": outbound_layer_name}

        # Remove default 'Predefined Rule'
        https_rulebase_reply = client.api_call("show-https-rulebase",
                                               {"name": outbound_layer_name, "details-level": "uid"})
        if https_rulebase_reply.success and "total" in https_rulebase_reply.data:
            last_rule_number = int(https_rulebase_reply.data["total"])
            if last_rule_number > 1:
                delete_https_rule = client.api_call("delete-https-rule",
                                                    {"rule-number": last_rule_number, "layer": outbound_layer_name})
                if not delete_https_rule.success:
                    debug_log("Failed to remove default Predefined Rule in https layer [" + outbound_layer_name + "]",
                              True, True)

    debug_log("Attaching layers to package")
    layer_attachment_reply = client.api_call("set-package", set_package_payload)
    if not layer_attachment_reply.success:
        debug_log("Failed to attach layers to package! "
                  "Error: " + layer_attachment_reply.error_message + ". Import operation aborted.", True, True)
    publish_reply = client.api_call("publish", wait_for_task=True)
    if not publish_reply.success:
        debug_log("Failed to attach layers to package! "
                  "Error: " + publish_reply.error_message + ". Import operation aborted.", True, True)
        sys.exit(1)

    generate_import_error_report()