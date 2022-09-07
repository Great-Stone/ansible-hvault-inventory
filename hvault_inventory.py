#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Licensed under the Apache License, Version 2.0

import argparse
import os
import sys
from io import BytesIO
import hvac
import requests

try:
    import json
except ImportError:
    import simplejson as json

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

__version__ = "0.0.2"

inventory = {}
inventory["vault_hosts"] = []
inventory["_meta"] = {}
inventory["_meta"]["hostvars"] = {}

ssh_path = "ansible-ssh"

parser = argparse.ArgumentParser(
    description="Dynamic HashiCorp Vault inventory.",
    epilog="version: " + __version__,
)

parser.add_argument(
    "-l",
    "--list",
    help="print the inventory",
    action="store_true",
)

parser.add_argument(
    "-o",
    "--otp-only",
    help="show only SSH OTP information",
    action="store_true",
)

parser.add_argument(
    "-p",
    "--password-only",
    help="show only local password information",
    action="store_true",
)

args = parser.parse_args()

try:
    client = hvac.Client(
        url=os.environ["VAULT_ADDR"],
        token=os.environ["VAULT_TOKEN"],
        namespace=os.environ["VAULT_NAMESPACE"]
    )

except KeyError as error:
    print("Environment variable " + str(error) + " is missing.", file=sys.stderr)
    sys.exit(1)

if not client.is_authenticated():
    print("Client is not authenticated.")
    sys.exit(1)

try:
    hosts_read_response = client.secrets.kv.read_secret_version(path="ansible-hosts")
except hvac.exceptions.InvalidPath as exception_string:
    print("InvalidPath Exception: ", str(exception_string), file=sys.stderr)
    sys.exit(1)


headers = {
  'X-Vault-Token': os.environ["VAULT_TOKEN"],
  'X-Vault-Namespace': os.environ["VAULT_NAMESPACE"]
}

for host in hosts_read_response["data"]["data"]:
    name = host
    ansible_host = hosts_read_response["data"]["data"][host]
    ANSIBLE_USER = None
    ANSIBLE_PASSWORD = None
    ANSIBLE_PORT = None
    ANSIBLE_BECOME_PASSWORD = None

    inventory["vault_hosts"].append(name)
    inventory["_meta"]["hostvars"][name] = {}

    post_data = {"ip": ansible_host}

    if not args.password_only:
        URL = os.environ["VAULT_ADDR"] + f"/v1/{ssh_path}/creds/otp-key-role"
        res = requests.post(URL, headers=headers, data=post_data)

        ssh_creds_response = res.json()

        try:
            if ssh_creds_response["data"]["username"]:
                ANSIBLE_USER = ssh_creds_response["data"]["username"]
            if ssh_creds_response["data"]["key"]:
                ANSIBLE_PASSWORD = ssh_creds_response["data"]["key"]
            if ssh_creds_response["data"]["port"]:
                ANSIBLE_PORT = ssh_creds_response["data"]["port"]
        except KeyError:
            pass

    if not args.otp_only:
        try:
            if not ANSIBLE_USER:
                try:
                    if os.environ["USER"]:
                        ANSIBLE_USER = os.environ["USER"]
                except KeyError:
                    pass

            user_password_read_response = client.secrets.kv.read_secret_version(
                path="linux/" + name + "/" + ANSIBLE_USER + "_creds",
                mount_point="systemcreds",
            )

            for username in user_password_read_response["data"]["data"]:
                if username == ANSIBLE_USER:
                    ANSIBLE_BECOME_PASSWORD = user_password_read_response["data"][
                        "data"
                    ][username]
        except hvac.exceptions.InvalidPath:
            pass
        except TypeError:
            pass
        except hvac.exceptions.Forbidden:
            pass

    if ansible_host:
        inventory["_meta"]["hostvars"][name]["ansible_host"] = ansible_host
    if ANSIBLE_USER:
        inventory["_meta"]["hostvars"][name]["ansible_user"] = ANSIBLE_USER
    if ANSIBLE_PASSWORD:
        inventory["_meta"]["hostvars"][name]["ansible_password"] = ANSIBLE_PASSWORD
    if ANSIBLE_PORT:
        inventory["_meta"]["hostvars"][name]["ansible_port"] = ANSIBLE_PORT
    if ANSIBLE_BECOME_PASSWORD:
        inventory["_meta"]["hostvars"][name][
            "ansible_become_password"
        ] = ANSIBLE_BECOME_PASSWORD

if args.list:
    print(json.dumps(inventory, sort_keys=True, indent=2))
else:
    print(json.dumps(inventory, sort_keys=True))
