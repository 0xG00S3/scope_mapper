#!/usr/bin/env python3
import requests
import csv
import sys
import socket
import re

ARIN_REST_IP = "https://whois.arin.net/rest/ip/"

def resolve_host(entry: str) -> str | None:
    """Resolve a hostname to an IPv4 or return the IP if already valid; None on failure."""
    # quick IPv4 check
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    if ip_pattern.match(entry):
        return entry
    try:
        return socket.gethostbyname(entry)
    except Exception:
        return None

def lookup_ip(ip: str) -> tuple[str, str, str, str]:
    """
    Query ARIN REST (JSON) and return:
      CIDR (joined by ';' if multiple),
      short_name (net.name like 'IPL' / 'MSFT'),
      org_name (orgRef @name like 'Company Name'),
      org_display ('{org_name} ({org_handle})')
    Falls back to 'N/A' on any missing fields or errors.
    """
    headers = {"Accept": "application/json"}
    try:
        r = requests.get(f"{ARIN_REST_IP}{ip}", headers=headers, timeout=10)
        r.raise_for_status()
        data = r.json()
        net = data.get("net", {})

        # short_name (net.name) e.g., 'IPL' / 'MSFT'
        if isinstance(net.get("name"), dict):
            short_name = net["name"].get("$", "N/A")
        else:
            short_name = net.get("name", "N/A") or "N/A"

        # orgRef info
        org_ref = net.get("orgRef", {})
        org_name = org_ref.get("@name", "N/A")
        org_handle = org_ref.get("@handle", "N/A")
        org_display = f"{org_name} ({org_handle})" if org_name != "N/A" and org_handle != "N/A" else "N/A"

        # netBlocks handling (can be dict or list)
        blocks = net.get("netBlocks", {}).get("netBlock", [])
        if isinstance(blocks, dict):  # single block case
            blocks = [blocks]

        cidrs = []
        for b in blocks:
            start = b.get("startAddress", {}).get("$")
            length = b.get("cidrLength", {}).get("$")
            if start and length:
                cidrs.append(f"{start}/{length}")

        cidr = ";".join(cidrs) if cidrs else "N/A"
        return cidr, short_name, org_name, org_display

    except Exception:
        return "N/A", "N/A", "N/A", "N/A"

def main(ip_file: str, hostname_file: str, network_file: str) -> None:
    with open(ip_file) as f:
        entries = [line.strip() for line in f if line.strip()]

    # Open BOTH outputs once; write rows in a single loop
    with open(hostname_file, "w", newline="") as host_csv, \
         open(network_file,  "w", newline="") as net_csv:

        # File 1: “hostnames” view
        host_fields = ["Input", "ResolvedIP", "CIDR", "Handle", "Organization", "OrgRef"]
        host_writer = csv.DictWriter(host_csv, fieldnames=host_fields)
        host_writer.writeheader()

        # File 2: “network” view (slimmer)
        net_fields = ["Input", "ResolvedIP", "Handle", "CIDR", "OrgRef"]
        net_writer = csv.DictWriter(net_csv, fieldnames=net_fields)
        net_writer.writeheader()

        for entry in entries:
            resolved_ip = resolve_host(entry)
            if resolved_ip:
                cidr, handle_short, org_name, org_display = lookup_ip(resolved_ip)
            else:
                resolved_ip, cidr, handle_short, org_name, org_display = "N/A", "N/A", "N/A", "N/A", "N/A"

            # Write to Hostname file (Handle before Organization, as requested)
            host_writer.writerow({
                "Input": entry,
                "ResolvedIP": resolved_ip,
                "CIDR": cidr,
                "Handle": handle_short,           # e.g., IPL / MSFT
                "Organization": org_name,         # e.g., Some Company Name
                "OrgRef": org_display             # e.g., Some Company Name (IPL-2)
            })

            # Write to Network file
            net_writer.writerow({
                "Input": entry,
                "ResolvedIP": resolved_ip,
                "Handle": handle_short,
                "CIDR": cidr,
                "OrgRef": org_display
            })

            print(f"[+] Processed {entry} -> {resolved_ip}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} input_list.txt hostnames.csv network.csv")
        sys.exit(1)

    main(sys.argv[1], sys.argv[2], sys.argv[3])
