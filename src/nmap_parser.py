#!/usr/bin/env python3
"""
nmap_parser.py

- run_nmap(target, nmap_arguments="-sV -O -p-") -> returns path to XML file
- parse_nmap_xml(xml_file) -> returns a feature dict including:
    - service_cpes (list and top-level joined string)
    - services (list of dicts with product/version/cpe/port)
    - port_xxx_open flags & total_open_ports
    - counts for vuln categories if NSE scripts found them (best-effort)
"""

import os
import subprocess
import xml.etree.ElementTree as ET
import re
from typing import Dict, Any, List, Optional

ROOT = os.path.dirname(os.path.abspath(__file__))

def sanitize_target_for_filename(target: str) -> str:
    return re.sub(r'[^A-Za-z0-9_.-]', '_', target)

def run_nmap(target: str, nmap_arguments: str = "-sV -O -p-") -> str:
    """
    Run nmap with provided arguments and output XML to data/<target>_nmap.xml
    Returns path to XML file (raises on error).
    """
    os.makedirs(os.path.join(ROOT, "..", "data"), exist_ok=True)
    safe = sanitize_target_for_filename(target)
    xml_out = os.path.join(ROOT, "..", "data", f"{safe}_nmap.xml")
    # Ensure -oX present
    cmd = f"nmap {nmap_arguments} {target} -oX {xml_out}"
    print(f"[*] Running command: {cmd}")
    # Use shell=False safer split if needed, but keep simple to respect user args
    subprocess.run(cmd, shell=True, check=True)
    return xml_out

def _safe_text(node: Optional[ET.Element]) -> str:
    return node.text.strip() if node is not None and node.text else ""

def _parse_service_elem(svc_elem: ET.Element) -> Dict[str, Any]:
    """
    Parse a <service> element inside <port>.
    Returns dict with product, version, name, cpes (list), extra info.
    """
    out = {"product": None, "version": None, "name": None, "cpe": [], "extra": {}, "port": None, "protocol": None}
    try:
        out["name"] = svc_elem.get("name")
        out["product"] = svc_elem.get("product")
        out["version"] = svc_elem.get("version")
        out["extrainfo"] = svc_elem.get("extrainfo")
        # cpe tags may appear as child <cpe>
        for cpe in svc_elem.findall("cpe"):
            txt = _safe_text(cpe)
            if txt:
                out["cpe"].append(txt)
        # Some nmap outputs place cpe under 'service' attributes or script outputs; handle later
    except Exception:
        pass
    return out

def _extract_script_vulns(port_elem: ET.Element) -> Dict[str,int]:
    """
    Look through <script> child elements (NSE scripts) and extract simple vulnerability indicators.
    Returns small dict of counts/flags.
    """
    features = {}
    for script in port_elem.findall("script"):
        scr_id = script.get("id", "").lower()
        output = _safe_text(script)
        # common patterns
        if "cve" in output.lower():
            # crude: count number of 'CVE-' occurrences
            features["nse_cve_count"] = features.get("nse_cve_count", 0) + len(re.findall(r"CVE-\d{4}-\d+", output, flags=re.I))
        if "backdoor" in scr_id or "backdoor" in output.lower():
            features["vuln_backdoor_detected"] = 1
        if "rce" in scr_id or "remote code" in output.lower():
            features["vuln_rce_detected"] = 1
        if "sql" in scr_id or "sql" in output.lower():
            features["vuln_sqli_detected"] = 1
    return features

def parse_nmap_xml(xml_file: str) -> Dict[str, Any]:
    """
    Parse nmap XML produced by -oX and extract feature vector and per-service CPEs.
    """
    features: Dict[str, Any] = {}
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"[!] Failed to parse Nmap XML '{xml_file}': {e}")
        return {}

    # Default counters
    total_open_ports = 0
    port_flags: Dict[str,int] = {}
    services_list: List[Dict[str,Any]] = []
    all_cpes: List[str] = []
    aggregate_nse = {}

    # Nmap XML layout: <nmaprun><host><ports><port>...
    for host in root.findall("host"):
        # skip hosts that are not 'up'
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            total_open_ports += 1
            portid = port.get("portid")
            protocol = port.get("protocol")
            svc = port.find("service")
            svc_info = {}
            if svc is not None:
                svc_info = _parse_service_elem(svc)
            svc_info["port"] = portid
            svc_info["protocol"] = protocol

            # Also look for script outputs attached to the port
            script_feats = _extract_script_vulns(port)
            # merge script feats into aggregate_nse
            for k,v in script_feats.items():
                if isinstance(v, int):
                    aggregate_nse[k] = aggregate_nse.get(k, 0) + v
                else:
                    aggregate_nse[k] = v

            # Some services include CPEs in <service><cpe> children (handled above)
            # Also some versions embed cpe in <service> attributes like 'cpe:/a:...'
            # collect CPEs from svc_info.cpe
            for c in svc_info.get("cpe", []) or []:
                if c and c.strip() not in all_cpes:
                    all_cpes.append(c.strip())

            # look for script tags under service (rare) or under port - handled above already
            services_list.append(svc_info)

            # set port flags like port_80_open
            try:
                num = int(portid)
                flag_key = f"port_{num}_open"
                port_flags[flag_key] = 1
            except Exception:
                pass

    # Some Nmap outputs produce <os> and <cpe> at host level; try to extract OS/service CPEs
    # Host-level CPEs (under os > osmatch > osclass > cpe)
    host_cpes = []
    for os_elem in root.findall(".//os"):
        for osmatch in os_elem.findall("osmatch"):
            for osclass in osmatch.findall("osclass"):
                for cpe in osclass.findall("cpe"):
                    txt = _safe_text(cpe)
                    if txt and txt not in host_cpes:
                        host_cpes.append(txt)
    for c in host_cpes:
        if c not in all_cpes:
            all_cpes.append(c)

    # Build features dict
    features.update(port_flags)
    features["total_open_ports"] = total_open_ports
    # common service indicators (guess from services list)
    # set a couple of convenience booleans if present
    for s in services_list:
        name = (s.get("product") or s.get("name") or "").lower() if s else ""
        if "apache" in name:
            features["service_contains_apache"] = 1
        if "openssh" in name or "ssh" in name:
            features["service_contains_openssh"] = 1
        if "vsftpd" in name or "ftp" in name:
            features["port_21_open"] = features.get("port_21_open", 0) or (1 if any(k=="port_21_open" for k in port_flags) else 0)
        # detect version strings that look old (simple heuristic)
        try:
            ver = s.get("version")
            if ver and re.search(r"^\d+\.\d+(\.\d+)?", ver):
                # crude rule: major < 3 considered old for many packages (tweak later)
                major = int(ver.split(".")[0]) if ver.split(".")[0].isdigit() else None
                if major is not None and major < 3:
                    features["version_contains_old"] = 1
        except Exception:
            pass

    # Merge NSE derived features
    for k,v in aggregate_nse.items():
        features[k] = v

    # store cpes and services in structured form
    features["service_cpes"] = all_cpes
    features["service_cpe"] = " ".join(all_cpes) if all_cpes else ""
    # include services list for per-service lookup (product/version/cpe/port)
    features["services"] = services_list

    # Try to set counts for common vuln severity placeholders if NSE indicated CVEs
    features["nse_cve_count"] = aggregate_nse.get("nse_cve_count", 0)
    features["vuln_backdoor_detected"] = aggregate_nse.get("vuln_backdoor_detected", 0)
    features["vuln_rce_detected"] = aggregate_nse.get("vuln_rce_detected", 0)
    features["vuln_sqli_detected"] = aggregate_nse.get("vuln_sqli_detected", 0)

    # some default safe fields to keep compatibility with GUI feature expectations
    features.setdefault("port_21_open", 0)
    features.setdefault("port_22_open", 0)
    features.setdefault("port_23_open", 0)
    features.setdefault("port_80_open", 0)
    features.setdefault("port_443_open", 0)
    features.setdefault("port_445_open", 0)
    features.setdefault("total_open_ports", total_open_ports)
    # return full features dict
    return features

# If run directly, parse a sample path
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python nmap_parser.py <path_to_nmap_xml>")
        sys.exit(1)
    xml = sys.argv[1]
    out = parse_nmap_xml(xml)
    print("Parsed features keys:", list(out.keys()))
    print("service_cpes:", out.get("service_cpes"))
    print("services (top 5):", out.get("services")[:5] if out.get("services") else None)
