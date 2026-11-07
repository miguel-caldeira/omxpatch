"""Módulo 1 — Descoberta por integração: Active Directory, Entra ID, VMware, Hyper-V, AWS, Azure, GCP, Kubernetes.

Cada fonte tem um *parser* puro (``parse_*``, testado com amostras) e uma função de recolha. O resultado é
sempre uma lista de dicionários compatível com ``inventory.upsert_asset``; ativos novos ficam como não geridos
(Shadow IT) até um agente ser instalado ou ficarem sob gestão sem agente.
"""
from __future__ import annotations

import logging
from datetime import datetime

import requests

from ..engine import ansible_runner, inventory
from ..extensions import db
from ..models import Connector, Tenant, utcnow
from ..security import check_outbound_url
from .http import request
from .store import ConnectorError, get_secrets

log = logging.getLogger("omxpatch.discovery")


def _fam(text: str) -> str:
    return inventory.guess_os_family(text)


def parse_ad(entries: list[dict]) -> list[dict]:
    out = []
    for e in entries:
        name = e.get("dNSHostName") or e.get("name") or ""
        if not name:
            continue
        os_name = str(e.get("operatingSystem") or "")
        out.append({"uid": str(name).lower(), "name": str(e.get("name") or name), "fqdn": str(e.get("dNSHostName") or ""),
                    "os_name": os_name, "os_version": str(e.get("operatingSystemVersion") or ""), "os_family": _fam(os_name),
                    "kind": "server" if "server" in os_name.lower() else "workstation",
                    "owner": str(e.get("managedBy") or ""), "department": str(e.get("department") or ""),
                    "managed": False})
    return out


def parse_entra(payload: dict) -> list[dict]:
    out = []
    for d in payload.get("value", []):
        name = d.get("displayName")
        if not name:
            continue
        osn = f"{d.get('operatingSystem', '')}"
        out.append({"uid": str(d.get("deviceId") or name).lower(), "name": name, "os_name": osn,
                    "os_version": d.get("operatingSystemVersion") or "", "os_family": _fam(osn), "kind": "workstation",
                    "primary_user": ((d.get("registeredOwners") or [{}])[0] or {}).get("userPrincipalName", ""),
                    "managed": False, "cloud_provider": "azure"})
    return out


def parse_vmware(vms: list[dict], identities: dict[str, dict] | None = None) -> list[dict]:
    identities = identities or {}
    out = []
    for vm in vms:
        ident = identities.get(vm.get("vm"), {})
        osn = ((ident.get("full_name") or {}).get("default_message")) or ident.get("name") or ""
        out.append({"uid": f"vmware:{vm.get('vm')}", "name": vm.get("name"), "ip": ident.get("ip_address", ""),
                    "fqdn": ident.get("host_name", ""), "kind": "server", "os_name": osn, "os_family": _fam(f"{osn} {ident.get('family', '')}"),
                    "hardware": {"cpu": vm.get("cpu_count"), "ram_gb": round((vm.get("memory_size_MiB") or 0) / 1024, 1),
                                 "power": vm.get("power_state")}, "managed": False, "cloud_provider": "vmware"})
    return out


def parse_hyperv(result: dict) -> list[dict]:
    out = []
    for vm in result.get("vms", []):
        nic = (vm.get("NetworkAdapters") or [{}])[0]
        ips = nic.get("IPAddresses") or []
        out.append({"uid": f"hyperv:{vm.get('VMId') or vm.get('Name')}", "name": vm.get("Name"),
                    "ip": next((i for i in ips if "." in i), ""), "mac": nic.get("MacAddress", ""), "kind": "server",
                    "hardware": {"cpu": vm.get("ProcessorCount"), "ram_gb": round((vm.get("MemoryAssigned") or 0) / 2**30, 1),
                                 "state": vm.get("State")}, "managed": False, "cloud_provider": "hyperv"})
    return out


def parse_aws(reservations: list[dict], region: str = "") -> list[dict]:
    out = []
    for res in reservations:
        for i in res.get("Instances", []):
            tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
            plat = "windows" if i.get("Platform") == "windows" else "linux"
            out.append({"uid": f"aws:{i['InstanceId']}", "name": tags.get("Name") or i["InstanceId"],
                        "ip": i.get("PrivateIpAddress", ""), "kind": "cloud_vm", "os_family": plat, "cloud_provider": "aws",
                        "cloud_id": i["InstanceId"], "owner": tags.get("Owner", ""), "tags": ",".join(f"{k}={v}" for k, v in tags.items())[:480],
                        "internet_exposed": "yes" if i.get("PublicIpAddress") else "no", "managed": False,
                        "hardware": {"type": i.get("InstanceType"), "region": region}})
    return out


def parse_azure(payload: dict) -> list[dict]:
    out = []
    for v in payload.get("value", []):
        props = v.get("properties", {})
        os_type = (props.get("storageProfile", {}).get("osDisk", {}).get("osType") or "").lower()
        out.append({"uid": f"azure:{v.get('id', v.get('name'))}".lower(), "name": v.get("name"), "kind": "cloud_vm",
                    "os_family": os_type if os_type in ("windows", "linux") else "", "cloud_provider": "azure",
                    "cloud_id": v.get("id", ""), "tags": ",".join(f"{k}={x}" for k, x in (v.get("tags") or {}).items())[:480],
                    "owner": (v.get("tags") or {}).get("Owner", ""), "hardware": {"size": props.get("hardwareProfile", {}).get("vmSize"),
                                                                                  "location": v.get("location")}, "managed": False})
    return out


def parse_gcp(payload: dict) -> list[dict]:
    out = []
    for zone in (payload.get("items") or {}).values():
        for i in zone.get("instances", []):
            nic = (i.get("networkInterfaces") or [{}])[0]
            lic = " ".join(l for d in i.get("disks", []) for l in d.get("licenses", []))
            out.append({"uid": f"gcp:{i.get('id')}", "name": i.get("name"), "ip": nic.get("networkIP", ""), "kind": "cloud_vm",
                        "os_family": "windows" if "windows" in lic else "linux", "cloud_provider": "gcp", "cloud_id": str(i.get("id")),
                        "internet_exposed": "yes" if any(ac.get("natIP") for ac in nic.get("accessConfigs", [])) else "no",
                        "owner": (i.get("labels") or {}).get("owner", ""), "managed": False,
                        "hardware": {"machine_type": str(i.get("machineType", "")).rsplit("/", 1)[-1]}})
    return out


def parse_k8s(nodes: dict, pods: dict, cluster: str = "k8s") -> tuple[list[dict], dict[str, list[dict]]]:
    """(ativos, software por uid): nós como ``k8s_node``; imagens dos pods por namespace como ``k8s_workload``."""
    assets: list[dict] = []
    software: dict[str, list[dict]] = {}
    for n in nodes.get("items", []):
        info = n.get("status", {}).get("nodeInfo", {})
        addr = {a.get("type"): a.get("address") for a in n.get("status", {}).get("addresses", [])}
        uid = f"k8s:{cluster}:node:{n['metadata']['name']}"
        assets.append({"uid": uid, "name": n["metadata"]["name"], "ip": addr.get("InternalIP", ""), "kind": "k8s_node",
                       "cluster": cluster, "os_name": info.get("osImage", ""), "os_version": info.get("kernelVersion", ""),
                       "os_family": _fam(info.get("osImage", "") or info.get("operatingSystem", "")),
                       "managed": False, "criticality": "high"})
        software[uid] = [{"name": "kubelet", "version": str(info.get("kubeletVersion", "")).lstrip("v"), "vendor": "kubernetes"},
                         {"name": "containerd" if "containerd" in info.get("containerRuntimeVersion", "") else "container-runtime",
                          "version": info.get("containerRuntimeVersion", "").split("://")[-1]}]
    by_ns: dict[str, dict[str, dict]] = {}
    for p in pods.get("items", []):
        ns = p["metadata"].get("namespace", "default")
        for c in p.get("spec", {}).get("containers", []):
            image = c.get("image", "")
            name, _, tag = image.rpartition(":") if ":" in image.split("/")[-1] else (image, "", "")
            by_ns.setdefault(ns, {})[image] = {"name": name.split("/")[-1] or image, "version": tag.lstrip("v") or "latest",
                                               "vendor": name.split("/")[0] if "/" in name else "", "source": "container"}
    for ns, imgs in by_ns.items():
        uid = f"k8s:{cluster}:ns:{ns}"
        assets.append({"uid": uid, "name": f"{cluster}/{ns}", "kind": "k8s_workload", "cluster": cluster, "os_family": "linux",
                       "managed": False})
        software[uid] = list(imgs.values())
    return assets, software


def collect(c: Connector, tenant: Tenant) -> tuple[list[dict], dict[str, list[dict]]]:
    o, s = c.opts, get_secrets(c)
    software: dict[str, list[dict]] = {}
    try:
        if c.kind == "entra":
            r = request(c, "GET", "/v1.0/devices", params={"$select": "displayName,deviceId,operatingSystem,operatingSystemVersion,isManaged", "$top": 999},
                        timeout=90)
            r.raise_for_status()
            return parse_entra(r.json()), software
        if c.kind == "azure":
            sub = o.get("subscription_id") or ""
            r = request(c, "GET", f"/subscriptions/{sub}/providers/Microsoft.Compute/virtualMachines", params={"api-version": "2023-09-01"}, timeout=90)
            r.raise_for_status()
            return parse_azure(r.json()), software
        if c.kind == "gcp":
            r = request(c, "GET", f"/compute/v1/projects/{o.get('project', '')}/aggregated/instances", timeout=90)
            r.raise_for_status()
            return parse_gcp(r.json()), software
        if c.kind == "k8s":
            rn = request(c, "GET", "/api/v1/nodes", timeout=60)
            rp = request(c, "GET", "/api/v1/pods", timeout=60)
            rn.raise_for_status(); rp.raise_for_status()
            return (*parse_k8s(rn.json(), rp.json(), o.get("cluster") or "k8s"),)
        if c.kind == "vmware":
            base = c.base_url.rstrip("/")
            check_outbound_url(base)
            ses = requests.post(base + "/api/session", auth=(c.username, s.get("password", "")), timeout=30, verify=bool(c.verify_tls))
            ses.raise_for_status()
            h = {"vmware-api-session-id": ses.json()}
            vms = requests.get(base + "/api/vcenter/vm", headers=h, timeout=90, verify=bool(c.verify_tls))
            vms.raise_for_status()
            idents = {}
            for vm in vms.json()[:500]:
                ri = requests.get(f"{base}/api/vcenter/vm/{vm['vm']}/guest/identity", headers=h, timeout=20, verify=bool(c.verify_tls))
                if ri.status_code == 200:
                    idents[vm["vm"]] = ri.json()
            return parse_vmware(vms.json(), idents), software
        if c.kind == "aws":
            try:
                import boto3  # type: ignore
            except ImportError as exc:
                raise ConnectorError("AWS: instale boto3 (pip install 'omxpatch[cloud]')") from exc
            out = []
            for region in [r.strip() for r in (o.get("regions") or "").split(",") if r.strip()]:
                cli = boto3.client("ec2", region_name=region, aws_access_key_id=c.username, aws_secret_access_key=s.get("secret_key"))
                out += parse_aws(cli.describe_instances().get("Reservations", []), region)
            return out, software
        if c.kind == "ad":
            try:
                from ldap3 import ALL, Connection, Server  # type: ignore
            except ImportError as exc:
                raise ConnectorError("Active Directory: instale ldap3 (pip install 'omxpatch[ad]')") from exc
            conn = Connection(Server(c.base_url, get_info=ALL, use_ssl=c.base_url.startswith("ldaps")), user=c.username,
                              password=s.get("password"), auto_bind=True)
            conn.search(o.get("base_dn", ""), "(objectClass=computer)",
                        attributes=["name", "dNSHostName", "operatingSystem", "operatingSystemVersion", "managedBy", "department"], paged_size=500)
            rows = []
            for e in conn.entries:
                d = e.entry_attributes_as_dict
                rows.append({k: (v[0] if isinstance(v, list) and v else v) for k, v in d.items()})
            return parse_ad(rows), software
        if c.kind == "hyperv":
            hosts = [h.strip() for h in (o.get("hosts") or "").split(",") if h.strip()]
            if not hosts:
                raise ConnectorError("Hyper-V: indique os anfitriões em options.hosts")
            inv = {"all": {"hosts": {h.replace(".", "_"): {"ansible_host": h, "ansible_connection": "winrm"} for h in hosts}}}
            res = ansible_runner.run_playbook("discover_hyperv.yml", inv, {})
            if not res["result"]:
                raise ConnectorError("Hyper-V: o playbook não devolveu resultado\n" + res["output"][-500:])
            return parse_hyperv(res["result"]), software
    except requests.RequestException as exc:
        raise ConnectorError(str(exc)) from exc
    raise ConnectorError(f"Tipo de descoberta não suportado: {c.kind}")


def run(c: Connector, tenant: Tenant) -> dict:
    items, software = collect(c, tenant)
    new = 0
    for it in items:
        if not it.get("name") and not it.get("uid"):
            continue
        asset, created = inventory.upsert_asset(tenant, it, source=c.kind if c.kind in ("ad", "entra", "vmware", "hyperv", "aws", "azure", "gcp") else "agentless")
        new += created
        if not asset.managed:
            asset.shadow_it = True
        if it["uid"] in software:
            inventory.set_software(asset, software[it["uid"]], source="discovery")
    c.last_sync_at, c.last_ok, c.last_detail = utcnow(), True, f"{len(items)} ativos ({new} novos)"
    db.session.commit()
    return {"found": len(items), "new": new}


__all__ = ["datetime"]
