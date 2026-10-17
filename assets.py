"""Explicit public IP scope and conservative inventory metrics."""
import ipaddress
import re
from collections import Counter, defaultdict


def public_ips(text, limit=64):
    """Only global IPv4, entered explicitly; CIDRs cannot silently expand scans."""
    values = set()
    for token in re.split(r"[\s,;]+", text.strip()):
        if not token:
            continue
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError as exc:
            raise ValueError("IP o CIDR inválido: " + token) from exc
        if network.version != 4 or network.num_addresses > limit:
            raise ValueError("Solo IPv4 y bloques de hasta " + str(limit) + " direcciones: " + token)
        for addr in network.hosts():
            if not addr.is_global:
                raise ValueError("El alcance incluye una IP que no es pública: " + str(addr))
            values.add(str(addr))
        if len(values) > limit:
            raise ValueError("Máximo " + str(limit) + " IPs públicas por ejecución.")
    return sorted(values, key=lambda s: int(ipaddress.IPv4Address(s)))


def dns_ip_map(output, candidates):
    mapping = defaultdict(set)
    for line in output.splitlines():
        parts = line.split()
        if not parts or parts[0].lower().rstrip(".") not in candidates:
            continue
        host = parts[0].lower().rstrip(".")
        for token in parts[1:]:
            for match in re.findall(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])", token):
                try:
                    address = ipaddress.ip_address(match)
                    if address.version == 4 and address.is_global:
                        mapping[host].add(str(address))
                except ValueError:
                    pass
    return {k: sorted(v) for k, v in sorted(mapping.items())}


def dashboard_data(data):
    mapping = data.get("dns_ips", {})
    explicit = set(data.get("explicit_ips", []))
    dns_ips = {ip for ips in mapping.values() for ip in ips}
    scanned = set(data.get("scanned", []))
    ports = data.get("ports", [])
    count_ports = Counter(str(p.get("port", "")) + "/" + p.get("protocol", "tcp") for p in ports)
    service_rows = Counter((str(p.get("port", "")) + "/" + p.get("protocol", "tcp"),
                            p.get("service", "desconocido")) for p in ports)
    assets = []
    candidates={r['ip']:r for r in data.get('ip_candidates',[])}
    for ip in sorted(dns_ips | explicit | set(candidates)):
        names = [host for host, ips in mapping.items() if ip in ips]
        assets.append({"IP pública": ip, "FQDN observados": ", ".join(names) or "Sin FQDN en el inventario",
                       "Origen": "Alcance IP declarado" if ip in explicit else ", ".join(candidates[ip]["sources"]) if ip in candidates else "Resolución DNS",
                       "Titularidad": "Declarada por el operador" if ip in explicit else "Por validar; posible CDN o tercero",
                       "Estado de atribución":candidates.get(ip,{}).get("status","Relación DNS"),
                       "Sondeo directo": "Sí" if ip in scanned else "No"})
    return {"candidate_names": len(data.get("subdomains", [])),
            "resolved_names": len(data.get("resolved", [])),
            "dns_ips": len(dns_ips), "declared_ips": len(explicit),
            "ip_union": len(dns_ips | explicit), "ip_without_fqdn": len(explicit - dns_ips),
            "candidate_ips":len(candidates),"candidate_ips_without_fqdn":sum(r.get("no_fqdn_observed",False) for r in candidates.values()),
            "scanned_targets": len(scanned), "open_port_observations": len(ports),
            "unique_port_types": len(count_ports), "assets": assets,
            "ports_by_type": [{"Puerto": k, "Observaciones": v} for k, v in count_ports.most_common()],
            "services": [{"Puerto": p, "Servicio": s, "Observaciones": n}
                         for (p, s), n in service_rows.most_common()],
            "tool_status": Counter(x.get("status", "Sin estado") for x in data.get("results", []))}
