import json
import logging
import sys
import tempfile
from pathlib import Path

logging.disable(logging.CRITICAL)

try:
    from octodns.manager import Manager
    from octodns.zone import Zone

    request = json.load(sys.stdin)
    target = dict(request["provider"])
    target.update(
        strict_supports=True,
        apply_disabled=False,
        update_pcent_threshold=1.0,
        delete_pcent_threshold=1.0,
    )
    if "domains" in request:
        with tempfile.TemporaryDirectory(prefix="edge-dns-") as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"providers": {"target": target}, "zones": {}}))
            provider = Manager(str(path)).providers["target"]
            listed = getattr(provider, "list_zones", None)
            zones = [zone.rstrip(".").lower() for zone in listed()] if listed else None
            resolver = None
            if zones is None:
                import dns.resolver

                resolver = dns.resolver.Resolver()
                if hasattr(provider, "_auth_params"):
                    resolver.nameservers = [provider.host]
                    resolver.port = provider.port
                    auth = provider._auth_params()
                    if "keyalgorithm" in auth:
                        auth["algorithm"] = auth.pop("keyalgorithm")
                    if auth:
                        resolver.use_tsig(keyname=provider.key_name, **auth)
            result = {}
            for domain in request["domains"]:
                if zones is None:
                    result[domain] = dns.resolver.zone_for_name(domain.removeprefix("*."), resolver=resolver, tcp=True, lifetime=15).to_text().rstrip(".")
                else:
                    result[domain] = max((zone for zone in zones if domain == zone or domain.endswith("." + zone)), key=len)
            print(json.dumps(result))
    else:
        zone = request["zone"].rstrip(".") + "."
        with tempfile.TemporaryDirectory(prefix="edge-dns-") as directory:
            root = Path(directory)
            (root / (zone[:-1] + ".yaml")).write_text(json.dumps(request["records"]))
            config = {
                "providers": {
                    "source": {
                        "class": "octodns.provider.yaml.YamlProvider",
                        "directory": directory,
                        "enforce_order": False,
                    },
                    "target": target,
                },
                "processors": {
                    "ownership": {
                        "class": "octodns.processor.ownership.OwnershipProcessor",
                        "txt_name": "_haproxy-edge",
                        "txt_value": "haproxy-edge-operator:" + request["owner"],
                        "allow_takeover": False,
                    }
                },
                "zones": {
                    zone: {
                        "sources": ["source"],
                        "targets": ["target"],
                        "processors": ["ownership"],
                    }
                },
            }
            config_path = root / "config.json"
            config_path.write_text(json.dumps(config))
            manager = Manager(str(config_path))
            required = {"TXT"}
            for records in request["records"].values():
                for record in records if isinstance(records, list) else [records]:
                    required.add(record["type"])
            if not required.issubset(manager.providers["target"].SUPPORTS):
                raise ValueError("provider does not support the requested record types")
            previous = request.get("previous", {})
            managed = set()
            for records in (request["records"], previous):
                for name, entries in records.items():
                    for entry in entries if isinstance(entries, list) else [entries]:
                        managed.add((name, entry["type"]))
            existing = Zone(zone, [])
            manager.providers["target"].populate(existing, target=True)
            ttl = max((record.ttl for record in existing.records if (record.name, record._type) in managed), default=0)
            manager.sync(dry_run=False)
            current = Zone(zone, [])
            manager.providers["target"].populate(current, target=True)
            ttl = max(ttl, max((record.ttl for record in current.records if (record.name, record._type) in managed), default=0))
            print(ttl)
except Exception as error:
    print(f"octoDNS: {type(error).__name__}", file=sys.stderr)
    sys.exit(1)
