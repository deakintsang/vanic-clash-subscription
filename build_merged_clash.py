#!/usr/bin/env python3
"""
build_merged_clash.py — 合并 Vanic24/VPN 的 6 个 Clash 文件为单一订阅
输出: vanic_merged.yaml (Clash Meta / FlClash 可导入)
"""
from __future__ import annotations

import datetime
import json
import pathlib
import urllib.request

import yaml

REPO = "https://raw.githubusercontent.com/Vanic24/VPN/main"
FILES = ["8EB", "9PB", "Lifetime", "Sub3", "Filter", "MIX"]
OUT = pathlib.Path(__file__).parent / "vanic_merged.yaml"

MAIN_GROUP = "🌍 全线路选择"
AUTO_GROUP = "⚡️ 全自动测速"
GROUP_PREFIX = "📦 "
TEST_URL = "https://www.gstatic.com/generate_204"

RENAME = {"insecure": "skip-cert-verify", "tls-enabled": "tls"}
TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}


def as_bool(value, *, field, proxy_name):
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in TRUE_VALUES:
            return True
        if lowered in FALSE_VALUES:
            return False
    raise ValueError(
        f"proxy {proxy_name!r}: {field} must be a boolean-compatible value, "
        f"got {type(value).__name__}: {value!r}"
    )


def fetch(name):
    url = f"{REPO}/{name}"
    with urllib.request.urlopen(url, timeout=30) as response:
        config = yaml.safe_load(response.read().decode("utf-8"))
    if not isinstance(config, dict):
        raise ValueError(f"Upstream file {name} is not a YAML mapping")
    return config


def normalize(proxy):
    if not isinstance(proxy, dict):
        raise ValueError(f"Proxy entry must be a mapping, got {type(proxy).__name__}")

    out = dict(proxy)
    proxy_name = str(out.get("name", "<unnamed>"))

    if out.get("type") == "socks":
        out["type"] = "socks5"

    for old, new in RENAME.items():
        if old in out:
            out.setdefault(new, out[old])
            del out[old]

    # Normalize common Clash-family aliases without overwriting canonical fields.
    for old, new in (("sni", "servername"), ("fp", "client-fingerprint"),
                     ("allowInsecure", "skip-cert-verify")):
        if old in out:
            out.setdefault(new, out[old])
            del out[old]

    # Some upstream nodes use tls: {enabled: true, server_name: ...};
    # FlClash/Clash Meta proxy entries require tls itself to be a boolean.
    tls = out.get("tls")
    if isinstance(tls, dict):
        tls_options = tls
        out["tls"] = as_bool(
            tls_options.get("enabled", True), field="tls.enabled", proxy_name=proxy_name
        )
        server_name = tls_options.get("server_name") or tls_options.get("servername")
        if server_name and not out.get("servername"):
            out["servername"] = server_name
        if "insecure" in tls_options and "skip-cert-verify" not in out:
            out["skip-cert-verify"] = as_bool(
                tls_options["insecure"], field="tls.insecure", proxy_name=proxy_name
            )
    elif "tls" in out:
        out["tls"] = as_bool(out["tls"], field="tls", proxy_name=proxy_name)

    for field in ("skip-cert-verify", "udp"):
        if field in out:
            if out[field] is None:
                del out[field]
            else:
                out[field] = as_bool(out[field], field=field, proxy_name=proxy_name)

    return out


def stable_proxy_key(proxy):
    # Deduplicate only identical connection settings; server/port/type alone can
    # incorrectly merge distinct users, passwords, transports, or TLS settings.
    identity = dict(proxy)
    identity.pop("name", None)
    return json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def normalize_rules(rules, source_config):
    if not isinstance(rules, list):
        raise ValueError("The first upstream config must contain a rules list")

    group_map = {}
    for group in source_config.get("proxy-groups", []) or []:
        if not isinstance(group, dict) or not group.get("name"):
            continue
        # The source groups are not copied; route their rules to our equivalent groups.
        group_map[group["name"]] = (
            MAIN_GROUP if group.get("type") == "select" else AUTO_GROUP
        )

    normalized = []
    for rule in rules:
        if not isinstance(rule, str):
            normalized.append(rule)
            continue
        parts = rule.split(",")
        # IP rules may end in the optional no-resolve flag.
        target_index = -2 if parts and parts[-1].strip().lower() == "no-resolve" else -1
        if len(parts) >= abs(target_index) and parts[target_index].strip() in group_map:
            parts[target_index] = group_map[parts[target_index].strip()]
        normalized.append(",".join(parts))
    return normalized


def validate_config(config):
    proxies = config.get("proxies") or []
    groups = config.get("proxy-groups") or []
    proxy_names = [p.get("name") for p in proxies]
    group_names = [g.get("name") for g in groups]

    if len(proxy_names) != len(set(proxy_names)):
        raise ValueError("Generated proxy names are not unique")
    if len(group_names) != len(set(group_names)):
        raise ValueError("Generated proxy-group names are not unique")

    valid_refs = set(proxy_names) | set(group_names) | {"DIRECT", "REJECT", "PASS", "COMPATIBLE"}
    for group in groups:
        for ref in group.get("proxies", []):
            if ref not in valid_refs:
                raise ValueError(f"proxy-group {group['name']!r} references missing proxy/group {ref!r}")

    for rule in config.get("rules", []):
        if not isinstance(rule, str):
            continue
        parts = [part.strip() for part in rule.split(",")]
        if len(parts) < 2:
            continue
        target = parts[-2] if parts[-1].lower() == "no-resolve" else parts[-1]
        if target not in valid_refs:
            raise ValueError(f"rule references missing proxy/group {target!r}: {rule}")

    for proxy in proxies:
        for field in ("tls", "skip-cert-verify", "udp"):
            if field in proxy and not isinstance(proxy[field], bool):
                raise ValueError(
                    f"proxy {proxy.get('name')!r}: {field} must be bool, "
                    f"got {type(proxy[field]).__name__}"
                )


def main():
    raw = {}
    source_configs = {}
    for filename in FILES:
        print(f"[fetch] {filename}")
        source_configs[filename] = fetch(filename)
        raw[filename] = [normalize(proxy) for proxy in source_configs[filename].get("proxies", [])]
        if not raw[filename]:
            print(f"[warn] {filename} has no proxies")

    # Keep one canonical proxy per identical configuration, while remembering
    # all source groups it belongs to. This also handles source names like
    # "| Mix" versus the file name "MIX" without case-sensitive suffix checks.
    unique_by_key = {}
    deduped = []
    source_names = {filename: [] for filename in FILES}
    used_names = set()
    n_before = sum(len(raw[filename]) for filename in FILES)

    for filename in FILES:
        for proxy in raw[filename]:
            key = stable_proxy_key(proxy)
            canonical = unique_by_key.get(key)
            if canonical is None:
                canonical = dict(proxy)
                base_name = str(canonical.get("name") or f"{filename} node")
                unique_name = base_name
                suffix = 2
                while unique_name in used_names:
                    unique_name = f"{base_name} [{suffix}]"
                    suffix += 1
                canonical["name"] = unique_name
                used_names.add(unique_name)
                unique_by_key[key] = canonical
                deduped.append(canonical)
            source_names[filename].append(canonical["name"])

    print(f"[dedup] {n_before} -> {len(deduped)} ({n_before - len(deduped)} suppressed)")
    if not deduped:
        raise ValueError("No proxies were fetched; refusing to write an empty config")

    available_groups = []
    groups = [
        {
            "name": AUTO_GROUP,
            "type": "url-test",
            "proxies": [proxy["name"] for proxy in deduped],
            "url": TEST_URL,
            "interval": 300,
            "tolerance": 50,
        }
    ]

    for filename in FILES:
        # Remove duplicate references while preserving order.
        names = list(dict.fromkeys(source_names[filename]))
        if not names:
            continue
        group_name = f"{GROUP_PREFIX}{filename}"
        available_groups.append(group_name)
        groups.append({
            "name": group_name,
            "type": "url-test",
            "proxies": names,
            "url": TEST_URL,
            "interval": 300,
            "tolerance": 50,
        })

    groups.insert(0, {
        "name": MAIN_GROUP,
        "type": "select",
        "proxies": [AUTO_GROUP] + available_groups,
    })

    first_config = source_configs[FILES[0]]
    rules = normalize_rules(first_config.get("rules", []), first_config)
    output = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "ipv6": True,
        "external-controller": "127.0.0.1:9090",
        "proxies": deduped,
        "proxy-groups": groups,
        "rules": rules,
    }
    validate_config(output)

    header = (
        "# 合并 Vanic24/VPN 订阅（含 MIX）\n"
        f"# 源: {', '.join(FILES)}\n"
        f"# 生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"# 节点: {len(deduped)} (去重前 {n_before})  策略组: {len(groups)}\n"
    )
    content = header + yaml.safe_dump(
        output, allow_unicode=True, sort_keys=False, default_flow_style=False
    )
    OUT.write_text(content, encoding="utf-8")
    print(f"[write] {OUT} ({len(content)} bytes)")

    types = {}
    for proxy in deduped:
        protocol = proxy.get("type", "?")
        types[protocol] = types.get(protocol, 0) + 1
    print("types:", types)


if __name__ == "__main__":
    main()
