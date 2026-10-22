#!/usr/bin/env python3
"""Parity check: the TypeScript adapter (OLD) and the fork (NEW) must answer every read route
identically for the same vault. Prints item ids, routes and match/MISMATCH only, never a value.

    python3 -I parity.py http://127.0.0.1:8085 http://127.0.0.1:8098
"""

import json
import sys
import time
import urllib.error
import urllib.request

OLD, NEW = sys.argv[1], sys.argv[2]

SECRETS_BY_TYPE = {
    "login": ["password", "totp"],
    "card": ["number", "code"],
    "identity": ["ssn", "passportNumber", "licenseNumber"],
    "sshKey": ["privateKey"],
    "bankAccount": ["accountNumber", "pin", "iban"],
    "driversLicense": ["licenseNumber"],
    "passport": ["passportNumber", "nationalIdentificationNumber"],
    "note": [],
}
ROUTES_BY_TYPE = {"login": ["login", "passkey"], "card": ["card"]}

failures = 0
checks = 0


def call(base, method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as res:
            return res.status, json.loads(res.read() or b"null")
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read() or b"null")


def diff_paths(a, b, path=""):
    """Key paths where a and b differ (no values)."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for key in sorted(set(a) | set(b)):
            out += diff_paths(a.get(key, "<absent>"), b.get(key, "<absent>"), f"{path}.{key}")
        return out
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out += diff_paths(x, y, f"{path}[{i}]")
        return out
    return [] if a == b else [path or "<root>"]


def compare(label, method, path, body=None, error_message=True):
    global failures, checks
    checks += 1
    old = call(OLD, method, path, body)
    new = call(NEW, method, path, body)
    if not error_message and old[0] >= 400 and new[0] >= 400:
        same = old[0] == new[0] and old[1]["error"]["type"] == new[1]["error"]["type"]
        diffs = [] if same else ["<error>"]
    else:
        diffs = ([] if old[0] == new[0] else ["<status>"]) + diff_paths(old[1], new[1])
    if diffs:
        failures += 1
        print(f"MISMATCH {label}: status {old[0]}/{new[0]} at {', '.join(diffs[:8])}")
    return old, new


def main():
    _, old_items = call(OLD, "GET", "/v1/items")
    _, new_items = call(NEW, "GET", "/v1/items")
    old_items, new_items = old_items["items"], new_items["items"]
    print(f"items: old {len(old_items)}, new {len(new_items)}")
    if [i["id"] for i in old_items] != [i["id"] for i in new_items]:
        print("note: list order differs (compared by id below)")
    compare("GET /v1/items (as sets)", "GET", "/v1/items")  # also reported per item below
    old_by_id = {i["id"]: i for i in old_items}
    new_by_id = {i["id"]: i for i in new_items}
    for missing in set(old_by_id) ^ set(new_by_id):
        print(f"MISMATCH item {missing} only on {'old' if missing in old_by_id else 'new'}")

    compare("GET /v1/folders", "GET", "/v1/folders")
    for query in ["?type=login", "?type=note", "?q=a", "?q=com", "?uri=https"]:
        compare(f"GET /v1/items{query}", "GET", f"/v1/items{query}")

    for item in old_items:
        item_id, item_type = item["id"], item["type"]
        compare(f"GET item {item_id}", "GET", f"/v1/items/{item_id}")
        for field in SECRETS_BY_TYPE.get(item_type, []) + ["notes"]:
            compare(f"reveal {field} {item_id}", "POST", f"/v1/items/{item_id}/reveal", {"field": field}, error_message=False)
        for field in item.get("fields", []):
            if field["type"] == "hidden":
                compare(f"reveal custom {item_id}", "POST", f"/v1/items/{item_id}/reveal", {"field": "custom", "name": field["name"]})
        for route in ROUTES_BY_TYPE.get(item_type, []):
            compare(f"{route} {item_id}", "POST", f"/v1/items/{item_id}/{route}", {}, error_message=False)
        if item_type == "login" and item["login"]["hasTotp"]:
            for _ in range(3):
                old = call(OLD, "POST", f"/v1/items/{item_id}/totp", {})
                new = call(NEW, "POST", f"/v1/items/{item_id}/totp", {})
                if old[1].get("remaining", 0) > 2 and old[1].get("remaining") == new[1].get("remaining"):
                    break
                time.sleep(3)
            global checks, failures
            checks += 1
            if old[0] != new[0] or old[1].get("code") != new[1].get("code") or old[1].get("period") != new[1].get("period"):
                failures += 1
                print(f"MISMATCH totp {item_id}")
        if item_type == "note" and any(f["name"] == "Secret" and f["type"] == "hidden" for f in item.get("fields", [])):
            name = urllib.request.quote(item["name"], safe="")
            compare(f"secret reveal {item_id}", "POST", f"/v1/secrets/{name}/reveal", {})

    compare("error: unknown item", "GET", "/v1/items/00000000-0000-4000-8000-000000000000")
    compare("error: bad uuid", "GET", "/v1/items/nope", error_message=False)
    print(f"{checks} checks, {failures} mismatches")
    sys.exit(1 if failures else 0)


main()
