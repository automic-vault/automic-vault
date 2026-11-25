"""Check the inventory that the release job will attest."""

import json
from collections import defaultdict
from pathlib import Path


doc = json.loads(Path("target/release.spdx.json").read_text())
packages = {p["SPDXID"]: p for p in doc["packages"]}
files = {f["SPDXID"] for f in doc["files"]}
elements = set(packages) | files | {doc["SPDXID"]}
assert len(elements) == len(doc["packages"]) + len(doc["files"]) + 1, "Duplicate SPDX ID"

dependencies = defaultdict(set)
build_only = set()
roots = []
for edge in doc["relationships"]:
    source, target = edge["spdxElementId"], edge["relatedSpdxElement"]
    assert source in elements and target in elements, edge
    if edge["relationshipType"] == "DESCRIBES":
        assert source == doc["SPDXID"]
        roots.append(target)
    elif edge["relationshipType"] in {"DEPENDS_ON", "CONTAINS"}:
        dependencies[source].add(target)
    elif edge["relationshipType"] == "BUILD_DEPENDENCY_OF":
        build_only.add(source)

root, = roots
assert packages[root]["name"] == "av"
reachable = set()
pending = [root]
while pending:
    current = pending.pop()
    if current not in reachable:
        reachable.add(current)
        pending.extend(dependencies[current])

names = {packages[i]["name"] for i in reachable if i in packages}
assert "serde" in names and "appupdater" in names, names
pins = json.loads(Path("src/menu-helper/Package.resolved").read_text())["pins"]
assert {p["identity"] for p in pins} <= names
assert not any(p["name"].startswith("windows-") for p in packages.values())
syn = {i for i, p in packages.items() if p["name"] == "syn"}
assert syn and syn <= build_only and syn.isdisjoint(reachable)
for path in ("target/sbom-rust.spdx.json", "target/sbom-swift.spdx.json"):
    assert doc["documentNamespace"] != json.loads(Path(path).read_text())["documentNamespace"]
