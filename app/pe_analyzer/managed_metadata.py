"""Inspect CLR metadata without loading an assembly into the runtime."""

import hashlib
from importlib.metadata import version

from .analysis_models import StageResult
from .analysis_constants import MAX_METADATA_BYTES, MAX_METADATA_ITEMS, MAX_STRING_LENGTH


def table_rows(pe, name, notes):
    table = getattr(pe.net.mdtables, name, None)
    rows = getattr(table, "rows", [])
    if len(rows) > MAX_METADATA_ITEMS:
        notes.append(f"CLR {name} truncated at row limit")
    return rows[:MAX_METADATA_ITEMS]


def user_strings(heap, notes):
    if heap is None:
        return []
    results, offset = [], 1
    size = min(heap.sizeof(), MAX_METADATA_BYTES)
    while offset < size and len(results) < MAX_METADATA_ITEMS:
        item = heap.get(offset)
        if item is None:
            break
        if item.value:
            results.append(
                {"value": str(item.value)[:MAX_STRING_LENGTH], "heap_offset": hex(offset)}
            )
        offset += int(item.item_size) + item.item_size.raw_size
    if offset < heap.sizeof():
        notes.append("CLR user strings stopped at byte/item limit or malformed entry")
    return results


def managed_resources(pe, notes):
    results, remaining = [], MAX_METADATA_BYTES
    for resource in pe.net.resources[:MAX_METADATA_ITEMS]:
        content = resource.data
        record = {"name": str(resource.name)[:1024]}
        if isinstance(content, bytes):
            if len(content) > remaining:
                notes.append("Managed resource hashing stopped at byte budget")
                break
            remaining -= len(content)
            record.update(size=len(content), sha256=hashlib.sha256(content).hexdigest())
        else:
            record["kind"] = "structured resource set"
        results.append(record)
    if len(pe.net.resources) > MAX_METADATA_ITEMS:
        notes.append("Managed resource list truncated")
    return results


def inspect_dotnet(path: str) -> StageResult:
    import dnfile

    pe = dnfile.dnPE(path, clr_lazy_load=True)
    notes = []
    try:
        if pe.net is None:
            return StageResult("not_applicable", version("dnfile"))
        references = sorted(
            {str(row.Name) for row in table_rows(pe, "AssemblyRef", notes)}
        )
        pinvokes = [
            {"dll": str(row.ImportScope.row.Name), "function": str(row.ImportName)}
            for row in table_rows(pe, "ImplMap", notes)
            if row.ImportScope.row is not None
        ]
        details = {
            "runtime_version": pe.net.metadata.struct.Version.decode(
                "utf-8", "replace"
            ).rstrip("\0"),
            "assembly_references": references,
            "pinvokes": pinvokes,
            "user_strings": user_strings(pe.net.user_strings, notes),
            "resources": managed_resources(pe, notes),
        }
        notes.extend(str(item)[:1000] for item in pe.get_warnings()[:32])
        return StageResult(
            "partial" if notes else "completed", version("dnfile"), details, notes
        )
    finally:
        pe.close()
