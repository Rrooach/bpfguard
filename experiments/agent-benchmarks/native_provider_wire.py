"""Lossless local-tool wire adaptation, not an Agent loop or tool executor.

DeepSeek Responses accepts flat function names and custom apply_patch only.
Codex Code Mode declares namespaces and arbitrary custom grammar tools. Expose
each as a function on the provider wire, then restore the original native tool
kind/name/namespace/input before Codex sees it. IDs and usage are retained.
Both byte streams must be stored separately; they are NOT byte-identical.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re

VERSION = "CODEX_NATIVE_DEEPSEEK_LOCAL_TOOL_WIRE_V2"


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def prepare_request(native):
    data = deepcopy(native)
    mapping, tools = {}, []
    def visit(entries, namespace=()):
        for item in entries:
            kind, name = item["type"], item["name"]
            if kind == "namespace":
                visit(item["tools"], (*namespace, name))
                continue
            identity = {"name": name, "namespace": ".".join(namespace), "type": kind}
            # Keep meaningful names: opaque hashes obscured Codex instructions
            # referring to exec/apply_patch and caused real tool-choice errors.
            alias = re.sub(r'[^A-Za-z0-9_-]', '_', '__'.join((*namespace, name)))
            if not alias or len(alias) > 100:
                alias = alias[:80] + '_' + hashlib.sha256(canonical(identity)).hexdigest()[:16]
            if alias in mapping and mapping[alias] != identity:
                alias += '_' + hashlib.sha256(canonical(identity)).hexdigest()[:16]
            if alias in mapping:
                raise ValueError("duplicate native tool mapping")
            mapping[alias] = identity
            description = item.get("description", "")
            description = "Native local tool " + ".".join((*namespace, name)) + ".\n" + description
            if kind == "custom":
                description += "\nPass the exact native tool input in the string property input."
                if item.get("format"):
                    description += "\nNative input format: " + canonical(item["format"]).decode()
                parameters = {"type": "object", "properties": {"input": {"type": "string"}},
                    "required": ["input"], "additionalProperties": False}
            else:
                parameters = deepcopy(item.get("parameters", {"type": "object", "properties": {}}))
            tool = {"type": "function", "name": alias, "description": description, "parameters": parameters}
            if "strict" in item:
                tool["strict"] = item["strict"]
            tools.append(tool)
    visit(data.get("tools", []))
    def find(item):
        name, namespace = item.get("name"), item.get("namespace")
        matches = [(alias, info) for alias, info in mapping.items()
            if (info["name"] == name and (namespace is None or info["namespace"] == namespace))
            or (namespace is None and ".".join(filter(None, (info["namespace"], info["name"]))) == name)]
        if len(matches) != 1:
            raise ValueError("history references an ambiguous or undeclared native tool")
        return matches[0]
    if isinstance(data.get("input"), list):
        for item in data["input"]:
            if item.get("type") in ("function_call", "custom_tool_call"):
                alias, info = find(item)
                if info["type"] == "custom":
                    if item.get("type") != "custom_tool_call" or not isinstance(item.get("input"), str):
                        raise ValueError("custom native history has wrong input type")
                    item["arguments"] = canonical({"input": item.pop("input")}).decode()
                item.update(type="function_call", name=alias)
                item.pop("namespace", None)
            elif item.get("type") == "custom_tool_call_output":
                item["type"] = "function_call_output"
    choice = data.get("tool_choice")
    if isinstance(choice, dict):
        alias, _ = find(choice)
        data["tool_choice"] = {"type": "function", "name": alias}
    data["tools"] = tools
    return data, {"schema_version": 1, "version": VERSION, "tools": mapping,
        "native_tools_sha256": hashlib.sha256(canonical(native.get("tools", []))).hexdigest(),
        "provider_tools_sha256": hashlib.sha256(canonical(tools)).hexdigest()}


def restore_response(raw, receipt):
    mapping = receipt["tools"]
    events, complete = [], {}
    for block in raw.replace(b"\r\n", b"\n").split(b"\n\n"):
        data = b"\n".join(line[5:].lstrip(b" ") for line in block.splitlines() if line.startswith(b"data:"))
        if not data or data == b"[DONE]":
            continue
        row = json.loads(data)
        events.append(row)
        if row.get("type") in ("response.completed", "response.incomplete", "response.failed"):
            for item in row.get("response", {}).get("output") or []:
                if item.get("type") == "function_call":
                    info = mapping.get(item.get("name"))
                    if info is None:
                        raise ValueError("provider returned an undeclared tool alias")
                    complete[item.get("id")] = (info, item)
        if isinstance(row.get("item"), dict) and row["item"].get("type") == "function_call":
            info = mapping.get(row["item"].get("name"))
            if info is None:
                raise ValueError("provider streamed an undeclared tool alias")
    def restore_item(item):
        if item.get("type") != "function_call":
            return item
        item = deepcopy(item)
        info = mapping[item["name"]]
        item["name"] = info["name"]
        if info["namespace"]:
            item["namespace"] = info["namespace"]
        if info["type"] == "custom":
            args = item.pop("arguments", "")
            parsed = json.loads(args) if args else {"input": ""}
            if set(parsed) != {"input"} or not isinstance(parsed["input"], str):
                raise ValueError("provider custom wrapper must contain exactly one string input")
            item.update(type="custom_tool_call", input=parsed["input"])
        return item
    restored = []
    for row in events:
        row = deepcopy(row)
        kind = row.get("type", "")
        if kind.startswith("response.function_call_arguments."):
            binding = complete.get(row.get("item_id"))
            if binding and binding[0]["type"] == "custom":
                if kind.endswith(".delta"):
                    continue
                item = restore_item(binding[1])
                restored.append({"type": "response.custom_tool_call_input.delta",
                    "item_id": row["item_id"], "output_index": row.get("output_index", 0), "delta": item["input"]})
                row.pop("arguments", None)
                row.update(type="response.custom_tool_call_input.done", input=item["input"])
        if isinstance(row.get("item"), dict):
            row["item"] = restore_item(row["item"])
        if isinstance(row.get("response"), dict) and isinstance(row["response"].get("output"), list):
            row["response"]["output"] = [restore_item(item) for item in row["response"]["output"]]
        restored.append(row)
    # Buffering was already required by budget settlement. Renumber translated
    # events because a custom wrapper's JSON deltas become one native input.
    blocks = []
    for index, row in enumerate(restored):
        row["sequence_number"] = index
        blocks.append(b"event: " + row["type"].encode() + b"\ndata: " + canonical(row) + b"\n\n")
    return b"".join(blocks)
