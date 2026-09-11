#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

readonly SOURCE_URL=https://cdn.deepseek.com/api-docs/codex-deepseek-setup-en.sh
readonly EXPECTED_SOURCE_SHA256=ee0119610037ef8fc4cf05899109dec1530ad900730fd29797da751afd85953e
readonly EXPECTED_CATALOG_SHA256=bce20f679495809f4fa6e48672b6dcbab84b6adff5251890b6e6a21eddb9c12f

usage()
{
	echo "usage: $0 OUTPUT_JSON" >&2
	exit 2
}

[[ "$#" -eq 1 ]] || usage
readonly OUTPUT_JSON="$1"
readonly OUTPUT_PARENT="$(dirname -- "$OUTPUT_JSON")"
[[ -d "$OUTPUT_PARENT" && ! -e "$OUTPUT_JSON" && ! -L "$OUTPUT_JSON" ]] || {
	echo "output parent must exist and OUTPUT_JSON must be new: $OUTPUT_JSON" >&2
	exit 1
}

readonly TEMP_ROOT="$(mktemp -d)"
cleanup()
{
	rm -rf -- "$TEMP_ROOT"
}
trap cleanup EXIT HUP INT TERM

readonly SETUP_SCRIPT="$TEMP_ROOT/deepseek-codex-setup.sh"
readonly EXTRACTED_JSON="$TEMP_ROOT/models.json"

env -u NODE_TLS_REJECT_UNAUTHORIZED curl \
	--fail --silent --show-error --location \
	--proto '=https' --tlsv1.2 \
	--output "$SETUP_SCRIPT" "$SOURCE_URL"
readonly SOURCE_SHA256="$(sha256sum "$SETUP_SCRIPT" | awk '{print $1}')"
[[ "$SOURCE_SHA256" == "$EXPECTED_SOURCE_SHA256" ]] || {
	echo "DeepSeek setup source changed; review and update the pinned digest" >&2
	exit 1
}

awk '
	!capture && /^  cat > / && /CODEX_MODELS_JSON/ { capture = 1; next }
	capture && $0 == "CODEX_MODELS_JSON" { complete = 1; exit }
	capture { print }
	END { if (!complete) exit 1 }
' "$SETUP_SCRIPT" > "$EXTRACTED_JSON"

python3 - "$EXTRACTED_JSON" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
raw = path.read_bytes()
if not raw or len(raw) > 1024 * 1024:
    raise SystemExit("model catalog size is outside 1..1048576 bytes")
catalog = json.loads(raw)
if set(catalog) != {"models"} or not isinstance(catalog["models"], list):
    raise SystemExit("model catalog does not have the expected top-level shape")
models = catalog["models"]
slugs = [model.get("slug") for model in models if isinstance(model, dict)]
if len(slugs) != len(models) or len(slugs) != len(set(slugs)):
    raise SystemExit("model catalog contains malformed or duplicate model entries")
for required in ("deepseek-flash", "deepseek-v4-pro"):
    if required not in slugs:
        raise SystemExit(f"model catalog is missing {required}")
def version_tuple(value):
    try:
        return tuple(int(part) for part in value.split("."))
    except (AttributeError, ValueError):
        raise SystemExit(f"invalid minimal_client_version: {value!r}")

for model in models:
    if version_tuple(model.get("minimal_client_version", "0")) > version_tuple("0.154.0"):
        raise SystemExit(
            f"{model['slug']} requires newer Codex {model['minimal_client_version']}"
        )
PY

readonly CATALOG_SHA256="$(sha256sum "$EXTRACTED_JSON" | awk '{print $1}')"
[[ "$CATALOG_SHA256" == "$EXPECTED_CATALOG_SHA256" ]] || {
	echo "extracted DeepSeek model catalog changed unexpectedly" >&2
	exit 1
}

install -m 0444 -- "$EXTRACTED_JSON" "$OUTPUT_JSON"
echo "source_url=$SOURCE_URL"
echo "source_sha256=$SOURCE_SHA256"
echo "catalog_sha256=$CATALOG_SHA256"
