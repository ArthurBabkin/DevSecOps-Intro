#!/usr/bin/env bash
set -euo pipefail

# Add Kata runtime to containerd config.

CONF_DEFAULT="/etc/containerd/config.toml"
# Allow custom config path.
CONF="${CONF:-${1:-$CONF_DEFAULT}}"
TMP=$(mktemp)

backup() {
  if [ -f "$CONF" ]; then
    cp -a "$CONF" "${CONF}.$(date +%Y%m%d%H%M%S).bak"
  fi
}

ensure_default() {
  if [ ! -s "$CONF" ]; then
    echo "Generating default containerd config at $CONF" >&2
    mkdir -p "$(dirname "$CONF")"
    containerd config default > "$CONF"
  fi
}

detect_header() {
  # Use v3 CRI path if present.
  if grep -q "^\[plugins\.'io\.containerd\.cri\.v1\.runtime'\]" "$CONF"; then
    echo "[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata]"
  else
    echo "[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]"
  fi
}

insert_or_update_kata() {
  local header
  header=$(detect_header)
  local value="  runtime_type = 'io.containerd.kata.v2'"

  # Update existing kata block or append a new one.
  awk -v hdr="$header" -v val="$value" '
    BEGIN { inside=0; updated=0 }
    {
      if ($0 == hdr) {
        print $0; inside=1; next
      }
      if (inside) {
        if ($0 ~ /^\[/) {
          if (!updated) print val
          inside=0
          print $0
          next
        }
        if ($0 ~ /^\s*runtime_type\s*=\s*/){
          print val; updated=1; next
        }
        print $0; next
      }
      print $0
    }
    END {
      if (inside && !updated) {
        print val
      } else if (!inside && NR > 0) {
        # No-op. Missing header is appended later.
      }
    }
  ' "$CONF" > "$TMP"

  if ! grep -qF "$header" "$TMP"; then
    {
      printf '\n%s\n%s\n' "$header" "$value"
    } >> "$TMP"
  fi

  install -m 0644 "$TMP" "$CONF"
}

main() {
  backup
  ensure_default
  insert_or_update_kata
  echo "Updated $CONF with Kata runtime: io.containerd.kata.v2" >&2
  echo "Restart containerd to apply: sudo systemctl restart containerd" >&2
}

main "$@"
