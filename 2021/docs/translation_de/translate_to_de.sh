#!/bin/bash
for f in "$1"/*.md; do
  [ -f "$f" ] || continue
  base=$(basename "$f")
  trans -indent 0 -brief -i "$f" -o "$1/${base%.*}.de.${base##*.}"
  # trans -indent 0 -brief -i A00_2021_Introduction.md -o A00_2021_Introduction.de.md
done
