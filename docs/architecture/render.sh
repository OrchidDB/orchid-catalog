#!/bin/sh
set -eu
cd "$(dirname "$0")"
dot -Tsvg 01-system.dot -o 01-system.svg
dot -Tpng 01-system.dot -o 01-system.png
