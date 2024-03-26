#!/bin/bash

readarray -t FILES<<<"$(find . \( -type d -name 'examples' \) -prune -o \
                        -type f -name '*.c' -print -o -name '*.h' -print)"

for FILE in "${FILES[@]}"; do
  echo -n "formatting $FILE.. "
  clang-format -style=Google -i "$FILE"
  echo "done"
done
