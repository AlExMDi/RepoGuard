#!/bin/bash
file=$(jq -r '.tool_input.file_path // empty')
case "$file" in *.ts|*.tsx|*.js|*.json|*.md|*.yml|*.yaml) ;; *) exit 0 ;; esac
cd "$CLAUDE_PROJECT_DIR" || exit 0
pnpm exec prettier --write "$file" >/dev/null 2>&1
if [[ "$file" == *.ts || "$file" == *.tsx ]]; then
  if ! out=$(pnpm exec eslint --fix "$file" 2>&1); then
    echo "$out" >&2
    exit 2
  fi
fi
exit 0
