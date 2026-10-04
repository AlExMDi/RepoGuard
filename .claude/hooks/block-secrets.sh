#!/bin/bash
input=$(cat)
file=$(jq -r '.tool_input.file_path // empty' <<<"$input")
[[ "$file" == */fixtures/* ]] && exit 0
text=$(jq -r '.tool_input.content // .tool_input.new_string // empty' <<<"$input")
if grep -Eq 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|-----BEGIN [A-Z ]*PRIVATE KEY-----' <<<"$text"; then
  jq -n '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny",
    permissionDecisionReason: "Posible secreto real fuera de fixtures/. Usa una variable de entorno."}}'
fi
exit 0
