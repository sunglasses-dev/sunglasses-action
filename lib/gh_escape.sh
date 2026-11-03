# Escape a value before it is written into a workflow-command line (`::error::...`).
#
# The runner reads commands from the start of any output line, so a value that
# carries a newline can start a second command, and a `%` or `,` or `:` in a
# property value changes which property it is. Message text escapes % CR LF;
# property values (file=...) also escape : and ,.
#
#   gh_escape "$value"       -> for the message part (after the second ::)
#   gh_escape -p "$value"    -> for a property value (file=<here>)
#
# Every `::` emission in entrypoint.sh must pass its variables through this
# function; tests/test_workflow_command_escape.py fails if one does not.
# Bash 3.2 compatible.
gh_escape() {
  local prop=0
  if [ "${1:-}" = "-p" ]; then prop=1; shift; fi
  local s="${1-}"
  s="${s//\%/%25}"
  s="${s//$'\r'/%0D}"
  s="${s//$'\n'/%0A}"
  if [ "$prop" -eq 1 ]; then
    s="${s//:/%3A}"
    s="${s//,/%2C}"
  fi
  printf '%s' "$s"
}
