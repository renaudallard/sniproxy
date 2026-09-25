#!/bin/sh
# Run a test and also fail it when its output reports a crashed helper
# process or a sanitizer finding: the main process only logs those, and
# a test that checks the exit status of what it started would pass.
out="./$(basename "$1").output"
"$@" > "$out" 2>&1
status=$?
cat "$out"
if grep -E 'crashed with signal|runtime error:|ERROR: (Address|Leak)Sanitizer|WARNING: MemorySanitizer' "$out" > /dev/null; then
    echo "check_output.sh: $1 reported a crash or a sanitizer finding" >&2
    status=1
fi
rm -f "$out"
exit $status
