# Verify we can spawn multiple bootc status at the same time and get valid JSON
use std assert
use tap.nu

tap begin "concurrent bootc status"

# Create a temporary directory for output files
let tmpdir = mktemp -d
print $"Using temporary directory: ($tmpdir)"

# Number of concurrent invocations  
let n = 10

# Create systemd unit files for concurrent bootc status commands.
# Writing actual unit files allows proper dependency tracking.
let units = 0..<$n | each { |v|
    let unit_name = $"bootc-status-test-($v).service"
    let outpath = $"($tmpdir)/($v).json"
    let unit_content = $"[Unit]
Description=Test bootc status ($v)

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'bootc status --format=json > ($outpath)'
"
    $unit_content | save -f $"/run/systemd/system/($unit_name)"
    $unit_name
}

# Reload systemd to pick up the new units.
systemctl daemon-reload

# Use systemd-run to create a transient sync unit with After= and Requires=
# dependencies on all worker units. --wait blocks until completion.
let dep_args = $units | each { |u| [$"--property=After=($u)" $"--property=Requires=($u)"] } | flatten
systemd-run --wait ...$dep_args -- true

# Verify each output file contains valid JSON with the expected structure.
# This is a regression test for spinner output polluting stdout.
for v in 0..<$n {
    let path = $"($tmpdir)/($v).json"
    # open automatically parses JSON files, so we get a record directly
    # If the file had spinner output mixed in, this would fail to parse
    let st = open $path
    assert equal $st.apiVersion org.containers.bootc/v1 $"($path) should contain valid bootc status JSON"
}

# Clean up
rm -rf $tmpdir

tap ok
