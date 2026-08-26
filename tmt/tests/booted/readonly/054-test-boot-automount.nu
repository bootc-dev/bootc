use tap.nu

# Test if we can still access /boot after it has expired

let automounted = (
    do { ^findmnt --mountpoint /boot --types autofs --noheadings } | complete
).exit_code == 0

if not $automounted {
    print "/boot is not automounted. Exiting"
    exit 0
}

$env.SYSTEMD_PAGER = ''

systemctl cat -l boot.automount

bootc status

# Expire boot.autmount
mkdir /etc/systemd/system/boot.automount.d

echo "
[Automount]
TimeoutIdleSec=1
" | save --force /etc/systemd/system/boot.automount.d/override.conf

systemctl daemon-reload
systemctl restart boot.automount

print "After overriding timeout"
systemctl cat -l boot.automount

# Wait for automount to expire
sleep 5sec

# Make sure bootc status works
bootc status

tap ok
