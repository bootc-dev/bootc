# number: 450
# tmt:
#   summary: Some random test
#   duration: 5m
#
# Verify that something works

bootc status -v
bootc status --json

def main[] {
    echo "The test has passed"
}
