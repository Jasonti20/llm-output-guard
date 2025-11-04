set -euo pipefail

printf 'Email: a@test.com\n' | guard scan --in - --format pretty; echo $?
printf 'Card: 4242 4242 4242 4242\n' > /tmp/leak.txt
guard scan --in /tmp/leak.txt --format json; echo $?
guard scan --in /tmp/leak.txt --profile strict --format pretty; echo $?
guard scan --in /tmp/leak.txt --policy policy/examples/policy.yaml --profile balanced; echo $?
