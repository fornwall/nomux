#!/bin/sh
# Keeps an abrupt-disconnect cell's login open so the runner has a connection to cut.
#
# The clean cells end their login by letting `ssh host 'cmd'` return; there is nothing to
# blackhole after that, because the connection is already gone. So the abrupt cells hold
# the login here instead, and the runner cuts the wire underneath it. The login then ends
# the only way left to it — sshd's `ClientAlive` timeout — which is the teardown path the
# whole cell exists to reach.
#
# The `while` loop rather than `exec sleep`: this process is the runner's clock. It polls
# for the name below to disappear and times how long that took, and a name that changed to
# `sleep` partway through would leave it timing nothing.
set -eu

# Read before the wire is cut, not after: the runner waits for this line, and only then is
# the connection idle enough that the next `ClientAlive` request is the one that goes
# unanswered.
printf 'NOMUX-HOLD-READY\n'

while :; do
    sleep 1
done
