#!/bin/sh
# Configures this container into one cell of the logout matrix, then hands over to
# systemd. Everything here has to happen *before* PID 1 starts: logind reads its
# configuration and the linger markers at startup, and PAM is consulted per login.
set -eu

cell_kill=${CELL_KILL_USER_PROCESSES:-no}
cell_linger=${CELL_LINGER:-no}
cell_pam=${CELL_PAM_SYSTEMD:-yes}
cell_user=nomuxer

# The axis the whole matrix exists for. With `yes` — the upstream default since systemd
# 230 — logind kills everything left in `session-N.scope` at the final logout, which is
# where a directly-launched daemon still lives after `setsid` (startup.rs says so).
mkdir -p /etc/systemd/logind.conf.d
cat > /etc/systemd/logind.conf.d/10-nomux-cell.conf <<EOF
[Login]
KillUserProcesses=$cell_kill
EOF

# Linger decides whether \`user@UID.service\` outlives the final logout, and so whether
# the transient scope \`systemd-run --user --scope\` puts the daemon in outlives it too.
# Written as the marker file logind reads at startup rather than through \`loginctl\`,
# which needs a bus that does not exist yet.
if [ "$cell_linger" = yes ]; then
    mkdir -p /var/lib/systemd/linger
    touch "/var/lib/systemd/linger/$cell_user"
else
    rm -f "/var/lib/systemd/linger/$cell_user"
fi

# The third axis: a login with no pam_systemd is a login with no session scope, no
# `$XDG_RUNTIME_DIR` and no user bus — the container and `UsePAM no` case, where
# `launcher::user_manager_reachable` must decline and the direct path must be taken.
if [ "$cell_pam" = no ]; then
    sed -i 's/^\(session.*pam_systemd\.so\)/#\1/' /etc/pam.d/common-session
else
    sed -i 's/^#\(session.*pam_systemd\.so\)/\1/' /etc/pam.d/common-session
fi

# The binaries under test, mounted rather than baked so a rebuild does not rebuild the
# image. Copied out of the mount because it is read-only and `/opt` is not on `PATH`
# for a non-interactive `ssh host 'cmd'`.
if [ -d /opt/nomux-bin ]; then
    install -m 0755 /opt/nomux-bin/nomux /usr/local/bin/nomux
    install -m 0755 /opt/nomux-bin/nomux-probe /usr/local/bin/nomux-probe
fi

# The runner's throwaway public key, mounted the same way.
if [ -r /opt/nomux-key.pub ]; then
    install -d -m 0700 -o "$cell_user" -g "$cell_user" "/home/$cell_user/.ssh"
    install -m 0600 -o "$cell_user" -g "$cell_user" \
        /opt/nomux-key.pub "/home/$cell_user/.ssh/authorized_keys"
fi

# Recorded where the runner can read it back, so a cell's verdict is filed against the
# configuration it actually booted with rather than the one the compose file requested.
cat > /run-cell.env <<EOF
CELL_KILL_USER_PROCESSES=$cell_kill
CELL_LINGER=$cell_linger
CELL_PAM_SYSTEMD=$cell_pam
EOF

exec /sbin/init
