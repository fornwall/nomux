# A host that can actually answer the question: systemd as PID 1, a real logind, a real
# sshd, and a real PAM stack. `docker exec` would bypass all four, so the matrix logs in
# over SSH and the logout it measures is a genuine one.
FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive
# `dbus-user-session` is load-bearing and easy to miss: without it there is a
# `$XDG_RUNTIME_DIR` but no `$XDG_RUNTIME_DIR/bus`, so `user@UID.service` never comes up,
# `launcher::user_manager_reachable` declines, and every cell silently measures the
# direct path no matter what its linger axis says. Plain `dbus` is the system bus only.
#
# `iptables` is what makes the abrupt-disconnect cells abrupt: the runner blackholes port
# 22 inside the container so sshd's packets go nowhere and no FIN or RST can reach it,
# leaving `ClientAliveInterval` as the only thing that will end the login. Killing the
# local ssh client would *not* do — the host kernel still closes the socket politely and
# sshd sees an orderly logout, which is the cell that already exists.
RUN apt-get update && apt-get install --no-install-recommends -y \
        systemd systemd-sysv dbus dbus-user-session libpam-systemd \
        openssh-server procps iproute2 iptables ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# systemd in a container: the units that need host state nobody gave it only slow the
# boot down and add noise to `journalctl` when the matrix is being debugged.
RUN systemctl mask \
        systemd-udevd.service systemd-udev-trigger.service \
        systemd-modules-load.service sys-kernel-config.mount \
        sys-kernel-debug.mount sys-kernel-tracing.mount \
    && systemctl enable ssh.service

# Keys, not passwords: the runner holds a throwaway pair generated per run.
RUN mkdir -p /run/sshd && ssh-keygen -A
COPY image/sshd_config /etc/ssh/sshd_config.d/10-nomux-e2e.conf

# The user whose logout is the experiment. A plain login user with a real home, because
# `rundir::run_dir` prefers `$HOME/.local/state` and that is the case worth testing:
# `$XDG_RUNTIME_DIR` is removed at the final logout, which is the whole hazard.
RUN useradd --create-home --shell /bin/bash nomuxer

COPY image/cell-entrypoint.sh /usr/local/sbin/cell-entrypoint.sh
COPY image/session-create.sh /usr/local/bin/nomux-cell-create
COPY image/session-hold.sh /usr/local/bin/nomux-cell-hold
RUN chmod 0755 /usr/local/sbin/cell-entrypoint.sh \
        /usr/local/bin/nomux-cell-create /usr/local/bin/nomux-cell-hold

# systemd's own shutdown request, so `docker compose down` is a clean poweroff rather
# than a SIGTERM logind never hears.
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/usr/local/sbin/cell-entrypoint.sh"]
