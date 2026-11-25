# A simulated EC2 instance: Ubuntu with systemd, as on an Ubuntu AMI, and
# nothing of Teleport. The simulator is its SSM agent (it runs SSM commands
# here with docker exec) and its instance metadata service.
FROM ubuntu:24.04

ENV container=docker DEBIAN_FRONTEND=noninteractive

# What Teleport's default installer needs (bash, sudo, curl, systemd), plus
# socat and iproute2 to forward 169.254.169.254 to the simulator (and
# 127.0.0.1:3080 to Teleport; see teleport-proxy.service). Package
# lists are removed, as on a fresh instance; the installer updates them.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus ca-certificates curl sudo gnupg socat iproute2 \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Units that need hardware or a console, which a container doesn't have.
RUN systemctl mask \
      systemd-udevd.service systemd-udevd-kernel.socket systemd-udevd-control.socket \
      systemd-modules-load.service systemd-firstboot.service \
      sys-kernel-config.mount sys-kernel-debug.mount sys-kernel-tracing.mount \
      getty.target console-getty.service

COPY imds.service trust-mkcert.service teleport-proxy.service /etc/systemd/system/
RUN systemctl enable imds.service trust-mkcert.service teleport-proxy.service

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
