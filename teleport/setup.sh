#!/busybox/sh
# One-shot: create Access Lists and install the SCIM plugin (neither can be
# created by --bootstrap),
# then write the SCIM bearer token to /scim/token for the simulator.
set -e
# Runs in Teleport's network namespace, so tctl reaches Auth on localhost.
tctl() { /usr/local/bin/tctl -c /etc/teleport/teleport.yaml "$@"; }

until tctl status >/dev/null 2>&1; do echo "waiting for Teleport..."; sleep 2; done

# Access Lists that SCIM groups map onto (by title). Retried: on first start
# Teleport may still be initializing its data dir.
until tctl create -f /access-lists.yaml; do echo "retrying..."; sleep 2; done

# Postgres TLS cert signed by Teleport's DB CA (Teleport authenticates with
# client certs). Files must be readable by the postgres user (uid 999), and
# the key private to it.
if [ ! -s /pg-certs/server.key ]; then
  tctl auth sign --format=db --host=postgres --out=/pg-certs/server --ttl=2190h
fi
chown 999:999 /pg-certs/server.*
chmod 644 /pg-certs/server.crt /pg-certs/server.cas
chmod 600 /pg-certs/server.key

if [ -s /scim/token ] && tctl get plugins/scim >/dev/null 2>&1; then
  echo "SCIM plugin already installed"
  exit 0
fi

tctl plugins delete scim >/dev/null 2>&1 || true
tctl plugins install scim --connector=simulator --connector-type=saml --auth=bearer \
  | sed -n 's/.*API Bearer Token: *//p' > /scim/token
[ -s /scim/token ]
echo "SCIM plugin installed; token written to /scim/token"
