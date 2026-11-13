# Teleport Workshop Environments

## Prerequisite

### TLS Certificates

The Teleport Web UI requires valid TLS certificates. These environments use
[mkcert](https://github.com/FiloSottile/mkcert) to generate certificates your
browser trusts, so you won't see certificate warnings.

1. [Install mkcert](https://github.com/filosottile/mkcert#installation) if you
   don't already have it.
2. Run `make certs` to generate and install the certificates in `./certs`.

#### Windows

macOS and Linux always resolve `*.localhost` names to 127.0.0.1. On Windows,
browsers resolve `*.localhost` on their own, but `tsh` and other command-line
tools may not. As Administrator, add this line to
`C:\Windows\System32\drivers\etc\hosts`:

```
127.0.0.1 teleport.localhost duo.localhost okta.localhost entra.localhost
```

### Teleport License

Place a valid `license.pem` file in the same directory as the Docker Compose
stack.

## Run

Run `make up` or `docker compose up` to start the workshop environments. The
environments store their state in `./data`. For a fresh cluster, run `make
clean` or delete `./data`.

Open Teleport at https://teleport.localhost:3080.

## Simulated Services

This Docker Compose stack runs three simulated services: Duo, Okta, and Entra
ID.

| Service  | URL                             | Metadata URL                                  |
|----------|---------------------------------|-----------------------------------------------|
| Duo      | https://duo.localhost:8443      | https://duo.localhost:8443/sso/saml/metadata   |
| Okta     | https://okta.localhost:9443     | https://okta.localhost:9443/sso/saml/metadata  |
| Entra ID | https://entra.localhost:10443   | https://entra.localhost:10443/sso/saml/metadata |
