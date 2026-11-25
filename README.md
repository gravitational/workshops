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
127.0.0.1 teleport.localhost duo.localhost okta.localhost entra.localhost github.localhost aws.localhost
```

### Teleport License

Place a valid `license.pem` file in the same directory as the Docker Compose
stack.

## Run

Run `make up` or `docker compose up` to start the workshop environments. The
environments store their state in `./data` (and the k3s cluster in the
`k3s-data` Docker volume). For a fresh cluster, run `make clean`; changes to
`teleport/bootstrap.yaml` (roles, the SAML connector) only apply to a fresh
cluster.

Open Teleport at https://teleport.localhost:3080.

## Simulated Services

This Docker Compose stack runs five simulated services: Duo, Okta, Entra ID,
GitHub Enterprise Server, and an AWS account.

| Service  | URL                             | Metadata URL                                  |
|----------|---------------------------------|-----------------------------------------------|
| Duo      | https://duo.localhost:8443      | https://duo.localhost:8443/sso/saml/metadata   |
| Okta     | https://okta.localhost:9443     | https://okta.localhost:9443/sso/saml/metadata  |
| Entra ID | https://entra.localhost:10443   | https://entra.localhost:10443/sso/saml/metadata |
| GitHub   | https://github.localhost:11443  | https://github.localhost:11443/_services/token/.well-known/openid-configuration |
| AWS      | https://aws.localhost:12443     | (API endpoint for IAM, STS, EC2, SSM and Account; the URL is also its console) |

If you generated certificates before `aws.localhost` was added, rerun `make
certs` so your browser and Terraform trust https://aws.localhost:12443.

## GitHub Actions → Kubernetes (simulated GHES)

A GitHub Actions workflow deploys a sample app (nginx) to a Kubernetes cluster
through Teleport without any stored secrets. The job presents its GitHub OIDC ID
token, `tbot` joins Teleport as the bot `github-actions-k8s-demo` with the
`github` join method, and `kubectl` reaches the `k3s` cluster through Teleport.

The pieces, all started by `docker compose up`:

- `simulator` serves a fake GitHub Enterprise Server, with the repo
  `example-org/teleport-k8s-demo` (contents from `github/repo/`) and the Actions
  OIDC issuer.
- `ci-runner` runs the sample GHA workflow
  (`github/repo/.github/workflows/deploy.yaml`) with real `tbot` and `kubectl`.
  Actions such as `teleport-actions/auth-k8s` are mocks that behave similarly
  to the real ones.
- `k3s` is the Kubernetes cluster (enrolled in Teleport as `k3s`) where the GHA
  workflow deploys to. It runs as a privileged container, and Teleport waits for
  it to be ready before starting.
- `teleport-setup` creates the bot, its role and its join token from
  `teleport/github-actions/*.yaml`. `ci-runner` waits for it to finish, so
  runs dispatched before then queue ("Waiting for a runner") until it has.
  To watch it, run `docker compose logs -f teleport-setup` until it exits.

Viewing the audit log and running `tsh kube login k3s` below needs a user in
the `admins` group, such as `andrew.admin` (it grants the `root-access`
role).

### Run the workflow

1. Open https://github.localhost:11443/example-org/teleport-k8s-demo/actions.
2. Select **Deploy**, click **Run workflow**, keep branch `main`, and click
   **Run workflow**.
3. Open the run. The `teleport-actions/auth-k8s` step logs the decoded ID
   token claims (`repository`, `ref`, ...) that Teleport checks, followed by
   tbot's output. The last step lists the two `nginx` pods.

### See the join in Teleport

In the Teleport Web UI, open the audit log and find the **Bot Joined** event
(`bot.join`, method `github`). Its attributes are the job's claims. From the
command line:

```
docker compose exec teleport tctl get bot_instance
```

The audit log is also on disk, one JSON event per line:

```
jq 'select(.event=="bot.join")' data/teleport/log/*/*.log
```

### See the pods

```
tsh login --proxy=teleport.localhost:3080
tsh kube login k3s
kubectl -n demo get pods
```

### A branch that isn't allowed

Run the workflow again on branch `dev`. The join token only allows
`refs/heads/main`, so Teleport rejects the join: the auth step fails with
tbot's `id token claims did not match any allow rules`, and the deploy steps
are skipped. The audit log shows a failed `bot.join`.

### Recreate on real GitHub

1. Copy the contents of `github/repo/` into your own GitHub repository,
   including the hidden `.github/` directory (`cp -R github/repo/. <your
   repo>`).
2. In `teleport/github-actions/token.yaml`, replace the `${GITHUB_REPOSITORY}`
   placeholder with your `owner/name` and delete `enterprise_server_host`
   (it's only for GitHub Enterprise Server). Then create the resources:

   ```
   tctl create -f teleport/gha-demo-resources.yaml
   ```
3. In `deploy.yaml`, set `proxy` to your Teleport proxy address and
   `kubernetes-cluster` to your cluster's name in Teleport.
4. Apply `k3s/manifests/github-ci-rbac.yaml` to your Kubernetes cluster
   (namespace `demo`, and RBAC for the `github-ci` group).
5. Make sure your Teleport proxy is reachable from GitHub-hosted runners.

## EC2 auto-discovery (simulated AWS)

Teleport's Discovery Service (group `cloud-discovery-group`) discovers EC2 instances
in a simulated AWS account. You set it up the way you would for a real
account: with Teleport's `discovery/aws` Terraform module, which creates an
IAM OIDC provider, role and policy, plus the Teleport integration, discovery
config and join token.

- `simulator` serves the AWS account at https://aws.localhost:12443: just the
  IAM, STS, EC2, SSM and Account API calls this flow makes, over two
  instances. Teleport reaches it through `AWS_ENDPOINT_URL`, and Terraform
  through its provider's `endpoints` block.
- `ec2-web-1` is instance `web-1`: a plain Ubuntu container with systemd. The
  simulator is its SSM agent (it runs SSM commands with `docker exec`) and its
  instance metadata service.
- `teleport-setup` writes `data/terraform/identity` for Terraform's Teleport
  provider.

```
cd terraform/aws-discovery
terraform init
terraform apply
```

Within a couple of minutes, Teleport discovers both instances. It installs
Teleport on `web-1` with its default install script through SSM, and the
instance joins as node `ip-10-0-1-11` with the IAM join method. `web-2`'s SSM
agent has lost its connection, so the integration page (**Zero Trust Access
→ Integrations**) shows it as a failed instance with a pending task. See
[terraform/aws-discovery/README.md](terraform/aws-discovery/README.md) for
what each instance shows, the full list of simulated APIs, and how the
simulation differs from AWS.
