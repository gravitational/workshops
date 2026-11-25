# EC2 auto-discovery with Terraform (simulated AWS)

This configuration sets up Teleport's EC2 auto-discovery with Teleport's
[`discovery/aws` Terraform module](https://github.com/gravitational/teleport/tree/master/integrations/terraform-modules/teleport/discovery/aws)
(`terraform.releases.teleport.dev/teleport/discovery/aws`, 19.0.1). It runs
against the workshop's Teleport cluster and the simulated AWS account served
by the `simulator` container at https://aws.localhost:12443. It never touches
real AWS.

## Run it

With the stack up (`make up`):

```
cd terraform/aws-discovery
terraform init
terraform apply
```

Terraform authenticates to Teleport with `data/terraform/identity`, which
`teleport-setup` writes on every `docker compose up` for the local user
`terraform` (preset role `terraform-provider`). The identity is valid for 12
hours. To renew it, run `docker compose up teleport-setup`. The AWS provider
uses a made-up access key, which the simulator accepts as the account's
administrator.

Within about a minute (`poll_interval` in `teleport/teleport.yaml`), the
Discovery Service picks up the new `discovery_config`.

## What you'll see

The simulated account (`123456789012`) has two instances in us-east-1. Open
https://aws.localhost:12443 to see them, along with the IAM resources
Terraform created, the SSM commands and their results, and every API call.

| Instance | What it is | What Teleport does |
|---|---|---|
| `web-1` (`i-0a1b2c3d4e5f60001`) | The `ec2-web-1` container: Ubuntu 24.04 with systemd, no Teleport | Sends Teleport's default install script through SSM. The script installs `teleport-ent` from Teleport's apt repository, and the instance joins as node `ip-10-0-1-11` with the IAM join method. |
| `web-2` (`i-0a1b2c3d4e5f60002`) | Exists only in API responses | Its SSM agent is `ConnectionLost`, so Teleport opens the user task `ec2-ssm-agent-connection-lost` |

In Teleport, about a minute after `terraform apply` (plus the install, which
takes 20–60 seconds):

- **Resources** lists `ip-10-0-1-11`, labeled with its AWS tags
  (`aws/Name=web-1`, …), `teleport.dev/instance-id` and
  `teleport.dev/account-id`. You can SSH to it as `root`.
- **Zero Trust Access → Integrations → discovery-aws-account-123456789012**
  shows EC2 found, enrolled and failed counts (2, 1 and 1 once the node has
  joined), plus the pending task.
- The audit log has `ssm.run` (with the script's real output), `instance.join`
  (method `iam`, with the instance's assumed-role ARN) and the user task.

`ec2-web-1` keeps Teleport installed across restarts. To discover a fresh
instance again, recreate it:

```
docker compose rm -sf ec2-web-1 && docker compose up -d ec2-web-1
tctl rm nodes/<host ID of ip-10-0-1-11>   # or wait for its heartbeat to expire
```

### How the instance works

- **SSM agent:** the simulator, through the Docker socket.
  `ssm:SendCommand` runs the `commands` with `docker exec ec2-web-1 /bin/sh -c
  ...`. `GetCommandInvocation` reports InProgress until the command finishes,
  then its real exit code, stdout and stderr. The SSM agent is Online while
  the container runs.
- **IMDS:** `169.254.169.254:80` inside the container is forwarded to the
  simulator, which identifies the instance by the container's IP. It serves
  IMDSv2 tokens, instance identity, tags, and credentials for the instance
  profile role `workshop-ec2-instance`.
- **IAM join:** the node signs `sts:GetCallerIdentity` for
  `sts.us-east-1.amazonaws.com` with those credentials. Teleport's Auth
  Service sends the request there. Inside Docker, that name (like
  `login.microsoftonline.com`) is an alias for the simulator, which answers as
  `assumed-role/workshop-ec2-instance/i-0a1b2c3d4e5f60001`. The token allows
  account `123456789012`.

## Simulated AWS APIs

The simulator implements only what this flow calls. Any other action returns
`InvalidAction`, and the simulator logs it as `aws: UNSUPPORTED <service>:<action>`.

| Caller | API calls |
|---|---|
| Terraform AWS provider, `terraform apply` | `sts:GetCallerIdentity`; `iam:CreateOpenIDConnectProvider`, `GetOpenIDConnectProvider`; `iam:CreateRole`, `GetRole`, `ListRolePolicies`, `ListAttachedRolePolicies`; `iam:CreatePolicy`, `GetPolicy`, `GetPolicyVersion`; `iam:AttachRolePolicy` |
| Terraform AWS provider, `terraform destroy` | `iam:DetachRolePolicy`, `ListInstanceProfilesForRole`, `DeleteRole`, `ListPolicyVersions`, `DeletePolicy`, `DeleteOpenIDConnectProvider` |
| Teleport, AWS OIDC integration | `sts:AssumeRoleWithWebIdentity` with a Teleport-signed JWT (issuer `https://teleport.localhost:3080`, audience `discover.teleport`); `sts:GetCallerIdentity` |
| Teleport Discovery Service | `account:ListRegions` (regions `["*"]`); `ec2:DescribeInstances` per region; `ssm:DescribeInstanceInformation`; `ssm:SendCommand` (`AWS-RunShellScript`); `ssm:GetCommandInvocation` (polled until done) |
| The instance (Teleport installer and node) | IMDS: `/latest/api/token`, `meta-data/` (instance ID, region, hostname, tags, `iam/security-credentials/<role>`), `dynamic/instance-identity/document` |
| Teleport Auth Service, IAM join | `sts:GetCallerIdentity` at `sts.us-east-1.amazonaws.com`, presigned by the node, with a JSON reply |

Also implemented, for module updates and other provider versions: role, policy
and provider tag/untag/update calls, `CreatePolicyVersion`,
`DeletePolicyVersion`, `ListEntitiesForPolicy`, `ec2:DescribeRegions`,
`ssm:ListCommandInvocations`, and `sts:AssumeRole` (the module's `trust_role`
mode).

The simulator behaves like AWS where it matters for this flow:

- `AssumeRoleWithWebIdentity` verifies the token's signature against
  Teleport's JWKS. The account must have an OIDC provider for the issuer
  whose client IDs include the token's audience, and the role's trust policy
  must allow that provider, including its `:aud` condition.
- The temporary credentials it issues can only call the actions in the role's
  attached policies. Remove an action from the policy and Teleport reports a
  permissions user task.
- IAM state persists in `data/simulator/aws-iam.json`, so it survives
  restarts. Plans stay clean, and destroy works.

## Differences from real AWS

- Teleport's issuer includes the proxy's port (`teleport.localhost:3080`), but
  AWS OIDC provider URLs can't have one, so the module creates
  `https://teleport.localhost`. Real AWS would fetch the keys from port 443.
  The simulator matches the provider by host and fetches the keys from the
  issuer URL. In a real deployment the proxy is on 443, so the two match.
- No signature (SigV4) checks: any long-term access key is the admin.
- Only the `Action` and `Effect` of identity policies are evaluated.
  `Resource` and `Condition` are ignored; the module only uses `"*"`.
- STS signatures aren't verified either, so the IAM join trusts whatever
  identity the node's session token names.
- The installer downloads Teleport from Teleport's package repository, so
  `ec2-web-1` needs internet access.
- curl resolves `*.localhost` to the loopback address without DNS. The
  instance therefore forwards its `127.0.0.1:3080` to the Teleport container,
  so the installer's `curl https://teleport.localhost:3080/...` works.
- The simulator has the host's Docker socket mounted, to act as the SSM
  agent. Access to that socket is access to the host's Docker.

## Re-applying after a destroy

The module names the IAM role with a random suffix, so `destroy` followed by
`apply` changes the integration's role ARN under the same integration name.
Teleport caches AWS credentials per integration name for up to 15 minutes.
Until that cache expires, discovery keeps using the deleted role's session,
gets `AccessDenied`, and opens an `ec2-perm-account-denied` task. AWS would do
the same. To skip the wait, run `docker compose restart teleport`.

## Note: a local Teleport provider in `~/.terraform.d/plugins`

If `~/.terraform.d/plugins/terraform.releases.teleport.dev/` holds a local
build of the Teleport provider, Terraform installs that provider only from
there, and `terraform init` fails with *no available releases match*. To
install from the registry anyway, use a CLI config with
`provider_installation { direct {} }` via `TF_CLI_CONFIG_FILE`.
