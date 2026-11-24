# teleport-k8s-demo

This is a simulated GitHub repository for the GitHub Actions demo.

Its workflow (`.github/workflows/deploy.yaml`) authenticates to Teleport with
Machine ID using the job's GitHub ID token, then deploys `manifests/deployment.yaml`
to the `k3s` cluster through Teleport, all without any standing secrets.
