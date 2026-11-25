# EC2 auto-discovery for this workshop's Teleport cluster, set up with
# Teleport's discovery/aws Terraform module, against the simulated AWS
# account in the simulator container instead of real AWS.

provider "aws" {
  region = "us-east-1"

  # The simulator accepts any long-term access key as the account's admin.
  access_key = "AKIAWORKSHOPEXAMPLE1"
  secret_key = "workshop-simulator-secret"

  # IAM and STS are the only AWS APIs this configuration calls.
  endpoints {
    iam = var.aws_endpoint
    sts = var.aws_endpoint
  }
  skip_metadata_api_check = true
}

provider "teleport" {
  addr               = var.teleport_proxy_public_addr
  identity_file_path = var.teleport_identity_file
}

module "aws_discovery" {
  source  = "terraform.releases.teleport.dev/teleport/discovery/aws"
  version = "19.0.1"

  teleport_integration_use_name_prefix = false

  teleport_proxy_public_addr    = var.teleport_proxy_public_addr
  teleport_discovery_group_name = "cloud-discovery-group"
  teleport_integration_name     = "aws-integration-6e8ca057"

  aws_matchers = [
    {
      types = ["ec2"]
    }
  ]
}
