variable "teleport_proxy_public_addr" {
  description = "Teleport proxy address, host:port."
  type        = string
  default     = "teleport.localhost:3080"
}

variable "teleport_identity_file" {
  description = "Identity file for the Teleport provider. teleport-setup writes it on every `docker compose up`."
  type        = string
  default     = "../../data/terraform/identity"
}

variable "aws_endpoint" {
  description = "The simulated AWS account's API endpoint (IAM and STS)."
  type        = string
  default     = "https://aws.localhost:12443"
}

variable "aws_regions" {
  description = "Regions to discover EC2 instances in. \"*\" lists the account's enabled regions with account:ListRegions."
  type        = list(string)
  default     = ["*"]
}
