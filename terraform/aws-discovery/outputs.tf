output "teleport_discovery_config_name" {
  description = "tctl get discovery_config/<name>"
  value       = module.aws_discovery.teleport_discovery_config_name
}

output "teleport_integration_name" {
  description = "tctl get integrations/<name>"
  value       = module.aws_discovery.teleport_integration_name
}

output "teleport_provision_token_name" {
  description = "tctl get tokens/<name>"
  value       = module.aws_discovery.teleport_provision_token_name
}

output "aws_iam_role_arn" {
  description = "The role Teleport's Discovery Service assumes with AWS OIDC."
  value       = module.aws_discovery.teleport_discovery_service_iam_role_arn
}

output "aws_oidc_provider_arn" {
  value = module.aws_discovery.aws_oidc_provider_arn
}
