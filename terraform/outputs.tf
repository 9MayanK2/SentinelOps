output "jenkins_public_ip" {
  description = "Jenkins Host Public IP"
  value       = module.ec2.public_ip
}

output "jenkins_instance_id" {
  description = "Jenkins Instance ID"
  value       = module.ec2.instance_id
}

output "backend_repository_url" {
  description = "Backend AWS ECR Repository URL"
  value       = module.ecr.backend_repository_url
}

output "frontend_repository_url" {
  description = "Frontend AWS ECR Repository URL"
  value       = module.ecr.frontend_repository_url
}

output "eks_cluster_name" {
  description = "Amazon EKS Cluster Name"
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "Amazon EKS API Server Endpoint"
  value       = module.eks.cluster_endpoint
}

output "configure_kubectl_command" {
  description = "Run this command to configure kubectl"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}"
}

output "rds_endpoint" {
  description = "Amazon RDS MySQL Endpoint (host:port)"
  value       = module.rds.db_instance_endpoint
}

output "rds_hostname" {
  description = "Amazon RDS MySQL Hostname"
  value       = module.rds.db_instance_address
}

output "rds_port" {
  description = "Amazon RDS MySQL Port"
  value       = module.rds.db_instance_port
}

output "rds_db_name" {
  description = "Amazon RDS MySQL Database Name"
  value       = module.rds.db_name
}

output "rds_username" {
  description = "Amazon RDS MySQL Username"
  value       = module.rds.db_username
}

