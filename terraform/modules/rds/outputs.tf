############################################################
# Database Endpoint
############################################################

output "db_instance_endpoint" {
  description = "RDS Endpoint"
  value       = aws_db_instance.mysql.endpoint
}

############################################################
# Database Address
############################################################

output "db_instance_address" {
  description = "Database Hostname"
  value       = aws_db_instance.mysql.address
}

############################################################
# Database Port
############################################################

output "db_instance_port" {
  description = "Database Port"
  value       = aws_db_instance.mysql.port
}

############################################################
# Database Name
############################################################

output "db_name" {
  description = "Database Name"
  value       = aws_db_instance.mysql.db_name
}

############################################################
# Database Username
############################################################

output "db_username" {
  description = "Database Username"
  value       = aws_db_instance.mysql.username
}

############################################################
# Security Group
############################################################

output "rds_security_group_id" {
  description = "RDS Security Group ID"
  value       = aws_security_group.rds.id
}

############################################################
# Database ARN
############################################################

output "db_instance_arn" {
  description = "Database ARN"
  value       = aws_db_instance.mysql.arn
}