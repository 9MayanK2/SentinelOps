############################################################
# Project
############################################################

variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

############################################################
# Networking
############################################################

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "allowed_security_group_ids" {
  type    = list(string)
  default = []
}

############################################################
# Database
############################################################

variable "db_name" {
  type    = string
  default = "sentinelops"
}

variable "db_username" {
  type    = string
  default = "admin"
}

variable "db_password" {
  type      = string
  sensitive = true
}

############################################################
# RDS Configuration
############################################################

variable "engine_version" {
  type    = string
  default = "8.0.43"
}

variable "instance_class" {
  type    = string
  default = "db.t3.micro"
}

variable "allocated_storage" {
  type    = number
  default = 20
}

variable "storage_encrypted" {
  type    = bool
  default = true
}

variable "backup_retention_period" {
  type    = number
  default = 0
}

variable "publicly_accessible" {
  type    = bool
  default = false
}

variable "multi_az" {
  type    = bool
  default = false
}

variable "deletion_protection" {
  type    = bool
  default = false
}

variable "apply_immediately" {
  type    = bool
  default = true
}