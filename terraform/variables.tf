variable "project_name" {
  description = "Project Name"
  type        = string
}

variable "environment" {
  description = "Environment Name"
  type        = string
}

variable "aws_region" {
  description = "AWS Region"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR Block"
  type        = string
}

variable "public_subnet_1_cidr" {
  description = "Public Subnet 1 CIDR"
  type        = string
}

variable "public_subnet_2_cidr" {
  description = "Public Subnet 2 CIDR"
  type        = string
}

variable "private_subnet_1_cidr" {
  description = "Private Subnet 1 CIDR"
  type        = string
}

variable "private_subnet_2_cidr" {
  description = "Private Subnet 2 CIDR"
  type        = string
}

variable "availability_zone_1" {
  description = "Availability Zone 1"
  type        = string
}

variable "availability_zone_2" {
  description = "Availability Zone 2"
  type        = string
}

variable "instance_type" {
  type = string
}

variable "key_name" {
  type = string
}

variable "eks_node_instance_type" {
  description = "EKS Node Group Instance Type"
  type        = string
  default     = "t3.medium"
}

variable "desired_size" {
  description = "Desired number of EKS worker nodes"
  type        = number
  default     = 2
}

variable "min_size" {
  description = "Minimum number of EKS worker nodes"
  type        = number
  default     = 1
}

variable "max_size" {
  description = "Maximum number of EKS worker nodes"
  type        = number
  default     = 3
}

variable "db_name" {
  description = "Database Name for RDS MySQL"
  type        = string
  default     = "devsecops"
}

variable "db_username" {
  description = "Database Master Username"
  type        = string
  default     = "admin"
}

variable "db_password" {
  description = "Database Master Password"
  type        = string
  sensitive   = true
}

variable "db_instance_class" {
  description = "RDS Instance Class"
  type        = string
  default     = "db.t3.micro"
}