############################################################
# RDS Subnet Group
############################################################

resource "aws_db_subnet_group" "rds" {

  name        = "${var.project_name}-${var.environment}-rds-subnet-group"
  description = "Private subnet group for SentinelOps RDS"

  subnet_ids = var.subnet_ids

  tags = {
    Name        = "${var.project_name}-${var.environment}-rds-subnet-group"
    Project     = var.project_name
    Environment = var.environment
  }
}

############################################################
# RDS Security Group
############################################################

resource "aws_security_group" "rds" {

  name        = "${var.project_name}-${var.environment}-rds-sg"
  description = "Security Group for SentinelOps MySQL"
  vpc_id      = var.vpc_id

  ingress {

    description = "Allow MySQL"

    from_port = 3306
    to_port   = 3306
    protocol  = "tcp"

    security_groups = var.allowed_security_group_ids
  }

  egress {

    from_port = 0
    to_port   = 0
    protocol  = "-1"

    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {

    Name        = "${var.project_name}-${var.environment}-rds-sg"
    Project     = var.project_name
    Environment = var.environment
  }
}

############################################################
# MySQL Database
############################################################

resource "aws_db_instance" "mysql" {

  identifier = "${var.project_name}-${var.environment}-mysql"

  engine         = "mysql"
  engine_version = var.engine_version

  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  max_allocated_storage = 100

  storage_type      = "gp3"
  storage_encrypted = var.storage_encrypted

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  port = 3306

  db_subnet_group_name   = aws_db_subnet_group.rds.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  publicly_accessible = var.publicly_accessible

  backup_retention_period = var.backup_retention_period

  maintenance_window = "Sun:04:00-Sun:05:00"

  deletion_protection = var.deletion_protection

  multi_az = var.multi_az

  apply_immediately = var.apply_immediately

  monitoring_interval = 0

  performance_insights_enabled = false

  iam_database_authentication_enabled = false

  skip_final_snapshot = true

  tags = {

    Name        = "${var.project_name}-${var.environment}-mysql"
    Project     = var.project_name
    Environment = var.environment
  }
}