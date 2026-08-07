resource "aws_iam_role" "jenkins_role" {

  name = "${var.project_name}-${var.environment}-jenkins-role"

  assume_role_policy = jsonencode({

    Version = "2012-10-17"

    Statement = [

      {

        Effect = "Allow"

        Principal = {
          Service = "ec2.amazonaws.com"
        }

        Action = "sts:AssumeRole"

      }

    ]

  })

}

resource "aws_iam_role_policy_attachment" "ssm" {

  role = aws_iam_role.jenkins_role.name

  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

}

####################################################
# Amazon ECR Access
####################################################

resource "aws_iam_role_policy_attachment" "ecr_power_user" {

  role = aws_iam_role.jenkins_role.name

  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser"

}

####################################################
# Amazon EKS Access
####################################################

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {

  role = aws_iam_role.jenkins_role.name

  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"

}

####################################################
# EKS kubectl Access
####################################################

resource "aws_iam_role_policy_attachment" "eks_service_policy" {

  role = aws_iam_role.jenkins_role.name

  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"

}

resource "aws_iam_instance_profile" "jenkins_profile" {

  name = "${var.project_name}-${var.environment}-instance-profile"

  role = aws_iam_role.jenkins_role.name

}

resource "aws_instance" "jenkins" {

  ami = var.ami_id

  instance_type = var.instance_type

  subnet_id = var.public_subnet_id

  vpc_security_group_ids = [
    var.security_group_id
  ]

  iam_instance_profile = aws_iam_instance_profile.jenkins_profile.name

  key_name = var.key_name

  associate_public_ip_address = true

  monitoring = true

  ebs_optimized = true

  root_block_device {

    volume_size = 30

    volume_type = "gp3"

    encrypted = true

    delete_on_termination = true

  }

  metadata_options {

    http_endpoint = "enabled"

    http_tokens = "required"

  }

  tags = {

    Name = "${var.project_name}-${var.environment}-jenkins"

  }

}