data "aws_ami" "ubuntu" {

  most_recent = true

  owners = ["099720109477"]

  filter {
    name = "name"

    values = [
      "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
    ]
  }

  filter {

    name = "virtualization-type"

    values = ["hvm"]

  }

}

####################################################
# Current AWS Account
####################################################

data "aws_caller_identity" "current" {}

####################################################
# EKS Cluster
####################################################

data "aws_eks_cluster" "eks" {
  name = module.eks.cluster_name
}

####################################################
# EKS Authentication
####################################################

data "aws_eks_cluster_auth" "eks" {
  name = module.eks.cluster_name
}

####################################################
# OIDC Provider
####################################################

data "tls_certificate" "eks" {
  url = data.aws_eks_cluster.eks.identity[0].oidc[0].issuer
}