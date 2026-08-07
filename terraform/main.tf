module "network" {

  source = "./modules/network"

  project_name = var.project_name
  environment  = var.environment

  vpc_cidr = var.vpc_cidr

  public_subnet_1_cidr = var.public_subnet_1_cidr
  public_subnet_2_cidr = var.public_subnet_2_cidr

  private_subnet_1_cidr = var.private_subnet_1_cidr
  private_subnet_2_cidr = var.private_subnet_2_cidr

  availability_zone_1 = var.availability_zone_1
  availability_zone_2 = var.availability_zone_2
}


module "ec2" {

  source = "./modules/ec2"

  project_name = var.project_name
  environment  = var.environment
  aws_region   = var.aws_region

  ami_id        = data.aws_ami.ubuntu.id
  instance_type = var.instance_type

  public_subnet_id  = module.network.public_subnet_1_id
  security_group_id = module.network.jenkins_security_group_id

  key_name = var.key_name

}

module "ecr" {

  source = "./modules/ecr"

  project_name = var.project_name
  environment  = var.environment

}

module "eks" {

  source = "./modules/eks"

  project_name = var.project_name
  environment  = var.environment

  vpc_id = module.network.vpc_id

  private_subnet_ids = [
    module.network.private_subnet_1_id,
    module.network.private_subnet_2_id
  ]

  instance_type = var.eks_node_instance_type

  desired_size = var.desired_size
  min_size     = var.min_size
  max_size     = var.max_size
}

module "rds" {
  source = "./modules/rds"

  project_name = var.project_name
  environment  = var.environment

  vpc_id = module.network.vpc_id

  subnet_ids = [
    module.network.private_subnet_1_id,
    module.network.private_subnet_2_id
  ]

  allowed_security_group_ids = [
    module.network.jenkins_security_group_id
  ]

  db_name        = var.db_name
  db_username    = var.db_username
  db_password    = var.db_password
  instance_class = var.db_instance_class
}
