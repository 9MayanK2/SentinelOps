# VPC Block
resource "aws_vpc" "main" {

  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-${var.environment}-vpc"
  }
}

# INternet Gateway Block
resource "aws_internet_gateway" "igw" {

  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.project_name}-${var.environment}-igw"
  }
}

#Public Subnet 1 Block
resource "aws_subnet" "public_subnet_1" {

  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_1_cidr
  availability_zone       = var.availability_zone_1
  map_public_ip_on_launch = true

  tags = {

    Name        = "${var.project_name}-public-1"
    Environment = var.environment
    Project     = var.project_name


    "kubernetes.io/role/elb" = "1"

    "kubernetes.io/cluster/${var.project_name}-${var.environment}-eks" = "shared"
  }
}

resource "aws_subnet" "public_subnet_2" {

  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_2_cidr
  availability_zone       = var.availability_zone_2
  map_public_ip_on_launch = true

  tags = {

    Name        = "${var.project_name}-public-2"
    Environment = var.environment
    Project     = var.project_name

    "kubernetes.io/role/elb" = "1"

    "kubernetes.io/cluster/${var.project_name}-${var.environment}-eks" = "shared"
  }
}

#Private Subnet 1 Block
resource "aws_subnet" "private_subnet_1" {

  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_1_cidr
  availability_zone = var.availability_zone_1

  tags = {

    Name        = "${var.project_name}-private-1"
    Environment = var.environment
    Project     = var.project_name

    "kubernetes.io/role/internal-elb" = "1"

    "kubernetes.io/cluster/${var.project_name}-${var.environment}-eks" = "shared"
  }
}

#Private Subnet 2 Block
resource "aws_subnet" "private_subnet_2" {

  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_2_cidr
  availability_zone = var.availability_zone_2

  tags = {
    Name        = "${var.project_name}-private-2"
    Environment = var.environment
    Project     = var.project_name

    "kubernetes.io/role/internal-elb" = "1"

    "kubernetes.io/cluster/${var.project_name}-${var.environment}-eks" = "shared"
  }
}

# Route Table Block
resource "aws_route_table" "public" {

  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.project_name}-${var.environment}-public-rt"
  }
}

# Route Table Association Block
resource "aws_route" "public_internet_access" {

  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

# Route Table Association Block
resource "aws_route_table_association" "public_subnet_1" {

  subnet_id      = aws_subnet.public_subnet_1.id
  route_table_id = aws_route_table.public.id
}

# Route Table Association Block
resource "aws_route_table_association" "public_subnet_2" {

  subnet_id      = aws_subnet.public_subnet_2.id
  route_table_id = aws_route_table.public.id
}

# Jenkins Security Group Block
resource "aws_security_group" "jenkins" {

  name        = "${var.project_name}-${var.environment}-jenkins-sg"
  description = "Security Group for Jenkins"
  vpc_id      = aws_vpc.main.id

  ingress {

    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {

    description = "Jenkins"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {

    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {

    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {

    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-jenkins-sg"
  }
}


####################################################
# Elastic IP for NAT Gateway
####################################################

resource "aws_eip" "nat" {

  domain = "vpc"
  tags = {
    Name = "${var.project_name}-${var.environment}-nat-eip"
  }
  depends_on = [
    aws_internet_gateway.igw
  ]
}

####################################################
# NAT Gateway
####################################################

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_subnet_1.id
  tags = {
    Name = "${var.project_name}-${var.environment}-nat"
  }
  depends_on = [
    aws_internet_gateway.igw
  ]
}

####################################################
# Private Route Table
####################################################

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.project_name}-${var.environment}-private-rt"
  }
}

####################################################
# Private Route
####################################################

resource "aws_route" "private_internet_access" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main.id
}

####################################################
# Private Subnet 1 Route Association
####################################################

resource "aws_route_table_association" "private_subnet_1" {
  subnet_id      = aws_subnet.private_subnet_1.id
  route_table_id = aws_route_table.private.id
}

####################################################
# Private Subnet 2 Route Association
####################################################

resource "aws_route_table_association" "private_subnet_2" {
  subnet_id      = aws_subnet.private_subnet_2.id
  route_table_id = aws_route_table.private.id
}
