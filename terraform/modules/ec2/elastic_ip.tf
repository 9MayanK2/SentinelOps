resource "aws_eip" "jenkins" {

  domain = "vpc"

  instance = aws_instance.jenkins.id

  tags = {
    Name = "${var.project_name}-${var.environment}-jenkins-eip"
  }

}