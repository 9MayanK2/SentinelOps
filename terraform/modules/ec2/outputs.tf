output "instance_id" {
  value = aws_instance.jenkins.id
}

output "public_ip" {
  value = aws_eip.jenkins.public_ip
}

output "public_dns" {
  value = aws_instance.jenkins.public_dns
}