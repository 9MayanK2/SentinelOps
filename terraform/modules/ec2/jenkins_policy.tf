resource "aws_iam_policy" "jenkins_eks_access" {

  name        = "${var.project_name}-${var.environment}-jenkins-eks-access"
  description = "Allow Jenkins to access EKS"

  policy = jsonencode({

    Version = "2012-10-17"

    Statement = [

      {
        Effect = "Allow"

        Action = [
          "eks:DescribeCluster",
          "eks:ListClusters"
        ]

        Resource = [
          "arn:aws:eks:${var.aws_region}:*:cluster/*"
        ]
      }

    ]

  })
}

resource "aws_iam_role_policy_attachment" "jenkins_eks_access" {

  role       = aws_iam_role.jenkins_role.name
  policy_arn = aws_iam_policy.jenkins_eks_access.arn

}