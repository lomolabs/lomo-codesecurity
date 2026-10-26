resource "aws_security_group" "demo" {
  name = "vulnerable-demo"

  ingress {
    description = "world-open ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
