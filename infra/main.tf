# INTENTIONALLY VULNERABLE: for IaC scanner validation only.
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAFAKEEXAMPLEKEY"
  secret_key = "fakeSecretForScannerOnly"
}

resource "aws_s3_bucket" "public_bucket" {
  bucket = "vuln-public-bucket-example"
  acl    = "public-read"
}

resource "aws_security_group" "open_sg" {
  name = "allow_all_inbound"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
