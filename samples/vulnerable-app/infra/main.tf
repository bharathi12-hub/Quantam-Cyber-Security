# INTENTIONALLY VULNERABLE sample for QuantumShield demo.
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI_K7MDENG_bPxRfiCYEXAMPLEKEY"
}

resource "aws_db_instance" "default" {
  engine   = "postgres"
  username = "admin"
  password = "SuperSecretDbPassword123"
}

resource "tls_private_key" "legacy" {
  algorithm = "RSA"
  rsa_bits  = 1024
}
