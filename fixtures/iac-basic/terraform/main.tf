resource "aws_s3_bucket" "logs" {
  bucket = "example-logs-bucket"
}

module "local" {
  source = "./modules/bucket"
}

module "reg" {
  source = "terraform-aws-modules/s3-bucket/aws"
}

module "git" {
  source = "git@github.com:example/mod.git"
}
