

resource "tls_private_key" "project_key" {
algorithm   = "RSA"
}

# Creating your key using terraform cmd

resource "aws_key_pair" "project" {
  key_name   = "project-key"
  public_key =  tls_private_key.project_key.public_key_openssh
}


# Creating Your Own Security Group Using Terraform

resource "aws_security_group" "sg_project" {
  name        = "sg_project"
  description = "Allow TLS"
  vpc_id      = "vpc-f7bfa29f"

  ingress {
    description = "TLS from VPC"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "TLS from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "TLS from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
 egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
 egress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_tls"
  }
}

provider "aws" {
  region = "ap-south-1"
}

resource "aws_instance"  "myproj" {
  ami         = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name	= aws_key_pair.project.key_name
  security_groups = ["sg_project"] 

 connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.project_key.private_key_pem
    host     = aws_instance.myproj.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd  php git -y",
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd",
    ]
  }

  tags = {
    Name = "projectOS"
  }
}


resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "oai for cloudfront"
}

# craeting S3 bucket
resource "aws_s3_bucket" "projectbucket" {
  bucket = "projectbucket5302.com"
  acl    = "public-read"

  tags = {
    Name = "My Project Bucket"
  }
}


locals {
  s3_origin_id = "myS3Origin"
}

# creating cloud front
resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.projectbucket.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Some comment"
  default_root_object = "index.html"

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  # Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = "PriceClass_All"

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB", "DE", "IN"]
    }
  }

  tags = {
    Environment = "production"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

#storing object in bucket
resource "aws_s3_bucket_object" "object" {
  acl = "public-read"
  depends_on = [aws_s3_bucket.projectbucket]
  bucket = "projectbucket5302.com"
  key    = "download.png"
  source = "download.png"
}

#creating ebs volume
resource "aws_ebs_volume" "project_vol" {

  availability_zone = aws_instance.myproj.availability_zone
  size              = 1

  tags = {
    Name = "project_vol"
  }
}

#volume attachment with ec2 instance
resource "aws_volume_attachment" "ebs_attach" {
  device_name = "/dev/sdd"
  volume_id   = aws_ebs_volume.project_vol.id
  instance_id = aws_instance.myproj.id
  force_detach = true
}

resource "null_resource" "cmd_save_public_ip"  {
	provisioner "local-exec" {
	    command = "echo  ${aws_instance.myproj.public_ip} > publicip.txt"
  	}
}

resource "null_resource" "cmd_for_mounting"  {

depends_on = [
    aws_volume_attachment.ebs_attach,
  ]


  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.project_key.private_key_pem
    host     = aws_instance.myproj.public_ip
  }

provisioner "remote-exec" {
    inline = [
      "sudo mkfs.ext4  /dev/xvdd",
      "sudo mount  /dev/xvdd   /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/akshat5302/cloudcomputing_task1.git  /var/www/html/"
    ]
  }
}

resource "null_resource" "cmd_for_chrome_site"  {


depends_on = [
    null_resource.cmd_for_mounting,
  ]

	provisioner "local-exec" {
	    command = "chrome  ${aws_instance.myproj.public_ip}"
  	}
}


