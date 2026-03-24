resource "aws_cloudfront_response_headers_policy" "security" {
  count = var.enable_cloudfront_https ? 1 : 0

  name = "${local.name}-security-headers"

  security_headers_config {
    content_type_options {
      override = true
    }

    frame_options {
      frame_option = "DENY"
      override     = true
    }

    referrer_policy {
      referrer_policy = "same-origin"
      override        = true
    }

    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = false
      preload                    = false
      override                   = true
    }

    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
  }
}

resource "aws_cloudfront_distribution" "app" {
  count = var.enable_cloudfront_https ? 1 : 0

  enabled         = true
  is_ipv6_enabled = true
  comment         = "${local.name} public HTTPS entrypoint"
  http_version    = "http2and3"
  price_class     = var.cloudfront_price_class
  web_acl_id      = try(aws_wafv2_web_acl.cloudfront[0].arn, null)

  origin {
    domain_name = aws_lb.main.dns_name
    origin_id   = "alb-${local.name}"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = var.acm_certificate_arn != null ? "https-only" : "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id           = "alb-${local.name}"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods             = ["GET", "HEAD", "OPTIONS"]
    compress                   = true
    default_ttl                = 0
    min_ttl                    = 0
    max_ttl                    = 0
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security[0].id

    forwarded_values {
      query_string = true
      headers      = ["*"]

      cookies {
        forward = "all"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1.2_2021"
  }

  tags = local.common_tags
}
