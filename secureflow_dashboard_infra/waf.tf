locals {
  actions_upload_bypass_header_name  = "x-secureflow-upload-key"
  actions_upload_bypass_header_value = trimspace(coalesce(var.actions_upload_bypass_key, ""))
  actions_upload_bypass_enabled      = trimspace(nonsensitive(coalesce(var.actions_upload_bypass_key, ""))) != ""
}

resource "aws_wafv2_web_acl" "alb" {
  count = var.enable_waf ? 1 : 0

  name  = "${local.name}-alb-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "rate-limit"
    priority = 10

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  dynamic "rule" {
    for_each = local.actions_upload_bypass_enabled ? [1] : []

    content {
      name     = "github-actions-upload-bypass"
      priority = 1

      action {
        allow {}
      }

      statement {
        and_statement {
          statement {
            byte_match_statement {
              field_to_match {
                single_header {
                  name = local.actions_upload_bypass_header_name
                }
              }

              positional_constraint = "EXACTLY"
              search_string         = local.actions_upload_bypass_header_value

              text_transformation {
                priority = 0
                type     = "NONE"
              }
            }
          }

          statement {
            or_statement {
              statement {
                byte_match_statement {
                  field_to_match {
                    uri_path {}
                  }

                  positional_constraint = "STARTS_WITH"
                  search_string         = "/api/v1/scans"

                  text_transformation {
                    priority = 0
                    type     = "NONE"
                  }
                }
              }

              statement {
                byte_match_statement {
                  field_to_match {
                    uri_path {}
                  }

                  positional_constraint = "STARTS_WITH"
                  search_string         = "/api/v1/isms"

                  text_transformation {
                    priority = 0
                    type     = "NONE"
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-upload-bypass"
        sampled_requests_enabled   = true
      }
    }
  }

  rule {
    name     = "aws-common"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-known-bad-inputs"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-sqli"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-sqli"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-ip-reputation"
    priority = 40

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-anonymous-ip"
    priority = 50

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAnonymousIpList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-anonymous-ip"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-web-acl"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  count = var.enable_waf ? 1 : 0

  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.alb[0].arn
}

resource "aws_wafv2_web_acl_logging_configuration" "alb" {
  count = var.enable_waf ? 1 : 0

  resource_arn            = aws_wafv2_web_acl.alb[0].arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
}

resource "aws_wafv2_web_acl" "cloudfront" {
  count    = var.enable_waf && var.enable_cloudfront_https ? 1 : 0
  provider = aws.us_east_1

  name  = "${local.name}-cloudfront-waf"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "rate-limit"
    priority = 10

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-cloudfront-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  dynamic "rule" {
    for_each = local.actions_upload_bypass_enabled ? [1] : []

    content {
      name     = "github-actions-upload-bypass"
      priority = 1

      action {
        allow {}
      }

      statement {
        and_statement {
          statement {
            byte_match_statement {
              field_to_match {
                single_header {
                  name = local.actions_upload_bypass_header_name
                }
              }

              positional_constraint = "EXACTLY"
              search_string         = local.actions_upload_bypass_header_value

              text_transformation {
                priority = 0
                type     = "NONE"
              }
            }
          }

          statement {
            or_statement {
              statement {
                byte_match_statement {
                  field_to_match {
                    uri_path {}
                  }

                  positional_constraint = "STARTS_WITH"
                  search_string         = "/api/v1/scans"

                  text_transformation {
                    priority = 0
                    type     = "NONE"
                  }
                }
              }

              statement {
                byte_match_statement {
                  field_to_match {
                    uri_path {}
                  }

                  positional_constraint = "STARTS_WITH"
                  search_string         = "/api/v1/isms"

                  text_transformation {
                    priority = 0
                    type     = "NONE"
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-cloudfront-upload-bypass"
        sampled_requests_enabled   = true
      }
    }
  }

  rule {
    name     = "aws-common"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-cloudfront-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-known-bad-inputs"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-cloudfront-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-sqli"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-cloudfront-sqli"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-ip-reputation"
    priority = 40

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-cloudfront-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-anonymous-ip"
    priority = 50

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAnonymousIpList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-cloudfront-anonymous-ip"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-cloudfront-web-acl"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_logging_configuration" "cloudfront" {
  count    = var.enable_waf && var.enable_cloudfront_https ? 1 : 0
  provider = aws.us_east_1

  resource_arn            = aws_wafv2_web_acl.cloudfront[0].arn
  log_destination_configs = [aws_cloudwatch_log_group.waf_cloudfront[0].arn]
}
