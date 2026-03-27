# Import examples for existing security resources.
# Uncomment and fill the real IDs only when you are ready to let this stack
# become the owner of those resources.

# Existing Security Hub account is already enabled in the target region.
#
# import {
#   to = aws_securityhub_account.main[0]
#   id = "<account-id>"
# }
#
# import {
#   to = aws_securityhub_standards_subscription.fsbp[0]
#   id = "<securityhub-standards-subscription-arn>"
# }

# Existing GuardDuty detector discovered in the target region.
#
# import {
#   to = aws_guardduty_detector.main[0]
#   id = "<guardduty-detector-id>"
# }

# Existing AWS Config resources discovered in the target region:
# - Recorder name: default
# - Delivery channel name: default
# - Recorder role ARN: <config-recorder-role-arn>
#
# import {
#   to = aws_config_configuration_recorder.main[0]
#   id = "default"
# }
#
# import {
#   to = aws_config_delivery_channel.main[0]
#   id = "default"
# }
#
# import {
#   to = aws_config_configuration_recorder_status.main[0]
#   id = "default"
# }

# Existing VPC Flow Log discovered in the target environment:
# - VPC:       <vpc-id>
# - Flow log:  <flow-log-id>
# - Log group: <flow-log-group-name>
# - Role ARN:  <flow-log-role-arn>
#
# import {
#   to = aws_flow_log.vpc["<vpc-id>"]
#   id = "<flow-log-id>"
# }

# Existing ECR registry scanning configuration discovered in the target region:
# - Registry ID: <account-id>
# - Scan type:   ENHANCED
# - Rule:        CONTINUOUS_SCAN on *
#
# import {
#   to = aws_ecr_registry_scanning_configuration.main[0]
#   id = "<account-id>"
# }

# Existing WAF import should be added only after the full Web ACL rule set has
# been translated into HCL in waf.tf.

# import {
#   to = aws_wafv2_web_acl.main[0]
#   id = "<web-acl-id>/<web-acl-name>/REGIONAL"
# }
