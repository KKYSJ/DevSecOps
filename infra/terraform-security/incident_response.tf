resource "aws_ssmincidents_response_plan" "basic" {
  count = var.enable_incident_response ? 1 : 0

  name         = var.incident_response_plan_name
  display_name = var.incident_response_plan_display_name

  incident_template {
    impact = var.incident_response_impact
    title  = "${local.name_prefix} incident"
  }
}
