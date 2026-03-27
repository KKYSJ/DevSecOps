# This stack intentionally does not auto-declare the existing Web ACL yet.
# The generated CloudFormation export shows a live WAF Web ACL, but safely
# managing it in Terraform requires importing the current ACL and preserving
# its full rule set. The next step is to translate the exported WAF resource
# into HCL and then add import blocks in imports.tf before enabling ownership.
