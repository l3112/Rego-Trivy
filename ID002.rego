# METADATA
# title: Deployment not allowed
# description: Deployments are not allowed because of some reasons.
# custom:
#   id: ID002
#   severity: LOW
#   input:
#     selector:
#     - type: terraform

package user.terraform.ID002
import future.keywords.if

# import data.lib.trivy

yes_bucket if { # if
	regex.match("ca.*", bucketName)
}

deny_bucket_creation if {
	input.request.operation == "CreateBucket"
	not startswith(input.parameters.bucketName, "ca_")
}

deny[msg] {
	input.kind == "CreateBucket"
	resource := input.parameters.bucketName[name]
	not startswith(input.parameters.bucketName, "ca_")
	msg = "should start "
}

