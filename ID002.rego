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
default allow := false

# import data.lib.trivy

yes_bucket if { # if
	regex.match("ca.*", bucketName)
}

deny_bucket_creation if {
	input.request.operation == "CreateBucket"
	not startswith(input.parameters.bucketName, "ca_")
}

eny[msg]  {
	input.kind == "CreateBucket"
	name := input.resource.aws_s3_bucket.name["ca_"] #I figured it out all by myself :D 
	resource := input.parameters.bucketName#[name]
	not startswith(name, "ca_")
	msg = sprintf("should start with %s", [name])
}

