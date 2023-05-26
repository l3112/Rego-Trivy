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

# import data.lib.trivy


# Use this one in that open Rego policy checker.

# This is an example for a Rego rule. The value inside the brackets [array.id] is returned if the rule evaluates to be true.
# Portions of the code below in the comments were created by Eric J. Kao on Styra Academy
#  regex.match("company_name.*", bucket_name)

## it may say 'has no terraform config files' in a directory, even if there are.
## drag a .tf file into the directory it's looking in
## I don't get it either but alas.

default allow = false
#may need to be removed

makeBucket if {input.parameters.bucketName == "ca_"} 

deny[res] {
    input.kind == "Deployment"
    msg := sprintf("Found deployment '%s' but deployments are not allowed", [input.metadata.name])
    res := result.new(msg, input.kind)
    }

deny_bucket_creation {
    input.request.operation == "CreateBucket"
    not startswith(input.parameters.bucketName, "ca_")
}
