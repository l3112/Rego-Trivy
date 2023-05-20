# Rego-Trivy
Let's finagle with rego and get this Trivy policy up and running!

# End Goal
For the policy to stop buckets being made in an AWS account that do not fit a particular naming scheme.

# Error (5/16)
`ID002.rego:38: rego_unsafe_var_error: var aws_s3_bucket is unsafe`

# Update (5/20)
The code has been updated to no longer give errors, but it does not acknowledge what it should be (ie, if the bucket does not meet parameters, it doesn't see that in the report)

## This will probably not be the last error! I'm new at rego. Feel free to watch if you want to help further!
