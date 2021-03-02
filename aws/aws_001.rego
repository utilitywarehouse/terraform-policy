package main

# aws_001
#
# Ensure that every aws_s3_bucket has an aws_s3_bucket_public_access_block
# defined

s3_bucket_has_public_access_block(resource_name, attributes) {
  input[_].contents.resource.aws_s3_bucket_public_access_block[_].bucket == attributes.bucket
}

s3_bucket_has_public_access_block(resource_name, attributes) {
  input[_].contents.resource.aws_s3_bucket_public_access_block[_].bucket == sprintf("${aws_s3_bucket.%s.id}", [resource_name])
}

s3_bucket_has_public_access_block(resource_name, attributes) {
  input[_].contents.resource.aws_s3_bucket_public_access_block[_].bucket == sprintf("${aws_s3_bucket.%s.bucket}", [resource_name])
}

deny_aws_001[msg] {
  path := input[file].path
  attributes := input[file].contents.resource.aws_s3_bucket[resource_name]

  not s3_bucket_has_public_access_block(resource_name, attributes)

  msg = sprintf("%s - %s: aws_s3_bucket.%s does not have a corresponding aws_s3_bucket_public_access_block", ["aws_001", path, resource_name])
}
