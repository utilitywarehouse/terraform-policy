package main

test_aws_001 {
  results := deny_aws_001 with input as [
    {
      "path": "aws/dev/module/bucket.tf",
      "contents": {"resource": {
        "aws_s3_bucket": {
          "foobar": {"bucket": "foobar-bucket"},
          "barfoo": {"bucket": "${var.barfoo}"},
          "boofar": {"bucket": "boofar-bucket"},
          # this bucket doesn't have a public access block and
          # therefore violates the policy
          "farboo": {"bucket": "farboo-bucket"},
        },
        "aws_s3_bucket_public_access_block": {
          "foobar": {"bucket": "${aws_s3_bucket.foobar.id}"},
          "barfoo": {"bucket": "${var.barfoo}"},
        },
      }},
    },
    {
      # Ensure that the policy finds the public access block in another file
      "path": "aws/dev/module/another-file.tf",
      "contents": {"resource": {"aws_s3_bucket_public_access_block": {"boofar": {"bucket": "${aws_s3_bucket.boofar.bucket}"}}}},
    },
  ]

  count(results) == 1
}
