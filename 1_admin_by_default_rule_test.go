package main

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AdminByDefault(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "issue found",
			Content: `
				resource "aws_iam_policy" "policy" {
					name        = "test_policy"
					path        = "/"
					description = "My test policy"

					# Terraform's "jsonencode" function converts a
					# Terraform expression result to valid JSON syntax.
					policy = jsonencode({
						Version = "2012-10-17"
						Statement = [
						{
							Action = [
							"ec2:Describe*",
							]
							Effect   = "Allow"
							Resource = "*"
						},
						]
					})
				}`,
			Expected: helper.Issues{
				{
					Rule:    NewAdminByDefaultRule(),
					Message: "Resource has an admin by default statement",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 14, Column: 9},
						End:      hcl.Pos{Line: 14, Column: 22},
					},
				},
				{
					Rule:    NewAdminByDefaultRule(),
					Message: "Resource has an admin by default statement",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 17, Column: 20},
						End:      hcl.Pos{Line: 17, Column: 21},
					},
				},
			},
		},
	}

	rule := NewAdminByDefaultRule()

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			runner := helper.TestRunner(t, map[string]string{"resource.tf": test.Content})

			if err := rule.Check(runner); err != nil {
				t.Fatalf("Unexpected error occurred: %s", err)
			}

			helper.AssertIssues(t, test.Expected, runner.Issues)
		})
	}
}
