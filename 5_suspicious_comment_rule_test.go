package main

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_Suspicious_Comment(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "issue found",
			Content: `
				resource "aws_iam_user_login_profile" "example" {
				user    = aws_iam_user.example.name
				password = "teste" //TODO
				}`,
			Expected: helper.Issues{
				{
					Rule:    NewSuspiciousCommentRule(),
					Message: "Resource has an suspicious comment",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 4, Column: 24},
						End:      hcl.Pos{Line: 5, Column: 1},
					},
				},
			},
		},
	}

	rule := NewSuspiciousCommentRule()

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
