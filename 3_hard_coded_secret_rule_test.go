package main

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_HardCodedSecret(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "issue found",
			Content: `
				resource "aws_iam_user_login_profile" "example" {
					user    = "teste"
				}`,
			Expected: helper.Issues{
				{
					Rule:    NewHardCodedSecretRule(),
					Message: "Resource has an hard coded secret attribute",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 16},
						End:      hcl.Pos{Line: 3, Column: 23},
					},
				},
			},
		},
	}

	rule := NewHardCodedSecretRule()

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
