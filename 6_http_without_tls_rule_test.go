package main

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_HTTP_Without_TLS(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "issue found",
			Content: `
				data "teste" "example" {
					url = "http://checkpoint-api.hashicorp.com/v1/check/terraform"
					request_headers = {
						Accept = "application/json"
					}
				}`,
			Expected: helper.Issues{
				{
					Rule:    NewHTTPWithoutTLSRule(),
					Message: "Resource has HTTP without TLS issue",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 13},
						End:      hcl.Pos{Line: 3, Column: 67},
					},
				},
			},
		},
	}

	rule := NewHTTPWithoutTLSRule()

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
