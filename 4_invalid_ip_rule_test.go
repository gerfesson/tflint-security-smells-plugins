package main

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_CidrExampleType(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "issue found",
			Content: `
				resource "aws_security_group_rule" "example" {
				type              = "ingress"
				from_port         = 0
				to_port           = 65535
				protocol          = "tcp"
				cidr_blocks       = ["0.0.0.0/0"]
				ipv6_cidr_blocks  = []
				security_group_id = "sg-123456"
				}`,
			Expected: helper.Issues{
				{
					Rule:    NewInsecureSecurityGroupRule(),
					Message: "Security group rule allows ingress from any IP",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 7, Column: 25},
						End:      hcl.Pos{Line: 7, Column: 38},
					},
				},
			},
		},
	}

	rule := NewInsecureSecurityGroupRule()

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
