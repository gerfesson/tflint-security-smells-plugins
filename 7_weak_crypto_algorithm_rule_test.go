package main

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_Crypto_Algorithm(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "issue found",
			Content: `
				resource "aws_db_instance" "default" {
					allocated_storage    = 10
					db_name              = "mydb"
					engine               = "mysql"
					engine_version       = "8.0"
					instance_class       = "db.t3.micro" #TODO: change instance class
					username             = aws_iam_user.default_user.name
					password             = "${md5("admin")}"
					vpc_security_group_ids = [aws_security_group.default_sg.id]
				}`,
			Expected: helper.Issues{
				{
					Rule:    NewWeakCryptoAlgorithmRule(),
					Message: "Resource has an weak cryptographic algorithm",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 9, Column: 32},
						End:      hcl.Pos{Line: 9, Column: 35},
					},
				},
			},
		},
	}

	rule := NewWeakCryptoAlgorithmRule()

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
