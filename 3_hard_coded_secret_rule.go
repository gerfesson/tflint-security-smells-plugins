package main

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

type HardCodedSecretRule struct {
	tflint.DefaultRule
}

func NewHardCodedSecretRule() *HardCodedSecretRule {
	return &HardCodedSecretRule{}
}

func (r *HardCodedSecretRule) Name() string {
	return "hard_coded_secret_rule"
}

func (r *HardCodedSecretRule) Enabled() bool {
	return true
}

func (r *HardCodedSecretRule) Severity() tflint.Severity {
	return tflint.WARNING
}

func (r *HardCodedSecretRule) Link() string {
	return "Documentation link here"
}

func (r *HardCodedSecretRule) Check(runner tflint.Runner) error {
	// Define the schema to look for password attributes
	schema := &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: "user"}, {Name: "uname"}, {Name: "username"}, {Name: "login"}, {Name: "userid"}, {Name: "loginid"},
			{Name: "pass"}, {Name: "pwd"}, {Name: "password"}, {Name: "passwd"}, {Name: "passno"}, {Name: "pass-no"},
			{Name: "auth_token"}, {Name: "authentication_token"}, {Name: "secret"}, {Name: "ssh_key"},
		},
	}

	schema2 := &hclext.BodySchema{
		Blocks: []hclext.BlockSchema{
			{
				Type:       "resource",
				LabelNames: []string{"type", "name"}, // resource "TYPE" "NAME"
			},
		},
	}

	moduleContent, err := runner.GetModuleContent(schema2, nil)
	if err != nil {
		return err
	}

	for _, block := range moduleContent.Blocks {
		if block.Type == "resource" && len(block.Labels) == 2 {
			fmt.Printf("Found resource: %s.%s\n", block.Labels[0], block.Labels[1])
			// Get all resources in the Terraform file
			resources, err := runner.GetResourceContent(block.Labels[0], schema, nil)
			if err != nil {
				return err
			}

			// Iterate over each resource and check for empty password attributes
			for _, resource := range resources.Blocks {
				for _, attrName := range resource.Body.Attributes {

					err := runner.EvaluateExpr(attrName.Expr, func(value string) error {
						if len(value) > 0 {
							return runner.EmitIssue(
								r,
								"Resource has an hard coded secret attribute",
								attrName.Expr.Range(),
							)
						}
						return nil
					}, nil)

					if err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}
