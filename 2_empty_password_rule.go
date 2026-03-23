package main

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

type EmptyPasswordRule struct {
	tflint.DefaultRule
}

func NewEmptyPasswordRule() *EmptyPasswordRule {
	return &EmptyPasswordRule{}
}

func (r *EmptyPasswordRule) Name() string {
	return "aws_empty_password_rule"
}

func (r *EmptyPasswordRule) Enabled() bool {
	return true
}

func (r *EmptyPasswordRule) Severity() tflint.Severity {
	return tflint.WARNING
}

func (r *EmptyPasswordRule) Link() string {
	return "Documentation link here"
}

func (r *EmptyPasswordRule) Check(runner tflint.Runner) error {
	// Define the schema to look for password attributes
	schema := &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: "password"},        //RDS, IAM User
			{Name: "master_password"}, //Redshift, DocumentDB
			{Name: "auth_token"},      //Elasticache
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
						if value == "" {
							return runner.EmitIssue(
								r,
								"Resource has an empty password attribute",
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
