package main

import (
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// InsecureSecurityGroupRule verifica se há security groups com regras inseguras
type InsecureSecurityGroupRule struct {
	tflint.DefaultRule
}

func NewInsecureSecurityGroupRule() *InsecureSecurityGroupRule {
	return &InsecureSecurityGroupRule{}
}

func (r *InsecureSecurityGroupRule) Name() string {
	return "aws_security_group_insecure_rule"
}

func (r *InsecureSecurityGroupRule) Enabled() bool {
	return true
}

func (r *InsecureSecurityGroupRule) Severity() tflint.Severity {
	return tflint.WARNING
}

func (r *InsecureSecurityGroupRule) Link() string {
	return "Documentation link here"
}

func (r *InsecureSecurityGroupRule) Check(runner tflint.Runner) error {
	// This rule is an example to get a top-level resource attribute.
	resources, err := runner.GetResourceContent("aws_security_group_rule", &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: "cidr_blocks"},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		attribute, exists := resource.Body.Attributes["cidr_blocks"]
		if !exists {
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(value []string) error {
			for _, val := range value {
				if val == "0.0.0.0/0" || val == "0.0.0.0" {
					return runner.EmitIssue(
						r,
						"Security group rule allows ingress from any IP",
						attribute.Expr.Range())
				} else {
					return nil
				}
			}
			return nil
		}, nil)
		if err != nil {
			return err
		}
	}

	return nil
}
