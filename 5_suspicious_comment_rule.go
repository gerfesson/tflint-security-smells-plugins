package main

import (
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// TerraformCommentSyntaxRule checks whether comments use the preferred syntax
type SuspiciousCommentRule struct {
	tflint.DefaultRule
}

// NewTerraformCommentSyntaxRule returns a new rule
func NewSuspiciousCommentRule() *SuspiciousCommentRule {
	return &SuspiciousCommentRule{}
}

// Name returns the rule name
func (r *SuspiciousCommentRule) Name() string {
	return "suspicious_comment_rule"
}

// Enabled returns whether the rule is enabled by default
func (r *SuspiciousCommentRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *SuspiciousCommentRule) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *SuspiciousCommentRule) Link() string {
	return ""
}

// Check checks whether single line comments is used
func (r *SuspiciousCommentRule) Check(runner tflint.Runner) error {
	path, err := runner.GetModulePath()
	if err != nil {
		return err
	}
	if !path.IsRoot() {
		// This rule does not evaluate child modules.
		return nil
	}

	files, err := runner.GetFiles()
	if err != nil {
		return err
	}
	for name, file := range files {
		if err := r.checkComments(runner, name, file); err != nil {
			return err
		}
	}

	return nil
}

func (r *SuspiciousCommentRule) checkComments(runner tflint.Runner, filename string, file *hcl.File) error {
	if strings.HasSuffix(filename, ".json") {
		return nil
	}

	tokens, diags := hclsyntax.LexConfig(file.Bytes, filename, hcl.InitialPos)
	if diags.HasErrors() {
		return diags
	}

	suspiciousKeywords := []string{"TODO", "FIXME", "TO-DO", "FIX-ME", "TBD"}

	for _, token := range tokens {
		if token.Type != hclsyntax.TokenComment {
			continue
		}

		if strings.HasPrefix(string(token.Bytes), "//") || strings.HasPrefix(string(token.Bytes), "/*") || strings.HasPrefix(string(token.Bytes), "#") {
			for _, keyword := range suspiciousKeywords {
				if strings.Contains(strings.ToLower(string(token.Bytes)), strings.ToLower(keyword)) {
					if err := runner.EmitIssue(
						r,
						"Resource has an suspicious comment",
						token.Range,
					); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}
