package main

import (
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// TerraformCommentSyntaxRule checks whether comments use the preferred syntax
type HTTPWithoutTLSRule struct {
	tflint.DefaultRule
}

// NewTerraformCommentSyntaxRule returns a new rule
func NewHTTPWithoutTLSRule() *HTTPWithoutTLSRule {
	return &HTTPWithoutTLSRule{}
}

// Name returns the rule name
func (r *HTTPWithoutTLSRule) Name() string {
	return "http_without_tls_rule"
}

// Enabled returns whether the rule is enabled by default
func (r *HTTPWithoutTLSRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *HTTPWithoutTLSRule) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *HTTPWithoutTLSRule) Link() string {
	return ""
}

// Check checks whether single line comments is used
func (r *HTTPWithoutTLSRule) Check(runner tflint.Runner) error {
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
		if err := r.checkHttpPattern(runner, name, file); err != nil {
			return err
		}
	}

	return nil
}

func (r *HTTPWithoutTLSRule) checkHttpPattern(runner tflint.Runner, filename string, file *hcl.File) error {
	if strings.HasSuffix(filename, ".json") {
		return nil
	}

	tokens, diags := hclsyntax.LexConfig(file.Bytes, filename, hcl.InitialPos)
	if diags.HasErrors() {
		return diags
	}

	for _, token := range tokens {
		if strings.ToLower(string(token.Bytes)) == "http" || strings.Contains(strings.ToLower(string(token.Bytes)), "http://") {
			if err := runner.EmitIssue(
				r,
				"Resource has HTTP without TLS issue",
				token.Range,
			); err != nil {
				return err
			}
		}
	}

	return nil
}
