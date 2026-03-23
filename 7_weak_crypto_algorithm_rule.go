package main

import (
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// TerraformCommentSyntaxRule checks whether comments use the preferred syntax
type WeakCryptoAlgorithmRule struct {
	tflint.DefaultRule
}

// NewTerraformCommentSyntaxRule returns a new rule
func NewWeakCryptoAlgorithmRule() *WeakCryptoAlgorithmRule {
	return &WeakCryptoAlgorithmRule{}
}

// Name returns the rule name
func (r *WeakCryptoAlgorithmRule) Name() string {
	return "weak_crypto_algorithm_rule"
}

// Enabled returns whether the rule is enabled by default
func (r *WeakCryptoAlgorithmRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *WeakCryptoAlgorithmRule) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *WeakCryptoAlgorithmRule) Link() string {
	return ""
}

// Check checks whether single line comments is used
func (r *WeakCryptoAlgorithmRule) Check(runner tflint.Runner) error {
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
		if err := r.checkWeakCryptoPattern(runner, name, file); err != nil {
			return err
		}
	}

	return nil
}

func (r *WeakCryptoAlgorithmRule) checkWeakCryptoPattern(runner tflint.Runner, filename string, file *hcl.File) error {
	if strings.HasSuffix(filename, ".json") {
		return nil
	}

	tokens, diags := hclsyntax.LexConfig(file.Bytes, filename, hcl.InitialPos)
	if diags.HasErrors() {
		return diags
	}

	labels := []string{"md5", "sha1", "arcfour"}

	for _, token := range tokens {
		for _, label := range labels {
			if strings.Contains(strings.ToLower(string(token.Bytes)), strings.ToLower(label)) {
				if err := runner.EmitIssue(
					r,
					"Resource has an weak cryptographic algorithm",
					token.Range,
				); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
