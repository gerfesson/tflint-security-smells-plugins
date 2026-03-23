package main

import (
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	"github.com/zclconf/go-cty/cty"
)

// TerraformCommentSyntaxRule checks whether comments use the preferred syntax
type AdminByDefaultRule struct {
	tflint.DefaultRule
}

// NewTerraformCommentSyntaxRule returns a new rule
func NewAdminByDefaultRule() *AdminByDefaultRule {
	return &AdminByDefaultRule{}
}

// Name returns the rule name
func (r *AdminByDefaultRule) Name() string {
	return "admin_by_default_rule"
}

// Enabled returns whether the rule is enabled by default
func (r *AdminByDefaultRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AdminByDefaultRule) Severity() tflint.Severity {
	return tflint.WARNING
}

// Link returns the rule reference link
func (r *AdminByDefaultRule) Link() string {
	return ""
}

var schema2 *hclext.BodySchema = &hclext.BodySchema{
	Blocks: []hclext.BlockSchema{
		{
			Type:       "resource",
			LabelNames: []string{"type", "name"}, // resource "TYPE" "NAME",
			Body: &hclext.BodySchema{
				Attributes: []hclext.AttributeSchema{
					{Name: "policy"},
				},
			},
		},
	},
}

// Check if admin by default is defined
func (r *AdminByDefaultRule) Check(runner tflint.Runner) error {

	body, err := runner.GetModuleContent(schema2, &tflint.GetModuleContentOption{ExpandMode: tflint.ExpandModeNone})
	if err != nil {
		return err
	}

	for _, resource := range body.Blocks {
		// inspect attributes at resource level
		for _, attr := range resource.Body.Attributes {
			if _, ok := attrNames[strings.ToLower(attr.Name)]; ok {
				if err := r.inspectExprForWildcard(runner, attr.Expr, attr.Expr.Range()); err != nil {
					return err
				}
			} else {
				if err := r.findKeysInExpr(runner, attr.Expr); err != nil {
					return err
				}
			}
		}

		// recurse into nested blocks of the resource
		if err := r.traverseBlocks(runner, resource.Body.Blocks); err != nil {
			return err
		}
	}

	return nil
}

// helper: attribute names of interest
var attrNames = map[string]struct{}{
	"actions":     {},
	"action":      {},
	"permissions": {},
	"resources":   {},
	"resource":    {},
}

// traverseBlocks walks blocks recursively and inspects attributes and nested objects
func (r *AdminByDefaultRule) traverseBlocks(runner tflint.Runner, blocks []*hclext.Block) error {
	for _, b := range blocks {
		for _, attr := range b.Body.Attributes {
			if _, ok := attrNames[strings.ToLower(attr.Name)]; ok {
				if err := r.inspectExprForWildcard(runner, attr.Expr, attr.Expr.Range()); err != nil {
					return err
				}
			} else {
				if err := r.findKeysInExpr(runner, attr.Expr); err != nil {
					return err
				}
			}
		}
		if len(b.Body.Blocks) > 0 {
			if err := r.traverseBlocks(runner, b.Body.Blocks); err != nil {
				return err
			}
		}
	}
	return nil
}

// findKeysInExpr looks for object keys that match interest names inside arbitrary expressions
func (r *AdminByDefaultRule) findKeysInExpr(runner tflint.Runner, expr hcl.Expression) error {
	switch e := expr.(type) {
	case *hclsyntax.ObjectConsExpr:
		for _, item := range e.Items {
			key := literalKey(item.KeyExpr)
			if key != "" {
				if _, ok := attrNames[strings.ToLower(key)]; ok {
					if err := r.inspectExprForWildcard(runner, item.ValueExpr, item.ValueExpr.Range()); err != nil {
						return err
					}
				}
			}
			// recurse into value
			if err := r.findKeysInExpr(runner, item.ValueExpr); err != nil {
				return err
			}
		}
	case *hclsyntax.TupleConsExpr:
		for _, ex := range e.Exprs {
			if err := r.findKeysInExpr(runner, ex); err != nil {
				return err
			}
		}
	case *hclsyntax.FunctionCallExpr:
		for _, arg := range e.Args {
			if err := r.findKeysInExpr(runner, arg); err != nil {
				return err
			}
		}
	case *hclsyntax.TemplateExpr:
		for _, p := range e.Parts {
			if err := r.findKeysInExpr(runner, p); err != nil {
				return err
			}
		}
	}
	return nil
}

// inspectExprForWildcard inspects many expression types for "*" or provider-scoped wildcards like "s3:*"
func (r *AdminByDefaultRule) inspectExprForWildcard(runner tflint.Runner, expr hcl.Expression, rng hcl.Range) error {
	switch e := expr.(type) {
	case *hclsyntax.LiteralValueExpr:
		if e.Val.Type() == cty.String {
			v := e.Val.AsString()
			if isWildcard(v) {
				return runner.EmitIssue(
					r,
					"Resource has an admin by default statement",
					rng,
				)
			}
		}
	case *hclsyntax.TupleConsExpr:
		for _, ex := range e.Exprs {
			if err := r.inspectExprForWildcard(runner, ex, rng); err != nil {
				return err
			}
		}
	case *hclsyntax.ObjectConsExpr:
		for _, item := range e.Items {
			if err := r.inspectExprForWildcard(runner, item.ValueExpr, item.ValueExpr.Range()); err != nil {
				return err
			}
		}
	case *hclsyntax.FunctionCallExpr:
		for _, arg := range e.Args {
			if err := r.inspectExprForWildcard(runner, arg, arg.Range()); err != nil {
				return err
			}
		}
	case *hclsyntax.TemplateExpr:
		for _, p := range e.Parts {
			if err := r.inspectExprForWildcard(runner, p, p.Range()); err != nil {
				return err
			}
		}
	default:
		// fallback: evaluate as string (useful for jsonencode(...) or expressions)
		if err := runner.EvaluateExpr(expr, func(value string) error {
			v := strings.TrimSpace(value)
			v = strings.Trim(v, `"`)
			if isWildcard(v) {
				return runner.EmitIssue(r, "Resource has an admin by default statement", rng)
			}
			return nil
		}, nil); err != nil {
			return err
		}
	}
	return nil
}

func literalKey(expr hcl.Expression) string {
	// try literal string key and simple template literal containing a single string part
	if lit, ok := expr.(*hclsyntax.LiteralValueExpr); ok && lit.Val.Type() == cty.String {
		return lit.Val.AsString()
	}
	if tmpl, ok := expr.(*hclsyntax.TemplateExpr); ok && len(tmpl.Parts) == 1 {
		if lit, ok := tmpl.Parts[0].(*hclsyntax.LiteralValueExpr); ok && lit.Val.Type() == cty.String {
			return lit.Val.AsString()
		}
	}
	// handle direct traversal expressions like foo.bar or aws_iam_role["name"]
	if tr, ok := expr.(*hclsyntax.ScopeTraversalExpr); ok {
		return traversalLastKey(tr.Traversal)
	}

	//FUNCIONANDO
	if tr, ok := expr.(*hclsyntax.ObjectConsKeyExpr).Wrapped.(*hclsyntax.ScopeTraversalExpr); ok {
		return traversalLastKey(tr.Traversal)
	}
	return ""
}

func traversalLastKey(tr hcl.Traversal) string {
	if len(tr) == 0 {
		return ""
	}
	switch last := tr[len(tr)-1].(type) {
	case hcl.TraverseRoot:
		return last.Name
	case hcl.TraverseIndex:
		// index key can be a string literal (e.g., data["key"])
		if last.Key.Type() == cty.String {
			return last.Key.AsString()
		}
	}
	return ""
}

func isWildcard(s string) bool {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"`)
	// "*" or "s3:*" or any occurrence of "*" inside (conservative)
	if s == "*" || strings.HasSuffix(s, ":*") || strings.Contains(s, "*") {
		return true
	}
	return false
}
