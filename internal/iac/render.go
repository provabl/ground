// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package iac

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// refResolver maps a CloudFormation logical ID to the HCL expression that
// references the corresponding Terraform resource's id, and template parameter
// names to their variable references.
type refResolver struct {
	// resources maps logical ID → HCL id expression, e.g.
	// "VPC" → "aws_vpc.vpc.id".
	resources map[string]string
	// attrs maps logical ID + CFN attribute → HCL expression, for Fn::GetAtt,
	// e.g. {"AuditBucket","Arn"} → "aws_s3_bucket.audit_bucket.arn".
	attrs map[string]string
	// params maps a CFN parameter name → HCL variable expression.
	params map[string]string
	// dataSources records which Terraform data sources the rendered expressions
	// ended up referencing, so the generator declares exactly those. Declaring
	// them unconditionally would leave unused data blocks in the output; guessing
	// would leave a dangling reference that fails `validate`.
	dataSources map[string]bool
}

// useData marks a data source as referenced and returns the expression unchanged.
func (r *refResolver) useData(name, expr string) string {
	if r.dataSources == nil {
		r.dataSources = map[string]bool{}
	}
	r.dataSources[name] = true
	return expr
}

func attrKey(logicalID, attr string) string { return logicalID + "." + attr }

// cfnAttrToTF maps the Fn::GetAtt attributes ground's templates actually read to
// their Terraform equivalents. Restricting this to a known set means a new
// GetAtt is a hard error rather than a guessed attribute name that plans clean
// and refers to nothing.
var cfnAttrToTF = map[string]map[string]string{
	"AWS::S3::Bucket":            {"Arn": "arn"},
	"AWS::CloudTrail::Trail":     {"Arn": "arn"},
	"AWS::IAM::Role":             {"Arn": "arn"},
	"AWS::SSO::PermissionSet":    {"PermissionSetArn": "arn"},
	"AWS::EC2::VPC":              {"CidrBlock": "cidr_block"},
	"AWS::Organizations::Policy": {"Id": "id"},
}

// resolveValue renders a CloudFormation property value as an HCL expression.
//
// It handles the closed set of intrinsics ground's templates use and rejects
// everything else, because a silently mistranslated intrinsic is worse than a
// failed export: it applies.
func (r *refResolver) resolveValue(logicalID string, v any) (string, error) {
	switch val := v.(type) {
	case nil:
		return "null", nil
	case string:
		return quoteHCL(val), nil
	case bool:
		return strconv.FormatBool(val), nil
	case int:
		return strconv.Itoa(val), nil
	case float64:
		// JSON numbers arrive as float64; render integers without a decimal point.
		if val == float64(int64(val)) {
			return strconv.FormatInt(int64(val), 10), nil
		}
		return strconv.FormatFloat(val, 'f', -1, 64), nil
	case []string:
		parts := make([]string, 0, len(val))
		for _, s := range val {
			parts = append(parts, quoteHCL(s))
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	case []any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			s, err := r.resolveValue(logicalID, item)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	case map[string]string:
		// A single-key {"Ref": "X"} arrives as map[string]string.
		if target, ok := val["Ref"]; ok && len(val) == 1 {
			return r.resolveRef(logicalID, target)
		}
		return r.resolveStringMap(val)
	case []map[string]string:
		// Tag lists are handled by the tag renderer, not here.
		return "", &UnsupportedError{
			LogicalID: logicalID,
			Construct: "tag list in a value position",
			Reason:    "tags are rendered by renderTags; this is a transpiler bug",
		}
	case map[string]any:
		return r.resolveIntrinsicOrObject(logicalID, val)
	case []map[string]any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			s, err := r.resolveValue(logicalID, item)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	default:
		return "", &UnsupportedError{
			LogicalID: logicalID,
			Construct: fmt.Sprintf("value of Go type %T", v),
			Reason:    "add a case to resolveValue if this property is needed",
		}
	}
}

// resolveIntrinsicOrObject handles a map that is either a CFN intrinsic call or
// a plain nested object.
func (r *refResolver) resolveIntrinsicOrObject(logicalID string, m map[string]any) (string, error) {
	if len(m) == 1 {
		for k, raw := range m {
			switch k {
			case "Ref":
				target, ok := raw.(string)
				if !ok {
					return "", &UnsupportedError{LogicalID: logicalID, Construct: "Ref", Reason: "target is not a string"}
				}
				return r.resolveRef(logicalID, target)

			case "Fn::GetAtt":
				return r.resolveGetAtt(logicalID, raw)

			case "Fn::Sub":
				return r.resolveSub(logicalID, raw)

			case "Fn::Select":
				return r.resolveSelect(logicalID, raw)

			case "Fn::GetAZs":
				// Terraform's equivalent is a data source, declared once by the generator.
				return r.useData("aws_availability_zones", "data.aws_availability_zones.available.names"), nil

			default:
				if strings.HasPrefix(k, "Fn::") {
					return "", &UnsupportedError{
						LogicalID: logicalID,
						Construct: k,
						Reason:    "no HCL equivalent is implemented; add one to resolveIntrinsicOrObject",
					}
				}
			}
		}
	}
	// A plain object — render as an HCL object expression, keys sorted so output
	// is deterministic.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		s, err := r.resolveValue(logicalID, m[k])
		if err != nil {
			return "", err
		}
		parts = append(parts, fmt.Sprintf("%s = %s", quoteHCL(k), s))
	}
	return "{ " + strings.Join(parts, ", ") + " }", nil
}

func (r *refResolver) resolveStringMap(m map[string]string) (string, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s = %s", quoteHCL(k), quoteHCL(m[k])))
	}
	return "{ " + strings.Join(parts, ", ") + " }", nil
}

// resolveRef renders a CFN Ref: either a resource id or a template parameter.
func (r *refResolver) resolveRef(logicalID, target string) (string, error) {
	if expr, ok := r.params[target]; ok {
		// An auto-discovered parameter resolves to a data source rather than a
		// variable; record it so the generator declares it.
		if rest, isData := strings.CutPrefix(expr, "data."); isData {
			if dot := strings.Index(rest, "."); dot > 0 {
				return r.useData(rest[:dot], expr), nil
			}
		}
		return expr, nil
	}
	if expr, ok := r.resources[target]; ok {
		return expr, nil
	}
	if strings.HasPrefix(target, "AWS::") {
		// Pseudo-parameters have data-source equivalents; only add ones actually needed.
		switch target {
		case "AWS::AccountId":
			return r.useData("aws_caller_identity", "data.aws_caller_identity.current.account_id"), nil
		case "AWS::Region":
			return r.useData("aws_region", "data.aws_region.current.name"), nil
		case "AWS::Partition":
			return r.useData("aws_partition", "data.aws_partition.current.partition"), nil
		}
	}
	return "", &UnsupportedError{
		LogicalID: logicalID,
		Construct: "Ref to " + target,
		Reason:    "not a known resource, parameter, or supported pseudo-parameter",
	}
}

// resolveGetAtt renders Fn::GetAtt. Only attributes in cfnAttrToTF are accepted.
func (r *refResolver) resolveGetAtt(logicalID string, raw any) (string, error) {
	var target, attr string
	switch g := raw.(type) {
	case []string:
		if len(g) != 2 {
			return "", &UnsupportedError{LogicalID: logicalID, Construct: "Fn::GetAtt", Reason: "expected [logicalId, attribute]"}
		}
		target, attr = g[0], g[1]
	case []any:
		if len(g) != 2 {
			return "", &UnsupportedError{LogicalID: logicalID, Construct: "Fn::GetAtt", Reason: "expected [logicalId, attribute]"}
		}
		t, ok1 := g[0].(string)
		a, ok2 := g[1].(string)
		if !ok1 || !ok2 {
			return "", &UnsupportedError{LogicalID: logicalID, Construct: "Fn::GetAtt", Reason: "non-string logicalId or attribute"}
		}
		target, attr = t, a
	default:
		return "", &UnsupportedError{LogicalID: logicalID, Construct: "Fn::GetAtt", Reason: "unexpected argument shape"}
	}

	if expr, ok := r.attrs[attrKey(target, attr)]; ok {
		return expr, nil
	}
	return "", &UnsupportedError{
		LogicalID: logicalID,
		Construct: fmt.Sprintf("Fn::GetAtt [%s, %s]", target, attr),
		Reason:    "no Terraform attribute mapping; add one to cfnAttrToTF",
	}
}

// resolveSub renders Fn::Sub as an HCL interpolated string. Only the
// "${Logical.Attr}" and "${Logical}" forms ground uses are supported.
func (r *refResolver) resolveSub(logicalID string, raw any) (string, error) {
	tmpl, ok := raw.(string)
	if !ok {
		// The [template, {vars}] form isn't used by ground's stacks.
		return "", &UnsupportedError{
			LogicalID: logicalID,
			Construct: "Fn::Sub with a variable map",
			Reason:    "only the single-string form is supported",
		}
	}

	var out strings.Builder
	out.WriteByte('"')
	rest := tmpl
	for {
		start := strings.Index(rest, "${")
		if start < 0 {
			out.WriteString(escapeHCLInner(rest))
			break
		}
		out.WriteString(escapeHCLInner(rest[:start]))
		end := strings.Index(rest[start:], "}")
		if end < 0 {
			return "", &UnsupportedError{LogicalID: logicalID, Construct: "Fn::Sub", Reason: "unterminated ${ in " + tmpl}
		}
		token := rest[start+2 : start+end]
		rest = rest[start+end+1:]

		var expr string
		var err error
		if dot := strings.Index(token, "."); dot >= 0 {
			expr, err = r.resolveGetAtt(logicalID, []string{token[:dot], token[dot+1:]})
		} else {
			expr, err = r.resolveRef(logicalID, token)
		}
		if err != nil {
			return "", err
		}
		out.WriteString("${" + expr + "}")
	}
	out.WriteByte('"')
	return out.String(), nil
}

// resolveSelect renders Fn::Select as HCL index syntax.
func (r *refResolver) resolveSelect(logicalID string, raw any) (string, error) {
	args, ok := raw.([]any)
	if !ok || len(args) != 2 {
		return "", &UnsupportedError{LogicalID: logicalID, Construct: "Fn::Select", Reason: "expected [index, list]"}
	}
	idx, err := r.resolveValue(logicalID, args[0])
	if err != nil {
		return "", err
	}
	list, err := r.resolveValue(logicalID, args[1])
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s[%s]", list, idx), nil
}

// jsonPolicy renders a CFN inline policy document as an HCL jsonencode() call.
//
// It goes through resolveValue rather than json.Marshal even when the document
// holds no intrinsics, so the same renderer covers both cases. That matters
// because most of ground's policy documents *do* embed a Ref or Fn::GetAtt (the
// bucket policy names the bucket's own ARN, the endpoint policies name the org
// id), and a second marshalling path would format its output differently — which
// `terraform fmt` would then rewrite.
func (r *refResolver) jsonPolicy(logicalID string, doc any) (string, error) {
	expr, err := r.resolveValue(logicalID, doc)
	if err != nil {
		return "", err
	}
	return "jsonencode(" + expr + ")", nil
}

// quoteHCL renders a Go string as an HCL string literal.
func quoteHCL(s string) string { return `"` + escapeHCLInner(s) + `"` }

// escapeHCLInner escapes the inside of an HCL string literal. `${` must be
// escaped as `$${` or HCL treats it as an interpolation — which matters for the
// IAM policy variables and CFN-ish text that appear in descriptions.
func escapeHCLInner(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\':
			b.WriteString(`\\`)
		case s[i] == '"':
			b.WriteString(`\"`)
		case s[i] == '\n':
			b.WriteString(`\n`)
		case s[i] == '\t':
			b.WriteString(`\t`)
		case s[i] == '$' && i+1 < len(s) && s[i+1] == '{':
			b.WriteString("$${")
			i++
		case s[i] == '%' && i+1 < len(s) && s[i+1] == '{':
			b.WriteString("%%{")
			i++
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
