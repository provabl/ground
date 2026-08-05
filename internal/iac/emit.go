// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package iac

import (
	"fmt"
	"sort"
	"strings"

	"github.com/provabl/ground/internal/cfn"
)

// hclBlock is one Terraform block, built structurally rather than as text.
//
// It exists so generated HCL is `terraform fmt`-canonical by construction.
// fmt aligns the `=` of consecutive single-line attributes as a group, which is
// tedious and fragile to reproduce by hand — TestHCL_IsFmtClean fails on a
// single misplaced space. Building blocks here and rendering once puts that
// alignment in one place.
type hclBlock struct {
	// header is everything before the brace, e.g. `resource "aws_vpc" "hub"`.
	header string
	// args are `name = value` attributes, rendered as one aligned group.
	args []string
	// nested are child blocks, rendered after the args.
	nested []hclBlock
	// comment, if set, is emitted as `#`-prefixed lines above the block.
	comment string
}

func (b hclBlock) render(indent string) string {
	var out strings.Builder
	for _, line := range strings.Split(strings.TrimRight(b.comment, "\n"), "\n") {
		if b.comment == "" {
			break
		}
		out.WriteString(strings.TrimRight(indent+"# "+line, " ") + "\n")
	}
	if len(b.args) == 0 && len(b.nested) == 0 {
		// fmt leaves an empty block on one line; an empty body would be reformatted.
		out.WriteString(indent + b.header + " {}\n")
		return out.String()
	}
	out.WriteString(indent + b.header + " {\n")
	for _, line := range alignAssignments(b.args) {
		out.WriteString(indent + "  " + line + "\n")
	}
	for _, n := range b.nested {
		out.WriteString(n.render(indent + "  "))
	}
	out.WriteString(indent + "}\n")
	return out.String()
}

// alignAssignments pads attribute names so the `=` line up, which is what
// `terraform fmt` does to a run of consecutive single-line attributes.
func alignAssignments(args []string) []string {
	width := 0
	for _, a := range args {
		if i := strings.Index(a, " = "); i > width {
			width = i
		}
	}
	out := make([]string, 0, len(args))
	for _, a := range args {
		i := strings.Index(a, " = ")
		if i < 0 {
			out = append(out, a)
			continue
		}
		out = append(out, a[:i]+strings.Repeat(" ", width-i)+a[i:])
	}
	return out
}

func arg(name, value string) string { return name + " = " + value }

// stackTemplate pairs a CloudFormation template with the stack that produced it.
type stackTemplate struct {
	title    string // section heading in the generated HCL
	template *cfn.Template
}

// transpiler converts the CloudFormation templates ground's stacks build into HCL.
type transpiler struct {
	resolver *refResolver
	// paramVars collects the Terraform variables synthesized from CFN parameters
	// that have no auto-discovered equivalent.
	paramVars map[string]cfnParam
}

type cfnParam struct {
	description string
	pattern     string
	defaultVal  string
}

// autoDiscovered maps the CFN parameters `ground deploy` fills in from the
// Organizations API to the Terraform data-source expression that does the same
// job. Translating these to a data source rather than a required variable is the
// *more* faithful rendering: the CloudFormation path does not ask the operator
// for them either.
var autoDiscovered = map[string]string{
	"OrgRootId": "data.aws_organizations_organization.current.roots[0].id",
	"OrgId":     "data.aws_organizations_organization.current.id",
}

func newTranspiler() *transpiler {
	return &transpiler{
		resolver: &refResolver{
			resources: map[string]string{},
			attrs:     map[string]string{},
			params:    map[string]string{},
		},
		paramVars: map[string]cfnParam{},
	}
}

// plan walks every template building the logical-ID → HCL reference map before
// any value is rendered. Two passes are required: CloudFormation templates freely
// reference resources declared later in the map.
func (t *transpiler) plan(stacks []stackTemplate) error {
	// taken guards against two logical IDs collapsing to the same Terraform name,
	// which would produce HCL that fails to parse — or worse, silently overwrite.
	taken := map[string]string{}

	for _, st := range stacks {
		if st.template == nil {
			continue
		}
		for _, name := range sortedKeys(st.template.Parameters) {
			p, _ := st.template.Parameters[name].(map[string]any)
			if expr, auto := autoDiscovered[name]; auto {
				t.resolver.params[name] = expr
				continue
			}
			desc, _ := p["Description"].(string)
			pat, _ := p["AllowedPattern"].(string)
			def, _ := p["Default"].(string)
			t.paramVars[name] = cfnParam{description: desc, pattern: pat, defaultVal: def}
			t.resolver.params[name] = "var." + tfName(name)
		}

		for _, logicalID := range sortedKeys(st.template.Resources) {
			res, ok := st.template.Resources[logicalID].(map[string]any)
			if !ok {
				return &UnsupportedError{LogicalID: logicalID, Construct: "resource entry", Reason: "not a JSON object"}
			}
			cfnType, _ := res["Type"].(string)
			mapping, known := cfnToTF[cfnType]
			if !known {
				return &UnsupportedError{
					LogicalID: logicalID,
					Construct: "resource type " + cfnType,
					Reason: "no Terraform mapping. Add one to cfnToTF so the export stays at parity " +
						"with the CloudFormation — an unmapped type must fail loudly, not vanish from the export",
				}
			}
			if mapping.tfType == "" {
				continue // deliberately not represented (e.g. WaitConditionHandle)
			}

			addr := mapping.tfType + "." + tfName(logicalID)
			if prev, dup := taken[addr]; dup {
				return &UnsupportedError{
					LogicalID: logicalID,
					Construct: "Terraform name " + addr,
					Reason:    "collides with logical ID " + prev + "; tfName must stay injective",
				}
			}
			taken[addr] = logicalID

			t.resolver.resources[logicalID] = addr + ".id"
			if cfnType == "AWS::SSO::PermissionSet" {
				// A permission set is referenced by ARN, not id.
				t.resolver.resources[logicalID] = addr + ".arn"
			}
			for cfnAttr, tfAttr := range cfnAttrToTF[cfnType] {
				t.resolver.attrs[attrKey(logicalID, cfnAttr)] = addr + "." + tfAttr
			}
		}
	}
	return nil
}

// emitStack renders every resource in one stack, in deterministic order.
func (t *transpiler) emitStack(st stackTemplate) ([]hclBlock, error) {
	var blocks []hclBlock
	for _, logicalID := range sortedKeys(st.template.Resources) {
		res := st.template.Resources[logicalID].(map[string]any)
		cfnType, _ := res["Type"].(string)
		mapping := cfnToTF[cfnType]
		if mapping.tfType == "" {
			continue
		}
		props, _ := res["Properties"].(map[string]any)
		if props == nil {
			props = map[string]any{}
		}
		bs, err := t.emitResource(logicalID, cfnType, mapping, props, res["DependsOn"])
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, bs...)
	}
	return blocks, nil
}

// emitResource renders one CFN resource, plus the extra Terraform resources it
// expands into (S3 sub-resources, policy attachments).
//
// resourceDependsOn is the resource-level DependsOn attribute, which is where
// CloudFormation actually reads it from; see dependsOn for why both positions are
// accepted.
func (t *transpiler) emitResource(logicalID, cfnType string, m resourceMapping, props map[string]any, resourceDependsOn any) ([]hclBlock, error) {
	name := tfName(logicalID)
	b := hclBlock{header: fmt.Sprintf("resource %q %q", m.tfType, name)}

	for _, cfnProp := range sortedKeys(props) {
		if cfnProp == "Tags" || cfnProp == "DependsOn" {
			continue // handled below
		}
		if _, dropped := m.drop[cfnProp]; dropped {
			continue
		}
		tfArg, mapped := m.props[cfnProp]
		if !mapped {
			return nil, &UnsupportedError{
				LogicalID: logicalID,
				Construct: fmt.Sprintf("property %q on %s", cfnProp, cfnType),
				Reason: "not mapped and not explicitly dropped. Add it to the mapping's props " +
					"(or to drop, with a reason) — an unmapped property would silently change what the export deploys",
			}
		}
		var expr string
		var err error
		if cfnProp == "PolicyDocument" || cfnProp == "AssumeRolePolicyDocument" {
			// Terraform takes policies as JSON strings, not nested objects.
			expr, err = t.resolver.jsonPolicy(logicalID, props[cfnProp])
		} else {
			expr, err = t.resolver.resolveValue(logicalID, props[cfnProp])
		}
		if err != nil {
			return nil, err
		}
		b.args = append(b.args, arg(tfArg, expr))
	}

	for _, k := range sortedStringKeys(m.synthesize) {
		b.args = append(b.args, arg(k, m.synthesize[k]))
	}

	if tags, ok := props["Tags"]; ok && m.tagStyle == "map" {
		rendered, err := renderTagsMap(tags)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", logicalID, err)
		}
		b.args = append(b.args, rendered)
	}

	sort.Strings(b.args)

	if refs := t.dependsOn(resourceDependsOn, props["DependsOn"]); len(refs) > 0 {
		b.args = append(b.args, arg("depends_on", "["+strings.Join(refs, ", ")+"]"))
	}

	extra, err := t.expand(logicalID, cfnType, name, props)
	if err != nil {
		return nil, err
	}
	// Blocks with an empty header are nested inside this resource; the rest are
	// sibling resources.
	var siblings []hclBlock
	for _, e := range extra {
		if e.nestedInParent {
			b.nested = append(b.nested, e.block)
			continue
		}
		siblings = append(siblings, e.block)
	}
	sort.Slice(siblings, func(i, j int) bool { return siblings[i].header < siblings[j].header })

	return append([]hclBlock{b}, siblings...), nil
}

// dependsOn resolves DependsOn declarations to Terraform resource addresses.
//
// It reads both positions on purpose. CloudFormation takes DependsOn as a
// resource-level attribute (a sibling of Type and Properties), but several of
// ground's stacks put it *inside* Properties, where CFN ignores it — so those
// ordering constraints are inert in the deploy path today (tracked separately).
// Accepting both means the export honours the declared intent now, and keeps
// honouring it after the stacks are fixed. Reading only the correct position would
// silently drop five constraints today; reading only Properties would silently
// drop them the day someone fixes the bug.
func (t *transpiler) dependsOn(decls ...any) []string {
	var names []string
	for _, d := range decls {
		switch v := d.(type) {
		case string:
			names = append(names, v)
		case []string:
			names = append(names, v...)
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					names = append(names, s)
				}
			}
		}
	}
	seen := map[string]bool{}
	var refs []string
	for _, dep := range names {
		expr, ok := t.resolver.resources[dep]
		if !ok {
			continue
		}
		// depends_on takes a resource address, not one of its attributes.
		addr := strings.TrimSuffix(strings.TrimSuffix(expr, ".id"), ".arn")
		if seen[addr] {
			continue
		}
		seen[addr] = true
		refs = append(refs, addr)
	}
	sort.Strings(refs)
	return refs
}

// expansion is a block produced by expanding one CFN resource: either a nested
// block inside it, or a separate sibling resource.
type expansion struct {
	block          hclBlock
	nestedInParent bool
}

// expand renders the blocks a single CloudFormation resource splits into.
//
// CloudFormation models these as nested properties; the AWS Terraform provider
// models several of them as separate top-level resources. This is where the
// properties listed in a mapping's drop set are actually accounted for — nothing
// in drop is lost, it is re-emitted here.
func (t *transpiler) expand(logicalID, cfnType, name string, props map[string]any) ([]expansion, error) {
	var out []expansion
	sibling := func(b hclBlock) { out = append(out, expansion{block: b}) }
	nested := func(b hclBlock) { out = append(out, expansion{block: b, nestedInParent: true}) }

	switch cfnType {
	case "AWS::S3::Bucket":
		bucketRef := fmt.Sprintf("aws_s3_bucket.%s.id", name)

		sibling(hclBlock{
			header: fmt.Sprintf("resource %q %q", "aws_s3_bucket_public_access_block", name),
			args: []string{
				arg("bucket", bucketRef),
				arg("block_public_acls", "true"),
				arg("block_public_policy", "true"),
				arg("ignore_public_acls", "true"),
				arg("restrict_public_buckets", "true"),
			},
		})

		sibling(hclBlock{
			header: fmt.Sprintf("resource %q %q", "aws_s3_bucket_server_side_encryption_configuration", name),
			args:   []string{arg("bucket", bucketRef)},
			nested: []hclBlock{{
				header: "rule",
				nested: []hclBlock{{
					header: "apply_server_side_encryption_by_default",
					args:   []string{arg("sse_algorithm", `"aws:kms"`)},
				}},
			}},
		})

		sibling(hclBlock{
			header: fmt.Sprintf("resource %q %q", "aws_s3_bucket_versioning", name),
			args:   []string{arg("bucket", bucketRef)},
			nested: []hclBlock{{
				header: "versioning_configuration",
				args:   []string{arg("status", `"Enabled"`)},
			}},
		})

		if olc, ok := props["ObjectLockConfiguration"].(map[string]any); ok {
			if mode, days := objectLockRetention(olc); days > 0 {
				sibling(hclBlock{
					header: fmt.Sprintf("resource %q %q", "aws_s3_bucket_object_lock_configuration", name),
					// Object Lock retention requires versioning to exist first; without the
					// explicit dependency Terraform may order them concurrently and fail.
					args: []string{
						arg("bucket", bucketRef),
						arg("depends_on", fmt.Sprintf("[aws_s3_bucket_versioning.%s]", name)),
					},
					nested: []hclBlock{{
						header: "rule",
						nested: []hclBlock{{
							header: "default_retention",
							args: []string{
								arg("mode", quoteHCL(mode)),
								arg("days", fmt.Sprint(days)),
							},
						}},
					}},
				})
			}
		}

		if lc, ok := props["LifecycleConfiguration"].(map[string]any); ok {
			if b, ok := lifecycleBlock(name, bucketRef, lc); ok {
				sibling(b)
			}
		}

	case "AWS::IAM::Role":
		arns, _ := props["ManagedPolicyArns"].([]string)
		for i, policyARN := range arns {
			attachName := name
			if len(arns) > 1 {
				attachName = fmt.Sprintf("%s_%d", name, i+1)
			}
			sibling(hclBlock{
				header: fmt.Sprintf("resource %q %q", "aws_iam_role_policy_attachment", attachName),
				args: []string{
					arg("role", fmt.Sprintf("aws_iam_role.%s.name", name)),
					arg("policy_arn", quoteHCL(policyARN)),
				},
			})
		}

	case "AWS::Organizations::Policy":
		// CFN attaches a policy via TargetIds; Terraform needs one attachment
		// resource per target.
		targets, _ := props["TargetIds"].([]any)
		for i, target := range targets {
			expr, err := t.resolver.resolveValue(logicalID, target)
			if err != nil {
				return nil, err
			}
			attachName := name
			if len(targets) > 1 {
				attachName = fmt.Sprintf("%s_%d", name, i+1)
			}
			sibling(hclBlock{
				header: fmt.Sprintf("resource %q %q", "aws_organizations_policy_attachment", attachName),
				args: []string{
					arg("policy_id", fmt.Sprintf("aws_organizations_policy.%s.id", name)),
					arg("target_id", expr),
				},
			})
		}

	case "AWS::CloudTrail::Trail":
		sels, _ := props["EventSelectors"].([]map[string]any)
		for _, sel := range sels {
			nested(eventSelectorBlock(sel))
		}

	case "AWS::Config::ConfigurationRecorder":
		if rg, ok := props["RecordingGroup"].(map[string]any); ok {
			all, _ := rg["AllSupported"].(bool)
			global, _ := rg["IncludeGlobalResourceTypes"].(bool)
			nested(hclBlock{
				header: "recording_group",
				args: []string{
					arg("all_supported", fmt.Sprint(all)),
					arg("include_global_resource_types", fmt.Sprint(global)),
				},
			})
		}

	case "AWS::Config::DeliveryChannel":
		if sd, ok := props["ConfigSnapshotDeliveryProperties"].(map[string]string); ok {
			if freq := sd["DeliveryFrequency"]; freq != "" {
				nested(hclBlock{
					header: "snapshot_delivery_properties",
					args:   []string{arg("delivery_frequency", quoteHCL(freq))},
				})
			}
		}

	case "AWS::SSO::PermissionSet":
		policies, _ := props["ManagedPolicies"].([]string)
		if len(policies) > 0 {
			instanceExpr, err := t.resolver.resolveValue(logicalID, props["InstanceArn"])
			if err != nil {
				return nil, err
			}
			for i, policyARN := range policies {
				attachName := name
				if len(policies) > 1 {
					attachName = fmt.Sprintf("%s_%d", name, i+1)
				}
				sibling(hclBlock{
					header: fmt.Sprintf("resource %q %q", "aws_ssoadmin_managed_policy_attachment", attachName),
					args: []string{
						arg("instance_arn", instanceExpr),
						arg("managed_policy_arn", quoteHCL(policyARN)),
						arg("permission_set_arn", fmt.Sprintf("aws_ssoadmin_permission_set.%s.arn", name)),
					},
				})
			}
		}
	}
	return out, nil
}

func objectLockRetention(olc map[string]any) (mode string, days int) {
	rule, ok := olc["Rule"].(map[string]any)
	if !ok {
		return "", 0
	}
	dr, ok := rule["DefaultRetention"].(map[string]any)
	if !ok {
		return "", 0
	}
	mode, _ = dr["Mode"].(string)
	return mode, toInt(dr["Days"])
}

func lifecycleBlock(name, bucketRef string, lc map[string]any) (hclBlock, bool) {
	rules, ok := lc["Rules"].([]map[string]any)
	if !ok || len(rules) == 0 {
		return hclBlock{}, false
	}
	b := hclBlock{
		header: fmt.Sprintf("resource %q %q", "aws_s3_bucket_lifecycle_configuration", name),
		args:   []string{arg("bucket", bucketRef)},
	}
	for _, rule := range rules {
		id, _ := rule["Id"].(string)
		status, _ := rule["Status"].(string)
		rb := hclBlock{
			header: "rule",
			args:   []string{arg("id", quoteHCL(id)), arg("status", quoteHCL(status))},
			// An explicit (empty) filter is required in provider v4+ for a rule to
			// apply to every object; omitting it is a plan-time error.
			nested: []hclBlock{{header: "filter"}},
		}
		trs, _ := rule["Transitions"].([]map[string]any)
		for _, tr := range trs {
			sc, _ := tr["StorageClass"].(string)
			rb.nested = append(rb.nested, hclBlock{
				header: "transition",
				args: []string{
					arg("days", fmt.Sprint(toInt(tr["TransitionInDays"]))),
					arg("storage_class", quoteHCL(sc)),
				},
			})
		}
		b.nested = append(b.nested, rb)
	}
	return b, true
}

func eventSelectorBlock(sel map[string]any) hclBlock {
	rw, _ := sel["ReadWriteType"].(string)
	mgmt, _ := sel["IncludeManagementEvents"].(bool)
	b := hclBlock{
		header: "event_selector",
		args: []string{
			arg("read_write_type", quoteHCL(rw)),
			arg("include_management_events", fmt.Sprint(mgmt)),
		},
	}
	drs, _ := sel["DataResources"].([]map[string]any)
	for _, dr := range drs {
		typ, _ := dr["Type"].(string)
		vals, _ := dr["Values"].([]string)
		quoted := make([]string, 0, len(vals))
		for _, v := range vals {
			quoted = append(quoted, quoteHCL(v))
		}
		b.nested = append(b.nested, hclBlock{
			header: "data_resource",
			args: []string{
				arg("type", quoteHCL(typ)),
				arg("values", "["+strings.Join(quoted, ", ")+"]"),
			},
		})
	}
	return b
}

// renderTagsMap renders a CFN Tags list as a Terraform tags map, merged with the
// export's managed tags so managed-by/version live in exactly one place.
func renderTagsMap(tags any) (string, error) {
	pairs, err := tagPairs(tags)
	if err != nil {
		return "", err
	}
	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		if k == "managed-by" || k == "ground:version" {
			continue // supplied by local.managed_tags
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return arg("tags", "local.managed_tags"), nil
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s = %s", quoteHCL(k), quoteHCL(pairs[k])))
	}
	return arg("tags", fmt.Sprintf("merge(local.managed_tags, { %s })", strings.Join(parts, ", "))), nil
}

func tagPairs(tags any) (map[string]string, error) {
	out := map[string]string{}
	switch tl := tags.(type) {
	case []map[string]string:
		for _, tag := range tl {
			out[tag["Key"]] = tag["Value"]
		}
	case []any:
		for _, item := range tl {
			switch tag := item.(type) {
			case map[string]string:
				out[tag["Key"]] = tag["Value"]
			case map[string]any:
				k, _ := tag["Key"].(string)
				v, _ := tag["Value"].(string)
				out[k] = v
			default:
				return nil, fmt.Errorf("unsupported tag entry %T", item)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported Tags shape %T", tags)
	}
	return out, nil
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStringKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
