package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// The rule fields below are Optional+Computed. When the user leaves one out and
// changes something else, Terraform plans it as unknown; the PUT that follows
// is a full replace, so anything the plan does not carry is wiped. These cases
// pin which prior value the plan adopts and when it must plan null instead
// because the server would reject the combination.

var (
	ruleResourceType = PolicyRuleResourceModel{}.TFType().AttrTypes
	portRangeType    = PolicyRulePortRangeModel{}.TFType()
	authGroupsType   = types.ListType{ElemType: types.StringType}
)

func strList(v ...string) types.List {
	elems := make([]attr.Value, 0, len(v))
	for _, s := range v {
		elems = append(elems, types.StringValue(s))
	}
	return types.ListValueMust(types.StringType, elems)
}

func portRanges(start, end int32) types.List {
	return types.ListValueMust(portRangeType, []attr.Value{
		types.ObjectValueMust(portRangeType.AttrTypes, map[string]attr.Value{
			"start": types.Int32Value(start),
			"end":   types.Int32Value(end),
		}),
	})
}

func ruleResource(id, typ string) types.Object {
	return types.ObjectValueMust(ruleResourceType, map[string]attr.Value{
		"id":   types.StringValue(id),
		"type": types.StringValue(typ),
	})
}

func authGroups(group string, users ...string) types.Map {
	return types.MapValueMust(authGroupsType, map[string]attr.Value{group: strList(users...)})
}

// ruleAllNull is a rule whose optional fields are all null, as in a config that
// sets only the required ones.
func ruleAllNull(protocol string) PolicyRuleModel {
	return PolicyRuleModel{
		Id:                  types.StringNull(),
		Name:                types.StringValue("r"),
		Description:         types.StringNull(),
		Action:              types.StringValue("accept"),
		Protocol:            types.StringValue(protocol),
		Ports:               types.ListNull(types.StringType),
		PortRanges:          types.ListNull(portRangeType),
		Enabled:             types.BoolValue(true),
		Bidirectional:       types.BoolValue(true),
		Sources:             types.ListNull(types.StringType),
		SourceResource:      types.ObjectNull(ruleResourceType),
		Destinations:        types.ListNull(types.StringType),
		DestinationResource: types.ObjectNull(ruleResourceType),
		AuthorizedGroups:    types.MapNull(authGroupsType),
	}
}

// rulePlanned is what Terraform plans for an update of ruleAllNull: every
// unconfigured computed field unknown.
func rulePlanned(protocol string) PolicyRuleModel {
	r := ruleAllNull(protocol)
	r.Id = types.StringUnknown()
	r.Ports = types.ListUnknown(types.StringType)
	r.PortRanges = types.ListUnknown(portRangeType)
	r.Sources = types.ListUnknown(types.StringType)
	r.SourceResource = types.ObjectUnknown(ruleResourceType)
	r.Destinations = types.ListUnknown(types.StringType)
	r.DestinationResource = types.ObjectUnknown(ruleResourceType)
	r.AuthorizedGroups = types.MapUnknown(authGroupsType)
	return r
}

func Test_adoptUnconfiguredRuleFields(t *testing.T) {
	groupsState := ruleAllNull("tcp")
	groupsState.Id = types.StringValue("rule1")
	groupsState.Ports = strList("443")
	groupsState.Sources = strList("g1")
	groupsState.Destinations = strList("g2")

	resourcesState := ruleAllNull("udp")
	resourcesState.PortRanges = portRanges(1000, 2000)
	resourcesState.SourceResource = ruleResource("r1", "subnet")
	resourcesState.DestinationResource = ruleResource("r2", "domain")

	sshState := ruleAllNull("netbird-ssh")
	sshState.Sources = strList("g1")
	sshState.Destinations = strList("g2")
	sshState.AuthorizedGroups = authGroups("g1", "root")

	cases := []struct {
		name   string
		plan   func() PolicyRuleModel
		config func() PolicyRuleModel
		state  PolicyRuleModel
		want   func() PolicyRuleModel
	}{
		{
			name:   "unconfigured group rule fields keep the server's values",
			plan:   func() PolicyRuleModel { return rulePlanned("tcp") },
			config: func() PolicyRuleModel { return ruleAllNull("tcp") },
			state:  groupsState,
			want: func() PolicyRuleModel {
				r := ruleAllNull("tcp")
				r.Id = types.StringUnknown()
				r.Ports = strList("443")
				r.Sources = strList("g1")
				r.Destinations = strList("g2")
				return r
			},
		},
		{
			name:   "unconfigured resource rule fields keep the server's values",
			plan:   func() PolicyRuleModel { return rulePlanned("udp") },
			config: func() PolicyRuleModel { return ruleAllNull("udp") },
			state:  resourcesState,
			want: func() PolicyRuleModel {
				r := ruleAllNull("udp")
				r.Id = types.StringUnknown()
				r.PortRanges = portRanges(1000, 2000)
				r.SourceResource = ruleResource("r1", "subnet")
				r.DestinationResource = ruleResource("r2", "domain")
				return r
			},
		},
		{
			name: "configured values are not touched",
			plan: func() PolicyRuleModel {
				r := rulePlanned("tcp")
				r.Ports = strList("80")
				r.Sources = strList("g3")
				return r
			},
			config: func() PolicyRuleModel {
				r := ruleAllNull("tcp")
				r.Ports = strList("80")
				r.Sources = strList("g3")
				return r
			},
			state: groupsState,
			want: func() PolicyRuleModel {
				r := ruleAllNull("tcp")
				r.Id = types.StringUnknown()
				r.Ports = strList("80")
				r.Sources = strList("g3")
				r.Destinations = strList("g2")
				return r
			},
		},
		{
			// The server rejects ports and port ranges together, and sources
			// with a source resource: the configured side wins and the other is
			// planned null, so the removal shows in the plan.
			name: "switching groups to resources drops the unconfigured side",
			plan: func() PolicyRuleModel {
				r := rulePlanned("udp")
				r.PortRanges = portRanges(1, 100)
				r.SourceResource = ruleResource("r1", "subnet")
				r.DestinationResource = ruleResource("r2", "domain")
				return r
			},
			config: func() PolicyRuleModel {
				r := ruleAllNull("udp")
				r.PortRanges = portRanges(1, 100)
				r.SourceResource = ruleResource("r1", "subnet")
				r.DestinationResource = ruleResource("r2", "domain")
				return r
			},
			state: groupsState,
			want: func() PolicyRuleModel {
				r := ruleAllNull("udp")
				r.Id = types.StringUnknown()
				r.PortRanges = portRanges(1, 100)
				r.SourceResource = ruleResource("r1", "subnet")
				r.DestinationResource = ruleResource("r2", "domain")
				return r
			},
		},
		{
			name: "switching resources to groups drops the unconfigured side",
			plan: func() PolicyRuleModel {
				r := rulePlanned("udp")
				r.Ports = strList("53")
				r.Sources = strList("g1")
				r.Destinations = strList("g2")
				return r
			},
			config: func() PolicyRuleModel {
				r := ruleAllNull("udp")
				r.Ports = strList("53")
				r.Sources = strList("g1")
				r.Destinations = strList("g2")
				return r
			},
			state: resourcesState,
			want: func() PolicyRuleModel {
				r := ruleAllNull("udp")
				r.Id = types.StringUnknown()
				r.Ports = strList("53")
				r.Sources = strList("g1")
				r.Destinations = strList("g2")
				return r
			},
		},
		{
			// The server refuses ports on an all or icmp rule.
			name:   "a portless protocol drops unconfigured ports",
			plan:   func() PolicyRuleModel { return rulePlanned("all") },
			config: func() PolicyRuleModel { return ruleAllNull("all") },
			state:  groupsState,
			want: func() PolicyRuleModel {
				r := ruleAllNull("all")
				r.Id = types.StringUnknown()
				r.Sources = strList("g1")
				r.Destinations = strList("g2")
				return r
			},
		},
		{
			name:   "an icmp rule drops unconfigured port ranges",
			plan:   func() PolicyRuleModel { return rulePlanned("icmp") },
			config: func() PolicyRuleModel { return ruleAllNull("icmp") },
			state:  resourcesState,
			want: func() PolicyRuleModel {
				r := ruleAllNull("icmp")
				r.Id = types.StringUnknown()
				r.SourceResource = ruleResource("r1", "subnet")
				r.DestinationResource = ruleResource("r2", "domain")
				return r
			},
		},
		{
			name:   "authorized groups kept while the rule stays netbird-ssh on the same sources",
			plan:   func() PolicyRuleModel { return rulePlanned("netbird-ssh") },
			config: func() PolicyRuleModel { return ruleAllNull("netbird-ssh") },
			state:  sshState,
			want: func() PolicyRuleModel {
				r := ruleAllNull("netbird-ssh")
				r.Id = types.StringUnknown()
				r.Sources = strList("g1")
				r.Destinations = strList("g2")
				r.AuthorizedGroups = authGroups("g1", "root")
				return r
			},
		},
		{
			// authorized_groups is only valid on netbird-ssh; keeping it would
			// fail the request.
			name:   "authorized groups dropped when the rule leaves netbird-ssh",
			plan:   func() PolicyRuleModel { return rulePlanned("tcp") },
			config: func() PolicyRuleModel { return ruleAllNull("tcp") },
			state:  sshState,
			want: func() PolicyRuleModel {
				r := ruleAllNull("tcp")
				r.Id = types.StringUnknown()
				r.Sources = strList("g1")
				r.Destinations = strList("g2")
				return r
			},
		},
		{
			// The server wants an entry for every source and the provider
			// rejects keys that are not sources, so the old map only survives
			// an unchanged source set.
			name: "authorized groups dropped when the sources change",
			plan: func() PolicyRuleModel {
				r := rulePlanned("netbird-ssh")
				r.Sources = strList("g1", "g3")
				return r
			},
			config: func() PolicyRuleModel {
				r := ruleAllNull("netbird-ssh")
				r.Sources = strList("g1", "g3")
				return r
			},
			state: sshState,
			want: func() PolicyRuleModel {
				r := ruleAllNull("netbird-ssh")
				r.Id = types.StringUnknown()
				r.Sources = strList("g1", "g3")
				r.Destinations = strList("g2")
				return r
			},
		},
		{
			name: "authorized groups dropped when the sources are not known yet",
			plan: func() PolicyRuleModel {
				r := rulePlanned("netbird-ssh")
				r.Sources = types.ListUnknown(types.StringType)
				return r
			},
			config: func() PolicyRuleModel {
				r := ruleAllNull("netbird-ssh")
				r.Sources = types.ListUnknown(types.StringType)
				return r
			},
			state: sshState,
			want: func() PolicyRuleModel {
				r := ruleAllNull("netbird-ssh")
				r.Id = types.StringUnknown()
				r.Sources = types.ListUnknown(types.StringType)
				r.Destinations = strList("g2")
				return r
			},
		},
		{
			// Without a known protocol there is no telling whether the server
			// will accept the old ports, so they stay unknown.
			name: "an unknown protocol leaves ports undecided",
			plan: func() PolicyRuleModel {
				r := rulePlanned("tcp")
				r.Protocol = types.StringUnknown()
				return r
			},
			config: func() PolicyRuleModel {
				r := ruleAllNull("tcp")
				r.Protocol = types.StringUnknown()
				return r
			},
			state: groupsState,
			want: func() PolicyRuleModel {
				r := ruleAllNull("tcp")
				r.Id = types.StringUnknown()
				r.Protocol = types.StringUnknown()
				r.Ports = types.ListUnknown(types.StringType)
				r.PortRanges = types.ListUnknown(portRangeType)
				r.Sources = strList("g1")
				r.Destinations = strList("g2")
				return r
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := adoptUnconfiguredRuleFields(c.plan(), c.config(), c.state)
			want := c.want()
			for _, f := range []struct {
				name      string
				got, want attr.Value
			}{
				{"ports", got.Ports, want.Ports},
				{"port_ranges", got.PortRanges, want.PortRanges},
				{"sources", got.Sources, want.Sources},
				{"source_resource", got.SourceResource, want.SourceResource},
				{"destinations", got.Destinations, want.Destinations},
				{"destination_resource", got.DestinationResource, want.DestinationResource},
				{"authorized_groups", got.AuthorizedGroups, want.AuthorizedGroups},
				{"protocol", got.Protocol, want.Protocol},
			} {
				if !f.got.Equal(f.want) {
					t.Errorf("%s = %s, want %s", f.name, f.got, f.want)
				}
			}
		})
	}
}

// Clearing an Optional+Computed field takes an explicit empty value, since
// leaving it out adopts the server's. The API reports an empty ports, port
// ranges, authorized groups or posture checks as absent, so the empty value has
// to survive the read or the apply returns something other than the plan.
func Test_keepEmptyCollections(t *testing.T) {
	ctx := context.Background()
	emptyAG := types.MapValueMust(authGroupsType, map[string]attr.Value{})

	ruleList := func(r PolicyRuleModel) types.List {
		l, d := types.ListValueFrom(ctx, PolicyRuleModel{}.TFType(), []PolicyRuleModel{r})
		if d.HasError() {
			t.Fatalf("building rules: %v", d)
		}
		return l
	}

	priorRule := ruleAllNull("netbird-ssh")
	priorRule.Ports = strList()
	priorRule.PortRanges = types.ListValueMust(portRangeType, []attr.Value{})
	priorRule.Sources = strList("g1")
	priorRule.AuthorizedGroups = emptyAG
	prior := PolicyModel{SourcePostureChecks: strList(), Rules: ruleList(priorRule)}

	readRule := ruleAllNull("netbird-ssh")
	readRule.Sources = strList("g1")
	data := PolicyModel{SourcePostureChecks: types.ListNull(types.StringType), Rules: ruleList(readRule)}

	if d := keepEmptyCollections(ctx, prior, &data); d.HasError() {
		t.Fatalf("keepEmptyCollections: %v", d)
	}

	if !data.SourcePostureChecks.Equal(strList()) {
		t.Errorf("source_posture_checks = %s, want []", data.SourcePostureChecks)
	}
	var rules []PolicyRuleModel
	if d := data.Rules.ElementsAs(ctx, &rules, false); d.HasError() || len(rules) != 1 {
		t.Fatalf("rules = %s: %v", data.Rules, d)
	}
	got := rules[0]
	for _, f := range []struct {
		name      string
		got, want attr.Value
	}{
		{"ports", got.Ports, priorRule.Ports},
		{"port_ranges", got.PortRanges, priorRule.PortRanges},
		{"authorized_groups", got.AuthorizedGroups, emptyAG},
		{"sources", got.Sources, strList("g1")},
	} {
		if !f.got.Equal(f.want) {
			t.Errorf("%s = %s, want %s", f.name, f.got, f.want)
		}
	}

	// A value the server does report wins over the prior one, and a prior
	// null stays null.
	data = PolicyModel{SourcePostureChecks: strList("pc1"), Rules: ruleList(readRule)}
	prior = PolicyModel{SourcePostureChecks: strList(), Rules: ruleList(ruleAllNull("tcp"))}
	if d := keepEmptyCollections(ctx, prior, &data); d.HasError() {
		t.Fatalf("keepEmptyCollections: %v", d)
	}
	if !data.SourcePostureChecks.Equal(strList("pc1")) {
		t.Errorf("source_posture_checks = %s, want [pc1]", data.SourcePostureChecks)
	}
	if !data.Rules.Equal(ruleList(readRule)) {
		t.Errorf("rules = %s, want the read value unchanged", data.Rules)
	}
}
