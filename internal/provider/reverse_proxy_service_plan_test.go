package provider

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// These tests drive the provider through the same protocol calls Terraform makes,
// without a Terraform binary or a server. The mapping tests cannot see plan
// behaviour: an attribute that goes unknown on update is dropped from the request
// by design, so the bug is in what the plan hands the mapping, not in the mapping.

const reverseProxyServiceType = "netbird_reverse_proxy_service"

// privateServiceAPI is a service in the shape the dashboard creates for a
// NetBird-only app: a private HTTP service whose single target is the proxy
// cluster itself, dialled directly on the proxy host.
func privateServiceAPI() *api.Service {
	mode := api.ServiceModeHttp
	preserve := api.ServiceTargetOptionsPathRewritePreserve
	return &api.Service{
		Id:               "svc-private",
		Name:             "jellyfin",
		Domain:           "jellyfin.proxy.example.com",
		Enabled:          true,
		Mode:             &mode,
		ListenPort:       valPtr(0),
		PortAutoAssigned: valPtr(false),
		PassHostHeader:   valPtr(true),
		RewriteRedirects: valPtr(false),
		ProxyCluster:     valPtr("proxy.example.com"),
		Private:          valPtr(true),
		AccessGroups:     &[]string{"group-family", "group-owner"},
		Targets: []api.ServiceTarget{{
			TargetId:   "proxy.example.com",
			TargetType: api.ServiceTargetTargetTypeCluster,
			Host:       valPtr("host.docker.internal"),
			Port:       8096,
			Protocol:   api.ServiceTargetProtocolHttp,
			Path:       valPtr("/"),
			Enabled:    true,
			Options: &api.ServiceTargetOptions{
				DirectUpstream: valPtr(true),
				PathRewrite:    &preserve,
			},
		}},
		Auth: api.ServiceAuthConfig{},
	}
}

// stateFromAPI is what Read leaves in state for svc, as after an import.
func stateFromAPI(t *testing.T, svc *api.Service) ReverseProxyServiceModel {
	t.Helper()
	var m ReverseProxyServiceModel
	if d := reverseProxyServiceAPIToTerraform(context.Background(), svc, &m); d.HasError() {
		t.Fatalf("mapping the prior state: %v", d.Errors())
	}
	return m
}

// configFromState is a configuration declaring everything state holds, leaving
// out only what is computed-only.
func configFromState(m ReverseProxyServiceModel) ReverseProxyServiceModel {
	m.Id = types.StringNull()
	m.ProxyCluster = types.StringNull()
	m.PortAutoAssigned = types.BoolNull()
	m.ListenPort = types.Int64Null()
	return m
}

// proposedNewState reproduces what Terraform core sends as the proposed new
// state: the configuration, with every computed attribute the configuration
// leaves null carried over from prior state. The exception, from core's
// optionalValueNotComputable, is an Optional and Computed nested attribute
// whose prior value sets any attribute that is not itself computed: core
// infers the configuration used to set it and proposes null.
func proposedNewState(t *testing.T, config, prior ReverseProxyServiceModel) ReverseProxyServiceModel {
	t.Helper()
	p := config
	p.Id = prior.Id
	p.ProxyCluster = prior.ProxyCluster
	p.PortAutoAssigned = prior.PortAutoAssigned
	if p.ListenPort.IsNull() {
		p.ListenPort = prior.ListenPort
	}
	if p.Mode.IsNull() {
		p.Mode = prior.Mode
	}
	if p.Private.IsNull() {
		p.Private = prior.Private
	}

	ctx := context.Background()
	var cfgTargets, priorTargets []ReverseProxyServiceTargetModel
	if d := config.Targets.ElementsAs(ctx, &cfgTargets, false); d.HasError() {
		t.Fatalf("reading config targets: %v", d.Errors())
	}
	if d := prior.Targets.ElementsAs(ctx, &priorTargets, false); d.HasError() {
		t.Fatalf("reading prior targets: %v", d.Errors())
	}
	restrictionsComputed, optionsComputed := computedBlocks()
	if restrictionsComputed && p.AccessRestrictions.IsNull() && !setsAnyAttribute(prior.AccessRestrictions) {
		p.AccessRestrictions = prior.AccessRestrictions
	}
	for i := range cfgTargets {
		if i >= len(priorTargets) {
			break
		}
		if cfgTargets[i].Host.IsNull() {
			cfgTargets[i].Host = priorTargets[i].Host
		}
		if cfgTargets[i].Path.IsNull() {
			cfgTargets[i].Path = priorTargets[i].Path
		}
		if optionsComputed && cfgTargets[i].Options.IsNull() && !setsAnyAttribute(priorTargets[i].Options) {
			cfgTargets[i].Options = priorTargets[i].Options
		}
	}
	list, d := types.ListValueFrom(ctx, ReverseProxyServiceTargetModel{}.TFType(), cfgTargets)
	if d.HasError() {
		t.Fatalf("building proposed targets: %v", d.Errors())
	}
	p.Targets = list
	return p
}

// setsAnyAttribute reports whether obj holds a non-null attribute. Every
// attribute inside access_restrictions and target options is Optional only.
func setsAnyAttribute(obj types.Object) bool {
	if obj.IsNull() || obj.IsUnknown() {
		return false
	}
	for _, v := range obj.Attributes() {
		if !v.IsNull() {
			return true
		}
	}
	return false
}

// computedBlocks reports whether access_restrictions and target options are
// computed, which decides whether core proposes their prior value when the
// configuration leaves them out.
func computedBlocks() (restrictions, options bool) {
	var sr resource.SchemaResponse
	(&ReverseProxyService{}).Schema(context.Background(), resource.SchemaRequest{}, &sr)
	restrictions = sr.Schema.Attributes["access_restrictions"].IsComputed()
	if targets, ok := sr.Schema.Attributes["targets"].(schema.ListNestedAttribute); ok {
		options = targets.NestedObject.Attributes["options"].IsComputed()
	}
	return restrictions, options
}

func reverseProxyServiceProtocol(t *testing.T) (tfprotov6.ProviderServer, tfsdk.State) {
	t.Helper()
	srv, err := providerserver.NewProtocol6WithError(New("test")())()
	if err != nil {
		t.Fatalf("starting the provider server: %v", err)
	}
	var sr resource.SchemaResponse
	(&ReverseProxyService{}).Schema(context.Background(), resource.SchemaRequest{}, &sr)
	empty := tfsdk.State{
		Schema: sr.Schema,
		Raw:    tftypes.NewValue(sr.Schema.Type().TerraformType(context.Background()), nil),
	}
	return srv, empty
}

func dynamicValue(t *testing.T, empty tfsdk.State, m ReverseProxyServiceModel) *tfprotov6.DynamicValue {
	t.Helper()
	s := empty
	if d := s.Set(context.Background(), &m); d.HasError() {
		t.Fatalf("encoding the model: %v", d.Errors())
	}
	dv, err := tfprotov6.NewDynamicValue(s.Raw.Type(), s.Raw)
	if err != nil {
		t.Fatalf("encoding the dynamic value: %v", err)
	}
	return &dv
}

func protocolErrors(diags []*tfprotov6.Diagnostic) []string {
	var out []string
	for _, d := range diags {
		if d.Severity == tfprotov6.DiagnosticSeverityError {
			out = append(out, d.Summary+": "+d.Detail)
		}
	}
	return out
}

// planUpdate plans an in-place update from prior to config and returns the
// planned state.
func planUpdate(t *testing.T, prior, config ReverseProxyServiceModel) ReverseProxyServiceModel {
	t.Helper()
	_, out := plan(t, prior, config)
	return out
}

func planResponse(t *testing.T, prior, config ReverseProxyServiceModel) (*tfprotov6.PlanResourceChangeResponse, tfsdk.State) {
	t.Helper()
	srv, empty := reverseProxyServiceProtocol(t)
	resp, err := srv.PlanResourceChange(context.Background(), &tfprotov6.PlanResourceChangeRequest{
		TypeName:         reverseProxyServiceType,
		PriorState:       dynamicValue(t, empty, prior),
		ProposedNewState: dynamicValue(t, empty, proposedNewState(t, config, prior)),
		Config:           dynamicValue(t, empty, config),
	})
	if err != nil {
		t.Fatalf("PlanResourceChange: %v", err)
	}
	return resp, empty
}

// planIsEmpty reports whether Terraform would plan no change: core compares the
// planned state with the prior state.
func planIsEmpty(t *testing.T, prior, config ReverseProxyServiceModel) bool {
	t.Helper()
	raw, _ := plan(t, prior, config)
	_, empty := reverseProxyServiceProtocol(t)
	priorDV := dynamicValue(t, empty, prior)
	priorRaw, err := priorDV.Unmarshal(empty.Raw.Type())
	if err != nil {
		t.Fatalf("decoding the prior state: %v", err)
	}
	if !raw.Equal(priorRaw) {
		diffs, _ := priorRaw.Diff(raw)
		for _, d := range diffs {
			t.Logf("planned change at %s: %v -> %v", d.Path, d.Value1, d.Value2)
		}
		return false
	}
	return true
}

func plan(t *testing.T, prior, config ReverseProxyServiceModel) (tftypes.Value, ReverseProxyServiceModel) {
	t.Helper()
	ctx := context.Background()
	resp, empty := planResponse(t, prior, config)
	if errs := protocolErrors(resp.Diagnostics); len(errs) > 0 {
		t.Fatalf("PlanResourceChange: %s", strings.Join(errs, "; "))
	}

	raw, err := resp.PlannedState.Unmarshal(empty.Raw.Type())
	if err != nil {
		t.Fatalf("decoding the planned state: %v", err)
	}
	planned := tfsdk.Plan{Schema: empty.Schema, Raw: raw}
	var out ReverseProxyServiceModel
	if d := planned.Get(ctx, &out); d.HasError() {
		t.Fatalf("reading the planned state: %v", d.Errors())
	}
	return raw, out
}

// validateConfig runs ValidateResourceConfig and returns the error summaries
// with the attribute each is attached to.
func validateConfig(t *testing.T, config ReverseProxyServiceModel) []string {
	t.Helper()
	srv, empty := reverseProxyServiceProtocol(t)
	resp, err := srv.ValidateResourceConfig(context.Background(), &tfprotov6.ValidateResourceConfigRequest{
		TypeName: reverseProxyServiceType,
		Config:   dynamicValue(t, empty, config),
	})
	if err != nil {
		t.Fatalf("ValidateResourceConfig: %v", err)
	}
	var out []string
	for _, d := range resp.Diagnostics {
		if d.Severity != tfprotov6.DiagnosticSeverityError {
			continue
		}
		var at []string
		if d.Attribute != nil {
			for _, step := range d.Attribute.Steps() {
				if name, ok := step.(tftypes.AttributeName); ok {
					at = append(at, string(name))
				}
			}
		}
		out = append(out, strings.Join(at, ".")+": "+d.Summary)
	}
	return out
}

// An update that touches something unrelated must not turn a private service
// public.
func Test_reverseProxyServicePlan_keepsPrivate(t *testing.T) {
	prior := stateFromAPI(t, privateServiceAPI())
	config := configFromState(prior)
	config.PassHostHeader = types.BoolValue(false)

	req := planUpdateRequest(t, prior, config)
	if req.Private == nil || !*req.Private {
		t.Errorf("request private = %v, want true", req.Private)
	}
	if req.AccessGroups == nil || !reflect.DeepEqual(*req.AccessGroups, []string{"group-family", "group-owner"}) {
		t.Errorf("request access_groups = %v, want both groups in order", req.AccessGroups)
	}
}

// A configuration written before private existed names neither private nor
// access_groups. private keeps the server's value, so the request is refused
// for lacking access groups; what must not happen is a request that quietly
// makes the service public.
func Test_reverseProxyServicePlan_keepsPrivateWhenUnset(t *testing.T) {
	prior := stateFromAPI(t, privateServiceAPI())
	config := configFromState(prior)
	config.Private = types.BoolNull()
	config.AccessGroups = types.ListNull(types.StringType)
	config.PassHostHeader = types.BoolValue(false)

	req := planUpdateRequest(t, prior, config)
	if req.Private == nil || !*req.Private {
		t.Fatalf("request private = %v, want true", req.Private)
	}
}

// planUpdateRequest plans the update and maps the planned state to the request
// Update would send.
func planUpdateRequest(t *testing.T, prior, config ReverseProxyServiceModel) api.ServiceRequest {
	t.Helper()
	planned := planUpdate(t, prior, config)
	req, d := reverseProxyServiceTerraformToAPI(context.Background(), &planned)
	if d.HasError() {
		t.Fatalf("TerraformToAPI: %v", d.Errors())
	}
	return req
}

func Test_reverseProxyService_validateConfig_private(t *testing.T) {
	ctx := context.Background()
	base := configFromState(stateFromAPI(t, privateServiceAPI()))
	groups := func(ids ...string) types.List {
		l, _ := types.ListValueFrom(ctx, types.StringType, ids)
		return l
	}
	withBearer := func(m ReverseProxyServiceModel, enabled types.Bool) ReverseProxyServiceModel {
		bearer := mustObjectValue(ctx, ReverseProxyBearerAuthModel{}.TFType().AttrTypes, ReverseProxyBearerAuthModel{
			Enabled:            enabled,
			DistributionGroups: types.ListNull(types.StringType),
		})
		attrs := m.Auth.Attributes()
		attrs["bearer_auth"] = bearer
		m.Auth = types.ObjectValueMust(ReverseProxyServiceAuthModel{}.TFType().AttrTypes, attrs)
		return m
	}

	cases := []struct {
		name   string
		mutate func(ReverseProxyServiceModel) ReverseProxyServiceModel
		want   string // attribute path of the expected error, "" for none
	}{
		{
			name:   "the deployment shape",
			mutate: func(m ReverseProxyServiceModel) ReverseProxyServiceModel { return m },
		},
		{
			name: "access_groups without private",
			mutate: func(m ReverseProxyServiceModel) ReverseProxyServiceModel {
				m.Private = types.BoolNull()
				return m
			},
			want: "access_groups",
		},
		{
			name: "access_groups on a public service",
			mutate: func(m ReverseProxyServiceModel) ReverseProxyServiceModel {
				m.Private = types.BoolValue(false)
				return m
			},
			want: "access_groups",
		},
		{
			name: "private without access_groups",
			mutate: func(m ReverseProxyServiceModel) ReverseProxyServiceModel {
				m.AccessGroups = types.ListNull(types.StringType)
				return m
			},
			want: "access_groups",
		},
		{
			name: "private with an empty access_groups",
			mutate: func(m ReverseProxyServiceModel) ReverseProxyServiceModel {
				m.AccessGroups = groups()
				return m
			},
			want: "access_groups",
		},
		{
			name: "private in tcp mode",
			mutate: func(m ReverseProxyServiceModel) ReverseProxyServiceModel {
				m.Mode = types.StringValue("tcp")
				return m
			},
			want: "mode",
		},
		{
			name: "private with bearer auth enabled",
			mutate: func(m ReverseProxyServiceModel) ReverseProxyServiceModel {
				return withBearer(m, types.BoolValue(true))
			},
			want: "auth.bearer_auth.enabled",
		},
		{
			name: "private with bearer auth disabled",
			mutate: func(m ReverseProxyServiceModel) ReverseProxyServiceModel {
				return withBearer(m, types.BoolValue(false))
			},
		},
		{
			name: "public service with bearer auth",
			mutate: func(m ReverseProxyServiceModel) ReverseProxyServiceModel {
				m.Private = types.BoolNull()
				m.AccessGroups = types.ListNull(types.StringType)
				return withBearer(m, types.BoolValue(true))
			},
		},
		// Values that are not known until apply, typically IDs of groups
		// created in the same run, are not errors at plan time.
		{
			name: "access_groups unknown",
			mutate: func(m ReverseProxyServiceModel) ReverseProxyServiceModel {
				m.AccessGroups = types.ListUnknown(types.StringType)
				return m
			},
		},
		{
			name: "private unknown",
			mutate: func(m ReverseProxyServiceModel) ReverseProxyServiceModel {
				m.Private = types.BoolUnknown()
				return m
			},
		},
		{
			name: "mode unknown",
			mutate: func(m ReverseProxyServiceModel) ReverseProxyServiceModel {
				m.Mode = types.StringUnknown()
				return m
			},
		},
		{
			name: "bearer auth enabled unknown",
			mutate: func(m ReverseProxyServiceModel) ReverseProxyServiceModel {
				return withBearer(m, types.BoolUnknown())
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := validateConfig(t, c.mutate(base))
			if c.want == "" {
				if len(errs) > 0 {
					t.Fatalf("unexpected errors: %v", errs)
				}
				return
			}
			if len(errs) != 1 {
				t.Fatalf("want one error on %s, got %v", c.want, errs)
			}
			if !strings.Contains(errs[0], c.want+": ") {
				t.Errorf("error %q is not on %s", errs[0], c.want)
			}
		})
	}
}

// targetModel builds a target the way configuration or state holds one.
func targetModel(id, typ, host, path string) ReverseProxyServiceTargetModel {
	str := func(s string) types.String {
		if s == "" {
			return types.StringNull()
		}
		return types.StringValue(s)
	}
	return ReverseProxyServiceTargetModel{
		TargetId:   types.StringValue(id),
		TargetType: types.StringValue(typ),
		Host:       str(host),
		Port:       types.Int64Value(8080),
		Protocol:   types.StringValue("http"),
		Path:       str(path),
		Enabled:    types.BoolValue(true),
		Options:    types.ObjectNull(ReverseProxyTargetOptionsModel{}.TFType().AttrTypes),
	}
}

func withTargets(t *testing.T, m ReverseProxyServiceModel, targets ...ReverseProxyServiceTargetModel) ReverseProxyServiceModel {
	t.Helper()
	list, d := types.ListValueFrom(context.Background(), ReverseProxyServiceTargetModel{}.TFType(), targets)
	if d.HasError() {
		t.Fatalf("building targets: %v", d.Errors())
	}
	m.Targets = list
	return m
}

type hostPath struct{ host, path *string }

func requestHostPaths(req api.ServiceRequest) []hostPath {
	var out []hostPath
	for _, tgt := range *req.Targets {
		out = append(out, hostPath{tgt.Host, tgt.Path})
	}
	return out
}

func (h hostPath) String() string {
	deref := func(p *string) string {
		if p == nil {
			return "<omitted>"
		}
		return *p
	}
	return "host=" + deref(h.host) + " path=" + deref(h.path)
}

// A target's host and path are Optional and Computed, so leaving them out of
// the configuration used to plan them as unknown on every update, and the
// request then omitted them. The PUT replaces the service: the server reset the
// path, and refused cluster and subnet targets outright for having no host.
func Test_reverseProxyServicePlan_keepsUnconfiguredTargetHostAndPath(t *testing.T) {
	str := func(s string) *string { return &s }

	cases := []struct {
		name   string
		prior  []ReverseProxyServiceTargetModel
		config []ReverseProxyServiceTargetModel
		want   []hostPath
	}{
		{
			name:   "cluster target",
			prior:  []ReverseProxyServiceTargetModel{targetModel("proxy.example.com", "cluster", "host.docker.internal", "/")},
			config: []ReverseProxyServiceTargetModel{targetModel("proxy.example.com", "cluster", "", "")},
			want:   []hostPath{{str("host.docker.internal"), str("/")}},
		},
		{
			name:   "subnet target with a path",
			prior:  []ReverseProxyServiceTargetModel{targetModel("res-subnet", "subnet", "192.168.1.10", "/api")},
			config: []ReverseProxyServiceTargetModel{targetModel("res-subnet", "subnet", "", "")},
			want:   []hostPath{{str("192.168.1.10"), str("/api")}},
		},
		{
			name:   "configured values win",
			prior:  []ReverseProxyServiceTargetModel{targetModel("res-subnet", "subnet", "192.168.1.10", "/api")},
			config: []ReverseProxyServiceTargetModel{targetModel("res-subnet", "subnet", "192.168.1.20", "/v2")},
			want:   []hostPath{{str("192.168.1.20"), str("/v2")}},
		},
		{
			// A path the server never reported stays absent rather than
			// becoming an explicit value.
			name:   "absent on the server",
			prior:  []ReverseProxyServiceTargetModel{targetModel("peer1", "peer", "100.64.0.1", "")},
			config: []ReverseProxyServiceTargetModel{targetModel("peer1", "peer", "", "")},
			want:   []hostPath{{str("100.64.0.1"), nil}},
		},
		{
			// Matching is by target, not by position, so a reordered list
			// does not hand one target's host to another.
			name: "reordered targets",
			prior: []ReverseProxyServiceTargetModel{
				targetModel("res-a", "subnet", "192.168.1.10", "/a"),
				targetModel("res-b", "subnet", "192.168.1.20", "/b"),
			},
			config: []ReverseProxyServiceTargetModel{
				targetModel("res-b", "subnet", "", ""),
				targetModel("res-a", "subnet", "", ""),
			},
			want: []hostPath{{str("192.168.1.20"), str("/b")}, {str("192.168.1.10"), str("/a")}},
		},
		{
			// Targets sharing a resource are told apart by their path, which
			// configuration must then set.
			name: "same resource twice, reordered",
			prior: []ReverseProxyServiceTargetModel{
				targetModel("res-a", "subnet", "192.168.1.10", "/a"),
				targetModel("res-a", "subnet", "192.168.1.20", "/b"),
				targetModel("res-c", "subnet", "192.168.1.30", "/c"),
			},
			config: []ReverseProxyServiceTargetModel{
				targetModel("res-c", "subnet", "", ""),
				targetModel("res-a", "subnet", "", "/b"),
				targetModel("res-a", "subnet", "", "/a"),
			},
			want: []hostPath{{str("192.168.1.30"), str("/c")}, {str("192.168.1.20"), str("/b")}, {str("192.168.1.10"), str("/a")}},
		},
		{
			// A new target on a resource another target already uses is new:
			// it must not inherit that target's host.
			name:  "adding a target on a shared resource",
			prior: []ReverseProxyServiceTargetModel{targetModel("res-a", "subnet", "192.168.1.10", "/a")},
			config: []ReverseProxyServiceTargetModel{
				targetModel("res-a", "subnet", "", "/new"),
				targetModel("res-a", "subnet", "", "/a"),
			},
			want: []hostPath{{nil, str("/new")}, {str("192.168.1.10"), str("/a")}},
		},
		{
			name:  "new target",
			prior: []ReverseProxyServiceTargetModel{targetModel("res-a", "subnet", "192.168.1.10", "/a")},
			config: []ReverseProxyServiceTargetModel{
				targetModel("res-a", "subnet", "", ""),
				targetModel("peer9", "peer", "", ""),
			},
			want: []hostPath{{str("192.168.1.10"), str("/a")}, {nil, nil}},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := stateFromAPI(t, privateServiceAPI())
			prior := withTargets(t, base, c.prior...)
			config := withTargets(t, configFromState(base), c.config...)
			config.PassHostHeader = types.BoolValue(false)

			got := requestHostPaths(planUpdateRequest(t, prior, config))
			if len(got) != len(c.want) {
				t.Fatalf("got %d targets, want %d", len(got), len(c.want))
			}
			for i := range got {
				if got[i].String() != c.want[i].String() {
					t.Errorf("target %d: %s, want %s", i, got[i], c.want[i])
				}
			}
		})
	}
}

// The deployment shape end to end: import leaves state as the server holds it,
// the configuration declares the service without host or path, and changing
// pass_host_header must send everything else back unchanged.
func Test_reverseProxyServicePlan_privateServiceUpdate(t *testing.T) {
	prior := stateFromAPI(t, privateServiceAPI())
	config := configFromState(prior)
	config.PassHostHeader = types.BoolValue(false)
	var targets []ReverseProxyServiceTargetModel
	if d := config.Targets.ElementsAs(context.Background(), &targets, false); d.HasError() {
		t.Fatalf("reading targets: %v", d.Errors())
	}
	targets[0].Host = types.StringNull()
	targets[0].Path = types.StringNull()
	config = withTargets(t, config, targets...)

	req := planUpdateRequest(t, prior, config)
	if req.Private == nil || !*req.Private {
		t.Errorf("private = %v, want true", req.Private)
	}
	if req.AccessGroups == nil || len(*req.AccessGroups) != 2 {
		t.Errorf("access_groups = %v, want both groups", req.AccessGroups)
	}
	if req.PassHostHeader == nil || *req.PassHostHeader {
		t.Errorf("pass_host_header = %v, want false", req.PassHostHeader)
	}
	tgt := (*req.Targets)[0]
	if got := (hostPath{tgt.Host, tgt.Path}).String(); got != "host=host.docker.internal path=/" {
		t.Errorf("target %s, want host=host.docker.internal path=/", got)
	}
	if tgt.Options == nil || tgt.Options.DirectUpstream == nil || !*tgt.Options.DirectUpstream {
		t.Errorf("direct_upstream dropped: %+v", tgt.Options)
	}
}

func Test_reverseProxyService_validateConfig_sharedTargets(t *testing.T) {
	base := configFromState(stateFromAPI(t, privateServiceAPI()))

	cases := []struct {
		name    string
		targets []ReverseProxyServiceTargetModel
		wantErr bool
	}{
		{
			name: "distinct paths",
			targets: []ReverseProxyServiceTargetModel{
				targetModel("peer1", "peer", "", "/"),
				targetModel("peer1", "peer", "", "/api"),
			},
		},
		{
			name: "one without a path",
			targets: []ReverseProxyServiceTargetModel{
				targetModel("peer1", "peer", "", "/api"),
				targetModel("peer1", "peer", "", ""),
			},
			wantErr: true,
		},
		{
			name: "the same path twice",
			targets: []ReverseProxyServiceTargetModel{
				targetModel("peer1", "peer", "", "/api"),
				targetModel("peer1", "peer", "", "/api"),
			},
			wantErr: true,
		},
		{
			name: "same ID, different types",
			targets: []ReverseProxyServiceTargetModel{
				targetModel("x", "peer", "", ""),
				targetModel("x", "subnet", "192.168.1.10", ""),
			},
		},
		{
			name: "path not known yet",
			targets: []ReverseProxyServiceTargetModel{
				targetModel("peer1", "peer", "", "/api"),
				func() ReverseProxyServiceTargetModel {
					m := targetModel("peer1", "peer", "", "")
					m.Path = types.StringUnknown()
					return m
				}(),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := validateConfig(t, withTargets(t, base, c.targets...))
			if !c.wantErr {
				if len(errs) > 0 {
					t.Fatalf("unexpected errors: %v", errs)
				}
				return
			}
			if len(errs) != 1 || !strings.HasPrefix(errs[0], "targets.path: ") {
				t.Fatalf("want one error on targets.path, got %v", errs)
			}
		})
	}
}

// withRestrictions sets access_restrictions from the given attributes, the rest
// null.
func withRestrictions(t *testing.T, m ReverseProxyServiceModel, set map[string]attr.Value) ReverseProxyServiceModel {
	t.Helper()
	list := types.ListNull(types.StringType)
	attrs := map[string]attr.Value{
		"allowed_cidrs":     list,
		"blocked_cidrs":     list,
		"allowed_countries": list,
		"blocked_countries": list,
		"crowdsec_mode":     types.StringNull(),
	}
	for k, v := range set {
		attrs[k] = v
	}
	obj, d := types.ObjectValue(ReverseProxyAccessRestrictionsModel{}.TFType().AttrTypes, attrs)
	if d.HasError() {
		t.Fatalf("building access_restrictions: %v", d.Errors())
	}
	m.AccessRestrictions = obj
	return m
}

// Target options and access restrictions left out of the configuration used
// to plan as null, and the PUT that replaces the whole service then removed
// them. Left out now means keep; an empty block removes them.
func Test_reverseProxyServicePlan_keepsUnconfiguredOptionsAndRestrictions(t *testing.T) {
	prior := withRestrictions(t, stateFromAPI(t, privateServiceAPI()), map[string]attr.Value{
		"allowed_countries": types.ListValueMust(types.StringType, []attr.Value{types.StringValue("DE")}),
		"crowdsec_mode":     types.StringValue("observe"),
	})

	t.Run("left out", func(t *testing.T) {
		config := configFromState(prior)
		config.PassHostHeader = types.BoolValue(false)
		config.AccessRestrictions = types.ObjectNull(ReverseProxyAccessRestrictionsModel{}.TFType().AttrTypes)
		var targets []ReverseProxyServiceTargetModel
		if d := config.Targets.ElementsAs(context.Background(), &targets, false); d.HasError() {
			t.Fatalf("reading targets: %v", d.Errors())
		}
		targets[0].Options = types.ObjectNull(ReverseProxyTargetOptionsModel{}.TFType().AttrTypes)
		config = withTargets(t, config, targets...)

		req := planUpdateRequest(t, prior, config)
		opts := (*req.Targets)[0].Options
		if opts == nil || !isTrue(opts.DirectUpstream) || opts.PathRewrite == nil {
			t.Errorf("target options dropped: %+v", opts)
		}
		ar := req.AccessRestrictions
		if ar == nil || ar.AllowedCountries == nil || len(*ar.AllowedCountries) != 1 || ar.CrowdsecMode == nil {
			t.Errorf("access_restrictions dropped: %+v", ar)
		}
	})

	t.Run("emptied", func(t *testing.T) {
		config := withRestrictions(t, configFromState(prior), nil)
		var targets []ReverseProxyServiceTargetModel
		if d := config.Targets.ElementsAs(context.Background(), &targets, false); d.HasError() {
			t.Fatalf("reading targets: %v", d.Errors())
		}
		targets[0].Options = optionsObject(t, nil)
		config = withTargets(t, config, targets...)

		req := planUpdateRequest(t, prior, config)
		if opts := (*req.Targets)[0].Options; opts != nil {
			t.Errorf("target options = %+v, want none", opts)
		}
		if req.AccessRestrictions != nil {
			t.Errorf("access_restrictions = %+v, want none", req.AccessRestrictions)
		}
	})
}

// mode is Optional and Computed, so an L4 service whose configuration leaves it
// out planned it as unknown on update and the request omitted it. The server
// defaults a missing mode to "http" and refuses the change from "tcp", so every
// update to such a service failed.
func Test_reverseProxyServicePlan_keepsUnconfiguredMode(t *testing.T) {
	svc := privateServiceAPI()
	tcp := api.ServiceModeTcp
	svc.Mode = &tcp
	svc.ListenPort = valPtr(15432)
	svc.Private = valPtr(false)
	svc.AccessGroups = nil
	svc.Targets = []api.ServiceTarget{{
		TargetId:   "peer1",
		TargetType: api.ServiceTargetTargetTypePeer,
		Host:       valPtr("100.64.0.9"),
		Port:       5432,
		Protocol:   api.ServiceTargetProtocolTcp,
		Enabled:    true,
	}}
	prior := stateFromAPI(t, svc)
	config := configFromState(prior)
	config.Mode = types.StringNull()
	config.Private = types.BoolNull()
	config.ListenPort = types.Int64Value(15433)

	req := planUpdateRequest(t, prior, config)
	if req.Mode == nil || *req.Mode != api.ServiceRequestModeTcp {
		t.Errorf("request mode = %v, want tcp", req.Mode)
	}
}

// After an apply that left target options and access restrictions out of the
// configuration, state still holds them, and core then proposes null for both
// because they set attributes that are not computed. Any difference from prior
// state makes the framework mark every unconfigured computed attribute
// unknown; the modifiers put options and restrictions back, and every other
// computed attribute has to come back too or the plan is never empty.
func Test_reverseProxyServicePlan_emptyAfterUnconfiguredBlocks(t *testing.T) {
	svc := privateServiceAPI()
	svc.Private = valPtr(false)
	svc.AccessGroups = nil
	svc.Targets[0].TargetType = "peer"
	prior := withRestrictions(t, stateFromAPI(t, svc), map[string]attr.Value{
		"allowed_countries": types.ListValueMust(types.StringType, []attr.Value{types.StringValue("DE")}),
	})

	config := configFromState(prior)
	config.Private = types.BoolNull()
	config.AccessGroups = types.ListNull(types.StringType)
	config.AccessRestrictions = types.ObjectNull(ReverseProxyAccessRestrictionsModel{}.TFType().AttrTypes)
	var targets []ReverseProxyServiceTargetModel
	if d := config.Targets.ElementsAs(context.Background(), &targets, false); d.HasError() {
		t.Fatalf("reading targets: %v", d.Errors())
	}
	targets[0].Host = types.StringNull()
	targets[0].Options = types.ObjectNull(ReverseProxyTargetOptionsModel{}.TFType().AttrTypes)
	config = withTargets(t, config, targets...)

	if !planIsEmpty(t, prior, config) {
		t.Error("plan right after apply is not empty")
	}
}

// Empty blocks remove options and restrictions, and the server then reports
// neither. State keeps the empty blocks, so the next plan is empty; where
// state has nothing, as after an import, one update brings it in line.
func Test_reverseProxyServicePlan_emptyBlocksConverge(t *testing.T) {
	ctx := context.Background()
	svc := privateServiceAPI()
	svc.Targets[0].Options = nil
	imported := stateFromAPI(t, svc)

	config := withRestrictions(t, configFromState(imported), nil)
	var targets []ReverseProxyServiceTargetModel
	if d := config.Targets.ElementsAs(ctx, &targets, false); d.HasError() {
		t.Fatalf("reading targets: %v", d.Errors())
	}
	targets[0].Options = optionsObject(t, nil)
	config = withTargets(t, config, targets...)

	if planIsEmpty(t, imported, config) {
		t.Fatal("empty blocks against an import that has none should plan one update")
	}

	// What Update stores: the API reports no options or restrictions, and
	// reconciling against the plan keeps the empty blocks.
	planned := planUpdate(t, imported, config)
	applied := stateFromAPI(t, svc)
	applied.AccessRestrictions = reconcileObject(ctx, planned.AccessRestrictions, applied.AccessRestrictions)
	reconciled, d := reconcileTargets(ctx, planned.Targets, applied.Targets)
	if d.HasError() {
		t.Fatalf("reconcileTargets: %v", d.Errors())
	}
	applied.Targets = reconciled

	if !planIsEmpty(t, applied, config) {
		t.Error("plan after applying the empty blocks is not empty")
	}
}

// proxy_cluster follows the domain and port_auto_assigned follows listen_port,
// so each is kept only while its source is.
func Test_reverseProxyServicePlan_derivedAttributesFollowTheirSource(t *testing.T) {
	prior := stateFromAPI(t, privateServiceAPI())

	moved := configFromState(prior)
	moved.Domain = types.StringValue("jellyfin.other.example.com")
	if got := planUpdate(t, prior, moved).ProxyCluster; !got.IsUnknown() {
		t.Errorf("proxy_cluster after a domain change = %v, want unknown", got)
	}

	ported := configFromState(prior)
	ported.ListenPort = types.Int64Value(15000)
	if got := planUpdate(t, prior, ported).PortAutoAssigned; !got.IsUnknown() {
		t.Errorf("port_auto_assigned after a listen_port change = %v, want unknown", got)
	}

	unchanged := configFromState(prior)
	unchanged.PassHostHeader = types.BoolValue(false)
	planned := planUpdate(t, prior, unchanged)
	if !planned.ProxyCluster.Equal(prior.ProxyCluster) || !planned.PortAutoAssigned.Equal(prior.PortAutoAssigned) || !planned.ListenPort.Equal(prior.ListenPort) {
		t.Errorf("unrelated update planned proxy_cluster %v, port_auto_assigned %v, listen_port %v; want the prior values",
			planned.ProxyCluster, planned.PortAutoAssigned, planned.ListenPort)
	}
}

// Targets sharing a resource are matched to prior state by path, so changing
// one target's path loses its match. Where exactly one target of that resource
// is left on each side, they are the same target; anything else is refused
// rather than guessed, because a wrong match sends another target's host and
// options, and no match sends none and the server clears them.
func Test_reverseProxyServicePlan_sharedTargetPathChange(t *testing.T) {
	timeout := func(v string) types.Object {
		return optionsObject(t, map[string]attr.Value{"request_timeout": types.StringValue(v)})
	}
	base := stateFromAPI(t, privateServiceAPI())

	t.Run("one path changed", func(t *testing.T) {
		prior := withTargets(t, base,
			withOptions(targetModel("res-a", "subnet", "192.168.1.10", "/a"), timeout("10s")),
			withOptions(targetModel("res-a", "subnet", "192.168.1.20", "/b"), timeout("20s")),
		)
		config := withTargets(t, configFromState(base),
			withOptions(targetModel("res-a", "subnet", "", "/a"), types.ObjectNull(ReverseProxyTargetOptionsModel{}.TFType().AttrTypes)),
			withOptions(targetModel("res-a", "subnet", "", "/c"), types.ObjectNull(ReverseProxyTargetOptionsModel{}.TFType().AttrTypes)),
		)

		req := planUpdateRequest(t, prior, config)
		got := (*req.Targets)[1]
		if got.Host == nil || *got.Host != "192.168.1.20" {
			t.Errorf("host = %v, want the /b target's 192.168.1.20", got.Host)
		}
		if got.Options == nil || got.Options.RequestTimeout == nil || *got.Options.RequestTimeout != "20s" {
			t.Errorf("options = %+v, want the /b target's", got.Options)
		}
	})

	t.Run("two paths changed", func(t *testing.T) {
		prior := withTargets(t, base,
			withOptions(targetModel("res-a", "subnet", "192.168.1.10", "/a"), timeout("10s")),
			withOptions(targetModel("res-a", "subnet", "192.168.1.20", "/b"), timeout("20s")),
			withOptions(targetModel("res-a", "subnet", "192.168.1.30", "/c"), timeout("30s")),
		)
		config := withTargets(t, configFromState(base),
			withOptions(targetModel("res-a", "subnet", "", "/a"), types.ObjectNull(ReverseProxyTargetOptionsModel{}.TFType().AttrTypes)),
			withOptions(targetModel("res-a", "subnet", "", "/x"), types.ObjectNull(ReverseProxyTargetOptionsModel{}.TFType().AttrTypes)),
			withOptions(targetModel("res-a", "subnet", "", "/y"), types.ObjectNull(ReverseProxyTargetOptionsModel{}.TFType().AttrTypes)),
		)

		resp, _ := planResponse(t, prior, config)
		errs := protocolErrors(resp.Diagnostics)
		if len(errs) != 2 {
			t.Fatalf("want an error for each of the two unmatched targets, got %v", errs)
		}
		for _, e := range errs {
			if !strings.Contains(e, "host") || !strings.Contains(e, "options") {
				t.Errorf("error does not say to set host and options: %s", e)
			}
		}
	})

	t.Run("configured explicitly", func(t *testing.T) {
		prior := withTargets(t, base,
			withOptions(targetModel("res-a", "subnet", "192.168.1.10", "/a"), timeout("10s")),
			withOptions(targetModel("res-a", "subnet", "192.168.1.20", "/b"), timeout("20s")),
			withOptions(targetModel("res-a", "subnet", "192.168.1.30", "/c"), timeout("30s")),
		)
		config := withTargets(t, configFromState(base),
			withOptions(targetModel("res-a", "subnet", "192.168.1.10", "/a"), timeout("10s")),
			withOptions(targetModel("res-a", "subnet", "192.168.1.40", "/x"), timeout("40s")),
			withOptions(targetModel("res-a", "subnet", "192.168.1.50", "/y"), optionsObject(t, nil)),
		)
		if errs := protocolErrors(func() []*tfprotov6.Diagnostic { r, _ := planResponse(t, prior, config); return r.Diagnostics }()); len(errs) > 0 {
			t.Fatalf("unexpected errors: %v", errs)
		}
	})
}
