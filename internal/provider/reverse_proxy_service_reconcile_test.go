package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// optionsObject builds target options with the given attributes set and the
// rest null.
func optionsObject(t *testing.T, set map[string]attr.Value) types.Object {
	t.Helper()
	attrs := map[string]attr.Value{
		"skip_tls_verify":      types.BoolNull(),
		"request_timeout":      types.StringNull(),
		"path_rewrite":         types.StringNull(),
		"custom_headers":       types.MapNull(types.StringType),
		"proxy_protocol":       types.BoolNull(),
		"session_idle_timeout": types.StringNull(),
		"direct_upstream":      types.BoolNull(),
	}
	for k, v := range set {
		attrs[k] = v
	}
	obj, d := types.ObjectValue(ReverseProxyTargetOptionsModel{}.TFType().AttrTypes, attrs)
	if d.HasError() {
		t.Fatalf("building options: %v", d.Errors())
	}
	return obj
}

func withOptions(m ReverseProxyServiceTargetModel, opts types.Object) ReverseProxyServiceTargetModel {
	m.Options = opts
	return m
}

func targetList(t *testing.T, targets ...ReverseProxyServiceTargetModel) types.List {
	t.Helper()
	l, d := types.ListValueFrom(context.Background(), ReverseProxyServiceTargetModel{}.TFType(), targets)
	if d.HasError() {
		t.Fatalf("building targets: %v", d.Errors())
	}
	return l
}

// Read keeps a prior target value only where the API reports the same thing
// differently: a host the server derives from the peer or resource, a false
// option it omits, a duration it rewrites in canonical form. Anything else the
// server reports is what state gets, so a change made outside Terraform shows
// up as drift instead of being papered over by the old state.
func Test_reconcileTargets_drift(t *testing.T) {
	ctx := context.Background()
	preserve := types.StringValue("preserve")
	headers := func(v string) types.Map {
		return types.MapValueMust(types.StringType, map[string]attr.Value{"X-Env": types.StringValue(v)})
	}

	cases := []struct {
		name       string
		prior, api ReverseProxyServiceTargetModel
		want       ReverseProxyServiceTargetModel
	}{
		{
			name:  "peer host is derived by the server",
			prior: targetModel("peer1", "peer", "10.0.0.1", "/"),
			api:   targetModel("peer1", "peer", "100.64.0.9", "/"),
			want:  targetModel("peer1", "peer", "10.0.0.1", "/"),
		},
		{
			name:  "path changed on the server",
			prior: targetModel("peer1", "peer", "100.64.0.9", "/app"),
			api:   targetModel("peer1", "peer", "100.64.0.9", "/other"),
			want:  targetModel("peer1", "peer", "100.64.0.9", "/other"),
		},
		{
			name:  "subnet host changed on the server",
			prior: targetModel("res1", "subnet", "192.168.1.10", "/"),
			api:   targetModel("res1", "subnet", "192.168.1.20", "/"),
			want:  targetModel("res1", "subnet", "192.168.1.20", "/"),
		},
		{
			name:  "cluster host changed on the server",
			prior: targetModel("proxy.example.com", "cluster", "host.docker.internal", "/"),
			api:   targetModel("proxy.example.com", "cluster", "10.1.1.1", "/"),
			want:  targetModel("proxy.example.com", "cluster", "10.1.1.1", "/"),
		},
		{
			name:  "option removed on the server",
			prior: withOptions(targetModel("peer1", "peer", "", "/"), optionsObject(t, map[string]attr.Value{"path_rewrite": preserve})),
			api:   targetModel("peer1", "peer", "", "/"),
			want:  targetModel("peer1", "peer", "", "/"),
		},
		{
			name: "option changed on the server",
			prior: withOptions(targetModel("peer1", "peer", "", "/"),
				optionsObject(t, map[string]attr.Value{"custom_headers": headers("prod")})),
			api: withOptions(targetModel("peer1", "peer", "", "/"),
				optionsObject(t, map[string]attr.Value{"custom_headers": headers("dev")})),
			want: withOptions(targetModel("peer1", "peer", "", "/"),
				optionsObject(t, map[string]attr.Value{"custom_headers": headers("dev")})),
		},
		{
			// The server omits false booleans, which reads back as null.
			name: "false option omitted by the server",
			prior: withOptions(targetModel("peer1", "peer", "", "/"),
				optionsObject(t, map[string]attr.Value{"direct_upstream": types.BoolValue(false), "path_rewrite": preserve})),
			api: withOptions(targetModel("peer1", "peer", "", "/"),
				optionsObject(t, map[string]attr.Value{"path_rewrite": preserve})),
			want: withOptions(targetModel("peer1", "peer", "", "/"),
				optionsObject(t, map[string]attr.Value{"direct_upstream": types.BoolValue(false), "path_rewrite": preserve})),
		},
		{
			name: "only false options, all omitted",
			prior: withOptions(targetModel("peer1", "peer", "", "/"),
				optionsObject(t, map[string]attr.Value{"skip_tls_verify": types.BoolValue(false)})),
			api: targetModel("peer1", "peer", "", "/"),
			want: withOptions(targetModel("peer1", "peer", "", "/"),
				optionsObject(t, map[string]attr.Value{"skip_tls_verify": types.BoolValue(false)})),
		},
		{
			// The server stores a duration and writes it back canonically.
			name: "duration in another spelling",
			prior: withOptions(targetModel("peer1", "peer", "", "/"),
				optionsObject(t, map[string]attr.Value{"request_timeout": types.StringValue("60s")})),
			api: withOptions(targetModel("peer1", "peer", "", "/"),
				optionsObject(t, map[string]attr.Value{"request_timeout": types.StringValue("1m0s")})),
			want: withOptions(targetModel("peer1", "peer", "", "/"),
				optionsObject(t, map[string]attr.Value{"request_timeout": types.StringValue("60s")})),
		},
		{
			name: "duration changed on the server",
			prior: withOptions(targetModel("peer1", "peer", "", "/"),
				optionsObject(t, map[string]attr.Value{"request_timeout": types.StringValue("60s")})),
			api: withOptions(targetModel("peer1", "peer", "", "/"),
				optionsObject(t, map[string]attr.Value{"request_timeout": types.StringValue("45s")})),
			want: withOptions(targetModel("peer1", "peer", "", "/"),
				optionsObject(t, map[string]attr.Value{"request_timeout": types.StringValue("45s")})),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, d := reconcileTargets(ctx, targetList(t, c.prior), targetList(t, c.api))
			if d.HasError() {
				t.Fatalf("reconcileTargets: %v", d.Errors())
			}
			if want := targetList(t, c.want); !got.Equal(want) {
				t.Errorf("got  %v\nwant %v", got, want)
			}
		})
	}
}
