package provider

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func Test_accountAPIToTerraform(t *testing.T) {
	cases := []struct {
		resource *api.Account
		expected AccountSettingsModel
	}{
		{
			resource: &api.Account{
				Id: "a",
				Settings: api.AccountSettings{
					AutoUpdateVersion:               nil,
					DnsDomain:                       nil,
					NetworkRange:                    nil,
					NetworkRangeV6:                  nil,
					Ipv6EnabledGroups:               nil,
					LazyConnectionEnabled:           nil,
					GroupsPropagationEnabled:        nil,
					JwtAllowGroups:                  nil,
					JwtGroupsClaimName:              nil,
					JwtGroupsEnabled:                nil,
					PeerInactivityExpiration:        1800,
					PeerInactivityExpirationEnabled: false,
					PeerLoginExpiration:             1800,
					PeerLoginExpirationEnabled:      false,
					RegularUsersViewBlocked:         false,
					RoutingPeerDnsResolutionEnabled: nil,
					PeerExposeEnabled:               false,
					PeerExposeGroups:                nil,
					Extra: &api.AccountExtraSettings{
						NetworkTrafficLogsEnabled:          false,
						NetworkTrafficPacketCounterEnabled: false,
						PeerApprovalEnabled:                false,
						UserApprovalRequired:               false,
						NetworkTrafficLogsGroups:           nil,
					},
				},
			},
			expected: AccountSettingsModel{
				Id:                                 types.StringValue("a"),
				JwtAllowGroups:                     types.ListNull(types.StringType),
				JwtGroupsClaimName:                 types.StringNull(),
				PeerLoginExpiration:                types.Int32Value(1800),
				PeerInactivityExpiration:           types.Int32Value(1800),
				PeerLoginExpirationEnabled:         types.BoolValue(false),
				PeerInactivityExpirationEnabled:    types.BoolValue(false),
				RegularUsersViewBlocked:            types.BoolValue(false),
				GroupsPropagationEnabled:           types.BoolNull(),
				JwtGroupsEnabled:                   types.BoolNull(),
				RoutingPeerDnsResolutionEnabled:    types.BoolNull(),
				PeerApprovalEnabled:                types.BoolValue(false),
				NetworkTrafficLogsEnabled:          types.BoolValue(false),
				NetworkTrafficPacketCounterEnabled: types.BoolValue(false),
				AutoUpdateVersion:                  types.StringNull(),
				DnsDomain:                          types.StringNull(),
				NetworkRange:                       types.StringNull(),
				NetworkRangeV6:                     types.StringNull(),
				IPv6EnabledGroups:                  types.ListNull(types.StringType),
				LazyConnectionEnabled:              types.BoolNull(),
				UserApprovalRequired:               types.BoolValue(false),
				NetworkTrafficLogsGroups:           types.ListNull(types.StringType),
				PeerExposeEnabled:                  types.BoolValue(false),
				PeerExposeGroups:                   types.ListNull(types.StringType),
			},
		},
		{
			resource: &api.Account{
				Id: "b",
				Settings: api.AccountSettings{
					AutoUpdateVersion:               valPtr("latest"),
					DnsDomain:                       valPtr("custom.com"),
					NetworkRange:                    valPtr("100.64.0.0/10"),
					NetworkRangeV6:                  valPtr("fd00:1234:5678::/64"),
					Ipv6EnabledGroups:               &[]string{"group1"},
					LazyConnectionEnabled:           valPtr(true),
					GroupsPropagationEnabled:        valPtr(true),
					JwtAllowGroups:                  &[]string{"test"},
					JwtGroupsClaimName:              valPtr("test"),
					JwtGroupsEnabled:                valPtr(true),
					PeerInactivityExpiration:        3600,
					PeerInactivityExpirationEnabled: true,
					PeerLoginExpiration:             3600,
					PeerLoginExpirationEnabled:      true,
					RegularUsersViewBlocked:         true,
					RoutingPeerDnsResolutionEnabled: valPtr(true),
					PeerExposeEnabled:               true,
					PeerExposeGroups:                []string{"group1"},
					Extra: &api.AccountExtraSettings{
						NetworkTrafficLogsEnabled:          true,
						NetworkTrafficPacketCounterEnabled: true,
						PeerApprovalEnabled:                true,
						UserApprovalRequired:               true,
						NetworkTrafficLogsGroups:           []string{"group1"},
					},
				},
			},
			expected: AccountSettingsModel{
				Id:                                 types.StringValue("b"),
				JwtAllowGroups:                     types.ListValueMust(types.StringType, []attr.Value{types.StringValue("test")}),
				JwtGroupsClaimName:                 types.StringValue("test"),
				PeerLoginExpiration:                types.Int32Value(3600),
				PeerInactivityExpiration:           types.Int32Value(3600),
				PeerLoginExpirationEnabled:         types.BoolValue(true),
				PeerInactivityExpirationEnabled:    types.BoolValue(true),
				RegularUsersViewBlocked:            types.BoolValue(true),
				GroupsPropagationEnabled:           types.BoolValue(true),
				JwtGroupsEnabled:                   types.BoolValue(true),
				RoutingPeerDnsResolutionEnabled:    types.BoolValue(true),
				PeerApprovalEnabled:                types.BoolValue(true),
				NetworkTrafficLogsEnabled:          types.BoolValue(true),
				NetworkTrafficPacketCounterEnabled: types.BoolValue(true),
				AutoUpdateVersion:                  types.StringValue("latest"),
				DnsDomain:                          types.StringValue("custom.com"),
				NetworkRange:                       types.StringValue("100.64.0.0/10"),
				NetworkRangeV6:                     types.StringValue("fd00:1234:5678::/64"),
				IPv6EnabledGroups:                  types.ListValueMust(types.StringType, []attr.Value{types.StringValue("group1")}),
				LazyConnectionEnabled:              types.BoolValue(true),
				UserApprovalRequired:               types.BoolValue(true),
				NetworkTrafficLogsGroups:           types.ListValueMust(types.StringType, []attr.Value{types.StringValue("group1")}),
				PeerExposeEnabled:                  types.BoolValue(true),
				PeerExposeGroups:                   types.ListValueMust(types.StringType, []attr.Value{types.StringValue("group1")}),
			},
		},
	}

	for _, c := range cases {
		var out AccountSettingsModel
		outDiag := accountAPIToTerraform(context.Background(), c.resource, &out)
		if outDiag.HasError() {
			t.Fatalf("Expected no error diagnostics, found %d errors", outDiag.ErrorsCount())
		}

		if !reflect.DeepEqual(out, c.expected) {
			t.Fatalf("Expected:\n%#v\nFound:\n%#v", c.expected, out)
		}
	}
}

func Test_accountTerraformToAPI(t *testing.T) {
	cases := []struct {
		currentAccount *api.Account
		data           AccountSettingsModel
		expected       api.AccountRequest
	}{
		{
			currentAccount: &api.Account{
				Id: "a1",
				Settings: api.AccountSettings{
					AutoUpdateVersion:               nil,
					DnsDomain:                       nil,
					NetworkRange:                    nil,
					NetworkRangeV6:                  nil,
					Ipv6EnabledGroups:               nil,
					LazyConnectionEnabled:           nil,
					GroupsPropagationEnabled:        nil,
					JwtAllowGroups:                  nil,
					JwtGroupsClaimName:              nil,
					JwtGroupsEnabled:                nil,
					PeerInactivityExpiration:        1800,
					PeerInactivityExpirationEnabled: false,
					PeerLoginExpiration:             1800,
					PeerLoginExpirationEnabled:      false,
					RegularUsersViewBlocked:         false,
					RoutingPeerDnsResolutionEnabled: nil,
					PeerExposeEnabled:               false,
					PeerExposeGroups:                nil,
					Extra: &api.AccountExtraSettings{
						NetworkTrafficLogsEnabled:          false,
						NetworkTrafficPacketCounterEnabled: false,
						PeerApprovalEnabled:                false,
						UserApprovalRequired:               false,
						NetworkTrafficLogsGroups:           nil,
					},
				},
			},
			data: AccountSettingsModel{
				Id:                  types.StringValue("a1"),
				PeerLoginExpiration: types.Int32Value(3600),
			},
			expected: api.AccountRequest{
				Settings: api.AccountSettings{
					AutoUpdateVersion:               nil,
					DnsDomain:                       nil,
					NetworkRange:                    nil,
					NetworkRangeV6:                  nil,
					Ipv6EnabledGroups:               nil,
					LazyConnectionEnabled:           nil,
					GroupsPropagationEnabled:        nil,
					JwtAllowGroups:                  nil,
					JwtGroupsClaimName:              nil,
					JwtGroupsEnabled:                nil,
					PeerInactivityExpiration:        1800,
					PeerInactivityExpirationEnabled: false,
					PeerLoginExpiration:             3600,
					PeerLoginExpirationEnabled:      false,
					RegularUsersViewBlocked:         false,
					RoutingPeerDnsResolutionEnabled: nil,
					PeerExposeEnabled:               false,
					PeerExposeGroups:                nil,
					Extra: &api.AccountExtraSettings{
						NetworkTrafficLogsEnabled:          false,
						NetworkTrafficPacketCounterEnabled: false,
						PeerApprovalEnabled:                false,
						UserApprovalRequired:               false,
						NetworkTrafficLogsGroups:           nil,
					},
				},
			},
		},
		{
			currentAccount: &api.Account{
				Id: "a2",
				Settings: api.AccountSettings{
					AutoUpdateVersion:               nil,
					DnsDomain:                       nil,
					NetworkRange:                    nil,
					NetworkRangeV6:                  nil,
					Ipv6EnabledGroups:               nil,
					LazyConnectionEnabled:           nil,
					GroupsPropagationEnabled:        nil,
					JwtAllowGroups:                  nil,
					JwtGroupsClaimName:              nil,
					JwtGroupsEnabled:                nil,
					PeerInactivityExpiration:        1800,
					PeerInactivityExpirationEnabled: false,
					PeerLoginExpiration:             1800,
					PeerLoginExpirationEnabled:      false,
					RegularUsersViewBlocked:         false,
					RoutingPeerDnsResolutionEnabled: nil,
					PeerExposeEnabled:               false,
					PeerExposeGroups:                nil,
					Extra: &api.AccountExtraSettings{
						NetworkTrafficLogsEnabled:          false,
						NetworkTrafficPacketCounterEnabled: false,
						PeerApprovalEnabled:                false,
						UserApprovalRequired:               false,
						NetworkTrafficLogsGroups:           nil,
					},
				},
			},
			data: AccountSettingsModel{
				Id:                                 types.StringValue("a2"),
				PeerLoginExpiration:                types.Int32Value(3600),
				PeerLoginExpirationEnabled:         types.BoolValue(true),
				JwtAllowGroups:                     types.ListValueMust(types.StringType, []attr.Value{types.StringValue("g1")}),
				NetworkTrafficLogsEnabled:          types.BoolValue(true),
				PeerInactivityExpirationEnabled:    types.BoolValue(true),
				RegularUsersViewBlocked:            types.BoolValue(true),
				GroupsPropagationEnabled:           types.BoolValue(true),
				JwtGroupsEnabled:                   types.BoolValue(true),
				RoutingPeerDnsResolutionEnabled:    types.BoolValue(true),
				PeerApprovalEnabled:                types.BoolValue(true),
				NetworkTrafficPacketCounterEnabled: types.BoolValue(true),
				PeerInactivityExpiration:           types.Int32Value(3600),
				JwtGroupsClaimName:                 types.StringValue("name"),
				AutoUpdateVersion:                  types.StringValue("latest"),
				DnsDomain:                          types.StringValue("custom.com"),
				NetworkRange:                       types.StringValue("100.64.0.0/10"),
				NetworkRangeV6:                     types.StringValue("fd00:1234:5678::/64"),
				IPv6EnabledGroups:                  types.ListValueMust(types.StringType, []attr.Value{types.StringValue("group1")}),
				LazyConnectionEnabled:              types.BoolValue(true),
				UserApprovalRequired:               types.BoolValue(true),
				NetworkTrafficLogsGroups:           types.ListValueMust(types.StringType, []attr.Value{types.StringValue("group1")}),
				PeerExposeEnabled:                  types.BoolValue(true),
				PeerExposeGroups:                   types.ListValueMust(types.StringType, []attr.Value{types.StringValue("group1")}),
			},
			expected: api.AccountRequest{
				Settings: api.AccountSettings{
					AutoUpdateVersion:               valPtr("latest"),
					DnsDomain:                       valPtr("custom.com"),
					NetworkRange:                    valPtr("100.64.0.0/10"),
					NetworkRangeV6:                  valPtr("fd00:1234:5678::/64"),
					Ipv6EnabledGroups:               &[]string{"group1"},
					LazyConnectionEnabled:           valPtr(true),
					GroupsPropagationEnabled:        valPtr(true),
					JwtAllowGroups:                  &[]string{"g1"},
					JwtGroupsClaimName:              valPtr("name"),
					JwtGroupsEnabled:                valPtr(true),
					PeerInactivityExpiration:        3600,
					PeerInactivityExpirationEnabled: true,
					PeerLoginExpiration:             3600,
					PeerLoginExpirationEnabled:      true,
					RegularUsersViewBlocked:         true,
					RoutingPeerDnsResolutionEnabled: valPtr(true),
					PeerExposeEnabled:               true,
					PeerExposeGroups:                []string{"group1"},
					Extra: &api.AccountExtraSettings{
						NetworkTrafficLogsEnabled:          true,
						NetworkTrafficPacketCounterEnabled: true,
						PeerApprovalEnabled:                true,
						UserApprovalRequired:               true,
						NetworkTrafficLogsGroups:           []string{"group1"},
					},
				},
			},
		},
	}

	for _, c := range cases {
		out, diags := accountTerraformToAPI(context.Background(), c.currentAccount, c.data)
		if diags.HasError() {
			t.Fatalf("Expected no error diagnostics, found %d errors", diags.ErrorsCount())
		}

		if !reflect.DeepEqual(out, c.expected) {
			t.Fatalf("Expected:\n%#v\nFound:\n%#v", c.expected, out)
		}
	}
}

// Test_accountTerraformToAPI_carriesUnmodelledSettings pins the reason the request
// starts from the current settings: management resets any field a PUT omits, so
// settings the schema does not model have to be sent back as they are.
func Test_accountTerraformToAPI_carriesUnmodelledSettings(t *testing.T) {
	current := &api.Account{
		Id: "a",
		Settings: api.AccountSettings{
			PeerLoginExpiration:      86400,
			PeerInactivityExpiration: 600,
			JwtGroupsEnabled:         valPtr(false),
			AgentNetworkOnly:         valPtr(true),
			AutoUpdateAlways:         valPtr(true),
			DashboardFeatures:        &api.AccountDashboardFeatures{AgentNetwork: valPtr(true)},
			EmbeddedIdpEnabled:       valPtr(true),
			LocalAuthDisabled:        valPtr(false),
			LocalMfaEnabled:          valPtr(true),
			MetricsPushEnabled:       valPtr(true),
			PeerExposeGroups:         []string{"g1"},
			Extra: &api.AccountExtraSettings{
				NetworkTrafficLogsEnabled: true,
				NetworkTrafficLogsGroups:  []string{"g2"},
			},
		},
	}
	// A second, independent copy to compare against afterwards: building the
	// request must not write through to the account it was given.
	before := &api.Account{}
	*before = *current
	before.Settings.DashboardFeatures = &api.AccountDashboardFeatures{AgentNetwork: valPtr(true)}
	before.Settings.Extra = &api.AccountExtraSettings{
		NetworkTrafficLogsEnabled: true,
		NetworkTrafficLogsGroups:  []string{"g2"},
	}

	data := AccountSettingsModel{
		Id:                        types.StringValue("a"),
		JwtGroupsEnabled:          types.BoolValue(true),
		NetworkTrafficLogsEnabled: types.BoolValue(false),
		PeerLoginExpiration:       types.Int32Unknown(),
		NetworkTrafficLogsGroups:  types.ListNull(types.StringType),
	}

	want := api.AccountRequest{
		Settings: api.AccountSettings{
			PeerLoginExpiration:      86400,
			PeerInactivityExpiration: 600,
			JwtGroupsEnabled:         valPtr(true),
			AgentNetworkOnly:         valPtr(true),
			AutoUpdateAlways:         valPtr(true),
			DashboardFeatures:        &api.AccountDashboardFeatures{AgentNetwork: valPtr(true)},
			EmbeddedIdpEnabled:       valPtr(true),
			LocalAuthDisabled:        valPtr(false),
			LocalMfaEnabled:          valPtr(true),
			MetricsPushEnabled:       valPtr(true),
			PeerExposeGroups:         []string{"g1"},
			Extra: &api.AccountExtraSettings{
				NetworkTrafficLogsEnabled: false,
				NetworkTrafficLogsGroups:  []string{"g2"},
			},
		},
	}

	got, diags := accountTerraformToAPI(context.Background(), current, data)
	if diags.HasError() {
		t.Fatalf("Expected no error diagnostics, found %d errors", diags.ErrorsCount())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Expected:\n%#v\nFound:\n%#v", want, got)
	}
	if !reflect.DeepEqual(current, before) {
		t.Fatalf("current account was modified:\n%#v\nwant:\n%#v", current, before)
	}

	// The request is sent after the account was fetched and may be adjusted
	// further; neither may reach into the other.
	*got.Settings.DashboardFeatures.AgentNetwork = false
	*got.Settings.MetricsPushEnabled = false
	got.Settings.Extra.NetworkTrafficLogsGroups[0] = "changed"
	got.Settings.PeerExposeGroups[0] = "changed"
	if !reflect.DeepEqual(current, before) {
		t.Fatalf("request aliases the current account:\n%#v\nwant:\n%#v", current, before)
	}
}

// Test_accountTerraformToAPI_nilExtra covers an account whose response carries
// no extra settings object: the modelled extra attributes still have to reach
// the request.
func Test_accountTerraformToAPI_nilExtra(t *testing.T) {
	current := &api.Account{Id: "a", Settings: api.AccountSettings{PeerLoginExpiration: 3600}}
	data := AccountSettingsModel{
		Id:                   types.StringValue("a"),
		UserApprovalRequired: types.BoolValue(true),
	}

	got, diags := accountTerraformToAPI(context.Background(), current, data)
	if diags.HasError() {
		t.Fatalf("Expected no error diagnostics, found %d errors", diags.ErrorsCount())
	}
	if got.Settings.Extra == nil || !got.Settings.Extra.UserApprovalRequired {
		t.Fatalf("Expected extra.user_approval_required in the request, found %#v", got.Settings.Extra)
	}
	if current.Settings.Extra != nil {
		t.Fatalf("current account was modified: %#v", current.Settings.Extra)
	}
}
