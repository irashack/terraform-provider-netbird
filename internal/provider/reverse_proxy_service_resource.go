package provider

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	netbird "github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// NewReverseProxyService creates a new reverse proxy service resource.
func NewReverseProxyService() resource.Resource {
	return &ReverseProxyService{}
}

// ReverseProxyService defines the resource implementation.
type ReverseProxyService struct {
	client *netbird.Client
}

// ReverseProxyServiceModel describes the resource data model.
type ReverseProxyServiceModel struct {
	Id                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Domain             types.String `tfsdk:"domain"`
	Mode               types.String `tfsdk:"mode"`
	ListenPort         types.Int64  `tfsdk:"listen_port"`
	PortAutoAssigned   types.Bool   `tfsdk:"port_auto_assigned"`
	Enabled            types.Bool   `tfsdk:"enabled"`
	PassHostHeader     types.Bool   `tfsdk:"pass_host_header"`
	RewriteRedirects   types.Bool   `tfsdk:"rewrite_redirects"`
	ProxyCluster       types.String `tfsdk:"proxy_cluster"`
	Private            types.Bool   `tfsdk:"private"`
	AccessGroups       types.List   `tfsdk:"access_groups"`
	Targets            types.List   `tfsdk:"targets"`
	Auth               types.Object `tfsdk:"auth"`
	AccessRestrictions types.Object `tfsdk:"access_restrictions"`
}

// ReverseProxyServiceTargetModel describes a service target.
type ReverseProxyServiceTargetModel struct {
	TargetId   types.String `tfsdk:"target_id"`
	TargetType types.String `tfsdk:"target_type"`
	Host       types.String `tfsdk:"host"`
	Port       types.Int64  `tfsdk:"port"`
	Protocol   types.String `tfsdk:"protocol"`
	Path       types.String `tfsdk:"path"`
	Enabled    types.Bool   `tfsdk:"enabled"`
	Options    types.Object `tfsdk:"options"`
}

// TFType returns the Terraform object type for service targets.
func (m ReverseProxyServiceTargetModel) TFType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"target_id":   types.StringType,
			"target_type": types.StringType,
			"host":        types.StringType,
			"port":        types.Int64Type,
			"protocol":    types.StringType,
			"path":        types.StringType,
			"enabled":     types.BoolType,
			"options":     ReverseProxyTargetOptionsModel{}.TFType(),
		},
	}
}

// ReverseProxyTargetOptionsModel describes per-target options.
type ReverseProxyTargetOptionsModel struct {
	SkipTLSVerify      types.Bool   `tfsdk:"skip_tls_verify"`
	RequestTimeout     types.String `tfsdk:"request_timeout"`
	PathRewrite        types.String `tfsdk:"path_rewrite"`
	CustomHeaders      types.Map    `tfsdk:"custom_headers"`
	ProxyProtocol      types.Bool   `tfsdk:"proxy_protocol"`
	SessionIdleTimeout types.String `tfsdk:"session_idle_timeout"`
	DirectUpstream     types.Bool   `tfsdk:"direct_upstream"`
}

// TFType returns the Terraform object type for target options.
func (m ReverseProxyTargetOptionsModel) TFType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"skip_tls_verify": types.BoolType,
			"request_timeout": types.StringType,
			"path_rewrite":    types.StringType,
			"custom_headers": types.MapType{
				ElemType: types.StringType,
			},
			"proxy_protocol":       types.BoolType,
			"session_idle_timeout": types.StringType,
			"direct_upstream":      types.BoolType,
		},
	}
}

// ReverseProxyServiceAuthModel describes the auth config.
type ReverseProxyServiceAuthModel struct {
	PasswordAuth types.Object `tfsdk:"password_auth"`
	PinAuth      types.Object `tfsdk:"pin_auth"`
	BearerAuth   types.Object `tfsdk:"bearer_auth"`
	LinkAuth     types.Object `tfsdk:"link_auth"`
	HeaderAuths  types.List   `tfsdk:"header_auths"`
}

// TFType returns the Terraform object type for service auth.
func (m ReverseProxyServiceAuthModel) TFType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"password_auth": ReverseProxyPasswordAuthModel{}.TFType(),
			"pin_auth":      ReverseProxyPinAuthModel{}.TFType(),
			"bearer_auth":   ReverseProxyBearerAuthModel{}.TFType(),
			"link_auth":     ReverseProxyLinkAuthModel{}.TFType(),
			"header_auths":  types.ListType{ElemType: ReverseProxyHeaderAuthModel{}.TFType()},
		},
	}
}

// ReverseProxyPasswordAuthModel describes password auth config.
type ReverseProxyPasswordAuthModel struct {
	Enabled  types.Bool   `tfsdk:"enabled"`
	Password types.String `tfsdk:"password"`
}

// TFType returns the Terraform object type for password auth.
func (m ReverseProxyPasswordAuthModel) TFType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"enabled":  types.BoolType,
			"password": types.StringType,
		},
	}
}

// ReverseProxyPinAuthModel describes PIN auth config.
type ReverseProxyPinAuthModel struct {
	Enabled types.Bool   `tfsdk:"enabled"`
	Pin     types.String `tfsdk:"pin"`
}

// TFType returns the Terraform object type for PIN auth.
func (m ReverseProxyPinAuthModel) TFType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"enabled": types.BoolType,
			"pin":     types.StringType,
		},
	}
}

// ReverseProxyBearerAuthModel describes bearer auth config.
type ReverseProxyBearerAuthModel struct {
	Enabled            types.Bool `tfsdk:"enabled"`
	DistributionGroups types.List `tfsdk:"distribution_groups"`
}

// TFType returns the Terraform object type for bearer auth.
func (m ReverseProxyBearerAuthModel) TFType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"enabled": types.BoolType,
			"distribution_groups": types.ListType{
				ElemType: types.StringType,
			},
		},
	}
}

// ReverseProxyLinkAuthModel describes link auth config.
type ReverseProxyLinkAuthModel struct {
	Enabled types.Bool `tfsdk:"enabled"`
}

// TFType returns the Terraform object type for link auth.
func (m ReverseProxyLinkAuthModel) TFType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"enabled": types.BoolType,
		},
	}
}

// ReverseProxyHeaderAuthModel describes header auth config.
type ReverseProxyHeaderAuthModel struct {
	Enabled types.Bool   `tfsdk:"enabled"`
	Header  types.String `tfsdk:"header"`
	Value   types.String `tfsdk:"value"`
}

// TFType returns the Terraform object type for header auth.
func (m ReverseProxyHeaderAuthModel) TFType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"enabled": types.BoolType,
			"header":  types.StringType,
			"value":   types.StringType,
		},
	}
}

// ReverseProxyAccessRestrictionsModel describes access restrictions.
type ReverseProxyAccessRestrictionsModel struct {
	AllowedCidrs     types.List   `tfsdk:"allowed_cidrs"`
	BlockedCidrs     types.List   `tfsdk:"blocked_cidrs"`
	AllowedCountries types.List   `tfsdk:"allowed_countries"`
	BlockedCountries types.List   `tfsdk:"blocked_countries"`
	CrowdsecMode     types.String `tfsdk:"crowdsec_mode"`
}

// TFType returns the Terraform object type for access restrictions.
func (m ReverseProxyAccessRestrictionsModel) TFType() types.ObjectType {
	return types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"allowed_cidrs":     types.ListType{ElemType: types.StringType},
			"blocked_cidrs":     types.ListType{ElemType: types.StringType},
			"allowed_countries": types.ListType{ElemType: types.StringType},
			"blocked_countries": types.ListType{ElemType: types.StringType},
			"crowdsec_mode":     types.StringType,
		},
	}
}

func (r *ReverseProxyService) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_reverse_proxy_service"
}

func (r *ReverseProxyService) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Create and manage Reverse Proxy Services",
		MarkdownDescription: "Create and manage Reverse Proxy Services for the NetBird reverse proxy.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Service ID",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Service name",
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"domain": schema.StringAttribute{
				MarkdownDescription: "Domain for the service",
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"mode": schema.StringAttribute{
				MarkdownDescription: "Service mode: \"http\" for L7 reverse proxy, \"tcp\"/\"udp\"/\"tls\" for L4 passthrough",
				Optional:            true,
				Computed:            true,
				Validators:          []validator.String{stringvalidator.OneOf("http", "tcp", "udp", "tls")},
			},
			"listen_port": schema.Int64Attribute{
				MarkdownDescription: "Port the proxy listens on (L4/TLS only). Set to 0 for auto-assignment.",
				Optional:            true,
				Computed:            true,
				Validators:          []validator.Int64{int64validator.Between(0, 65535)},
			},
			"port_auto_assigned": schema.BoolAttribute{
				MarkdownDescription: "Whether the listen port was auto-assigned by the server",
				Computed:            true,
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the service is enabled",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"pass_host_header": schema.BoolAttribute{
				MarkdownDescription: "When true, the original client Host header is passed through to the backend",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"rewrite_redirects": schema.BoolAttribute{
				MarkdownDescription: "When true, Location headers in backend responses are rewritten to replace the backend address with the public-facing domain",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"proxy_cluster": schema.StringAttribute{
				MarkdownDescription: "The proxy cluster handling this service (derived from domain)",
				Computed:            true,
			},
			"private": schema.BoolAttribute{
				MarkdownDescription: "When true, the service is reachable only over NetBird: peers in `access_groups` authenticate with their WireGuard identity instead of SSO, and management generates the access policy to the cluster's proxy peers. Requires `mode = \"http\"` and at least one access group, and cannot be combined with bearer auth. When unset, the server's current value is kept.",
				Optional:            true,
				Computed:            true,
				// The PUT replaces the whole service, so an unknown here would be
				// omitted from the request and silently make the service public.
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"access_groups": schema.ListAttribute{
				MarkdownDescription: "IDs of the groups whose peers may reach a private service over the tunnel. Required when `private` is true, and allowed only then.",
				Optional:            true,
				ElementType:         types.StringType,
			},
			"targets": schema.ListNestedAttribute{
				MarkdownDescription: "List of target backends for this service",
				Required:            true,
				PlanModifiers:       []planmodifier.List{keepUnconfiguredTargetFields{}},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"target_id": schema.StringAttribute{
							MarkdownDescription: "Target ID: the peer or network resource ID, or for a `cluster` target the proxy cluster address",
							Required:            true,
						},
						"target_type": schema.StringAttribute{
							MarkdownDescription: "Target type (peer, host, domain, subnet, cluster). A `cluster` target needs `host` and `options.direct_upstream = true`.",
							Required:            true,
							Validators:          []validator.String{stringvalidator.OneOf("peer", "host", "domain", "subnet", "cluster")},
						},
						"host": schema.StringAttribute{
							MarkdownDescription: "Backend IP or domain for this target. If omitted when the target is created, the API resolves it from the target peer or resource; if omitted afterwards, the value the server holds is kept.",
							Optional:            true,
							Computed:            true,
						},
						"port": schema.Int64Attribute{
							MarkdownDescription: "Backend port for this target (0 for scheme default)",
							Required:            true,
							Validators:          []validator.Int64{int64validator.Between(0, 65535)},
						},
						"protocol": schema.StringAttribute{
							MarkdownDescription: "Protocol to use when connecting to the backend (http, https for HTTP mode; tcp, udp for L4 mode)",
							Required:            true,
							Validators:          []validator.String{stringvalidator.OneOf("http", "https", "tcp", "udp")},
						},
						"path": schema.StringAttribute{
							MarkdownDescription: "URL path prefix for this target. The server routes a target without one as \"/\". If omitted, the value the server holds is kept.",
							Optional:            true,
							Computed:            true,
						},
						"enabled": schema.BoolAttribute{
							MarkdownDescription: "Whether this target is enabled",
							Optional:            true,
							Computed:            true,
							Default:             booldefault.StaticBool(true),
						},
						"options": schema.SingleNestedAttribute{
							MarkdownDescription: "Per-target options",
							Optional:            true,
							Attributes: map[string]schema.Attribute{
								"skip_tls_verify": schema.BoolAttribute{
									MarkdownDescription: "Skip TLS certificate verification for this backend (HTTPS targets only)",
									Optional:            true,
								},
								"request_timeout": schema.StringAttribute{
									MarkdownDescription: "Per-target response timeout as a Go duration string (e.g. \"30s\", \"2m\")",
									Optional:            true,
								},
								"path_rewrite": schema.StringAttribute{
									MarkdownDescription: "Controls how the request path is rewritten before forwarding. Default strips the matched prefix. \"preserve\" keeps the full original path. (HTTP only)",
									Optional:            true,
									Validators:          []validator.String{stringvalidator.OneOf("preserve")},
								},
								"custom_headers": schema.MapAttribute{
									MarkdownDescription: "Extra headers sent to the backend (HTTP only). Marked sensitive since values commonly carry credentials, e.g. an `Authorization` header.",
									Optional:            true,
									ElementType:         types.StringType,
									Sensitive:           true,
								},
								"proxy_protocol": schema.BoolAttribute{
									MarkdownDescription: "Send PROXY Protocol v2 header to this backend (TCP/TLS only)",
									Optional:            true,
								},
								"session_idle_timeout": schema.StringAttribute{
									MarkdownDescription: "Idle timeout before a UDP session is reaped, as a Go duration string (e.g. \"30s\", \"2m\"). Maximum 10m. (UDP only)",
									Optional:            true,
								},
								"direct_upstream": schema.BoolAttribute{
									MarkdownDescription: "Dial this target from the proxy host's own network stack instead of through the proxy's embedded NetBird client, for upstreams reachable without WireGuard (LAN services, localhost sidecars). Required for `cluster` targets.",
									Optional:            true,
								},
							},
						},
					},
				},
			},
			"auth": schema.SingleNestedAttribute{
				MarkdownDescription: "Authentication configuration",
				Required:            true,
				Attributes: map[string]schema.Attribute{
					"password_auth": schema.SingleNestedAttribute{
						MarkdownDescription: "Password authentication",
						Optional:            true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Required: true,
							},
							"password": schema.StringAttribute{
								Optional:  true,
								Sensitive: true,
							},
						},
					},
					"pin_auth": schema.SingleNestedAttribute{
						MarkdownDescription: "PIN authentication",
						Optional:            true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Required: true,
							},
							"pin": schema.StringAttribute{
								Optional:  true,
								Sensitive: true,
							},
						},
					},
					"bearer_auth": schema.SingleNestedAttribute{
						MarkdownDescription: "Bearer token authentication",
						Optional:            true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Required: true,
							},
							"distribution_groups": schema.ListAttribute{
								MarkdownDescription: "List of group IDs that can use bearer auth",
								Optional:            true,
								ElementType:         types.StringType,
							},
						},
					},
					"link_auth": schema.SingleNestedAttribute{
						MarkdownDescription: "Link authentication",
						Optional:            true,
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Required: true,
							},
						},
					},
					"header_auths": schema.ListNestedAttribute{
						MarkdownDescription: "Static header-value authentication rules",
						Optional:            true,
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"enabled": schema.BoolAttribute{
									Required: true,
								},
								"header": schema.StringAttribute{
									MarkdownDescription: "HTTP header name to check",
									Required:            true,
								},
								"value": schema.StringAttribute{
									MarkdownDescription: "Expected header value",
									Required:            true,
									Sensitive:           true,
								},
							},
						},
					},
				},
			},
			"access_restrictions": schema.SingleNestedAttribute{
				MarkdownDescription: "Connection-level access restrictions based on IP or geography",
				Optional:            true,
				Attributes: map[string]schema.Attribute{
					"allowed_cidrs": schema.ListAttribute{
						MarkdownDescription: "CIDR allowlist",
						Optional:            true,
						ElementType:         types.StringType,
					},
					"blocked_cidrs": schema.ListAttribute{
						MarkdownDescription: "CIDR blocklist",
						Optional:            true,
						ElementType:         types.StringType,
					},
					"allowed_countries": schema.ListAttribute{
						MarkdownDescription: "ISO 3166-1 alpha-2 country codes to allow",
						Optional:            true,
						ElementType:         types.StringType,
					},
					"blocked_countries": schema.ListAttribute{
						MarkdownDescription: "ISO 3166-1 alpha-2 country codes to block",
						Optional:            true,
						ElementType:         types.StringType,
					},
					"crowdsec_mode": schema.StringAttribute{
						MarkdownDescription: "CrowdSec IP reputation mode: \"enforce\", \"observe\" or \"off\". Takes effect only on a proxy cluster that supports CrowdSec.",
						Optional:            true,
						Validators:          []validator.String{stringvalidator.OneOf("enforce", "observe", "off")},
					},
				},
			},
		},
	}
}

// ValidateConfig checks the private-service contract at plan time. Management
// enforces the same rules, but only once the apply has started, and it would
// otherwise store access groups on a public service where they do nothing.
func (r *ReverseProxyService) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data ReverseProxyServiceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() || data.Private.IsUnknown() {
		return
	}

	private := data.Private.ValueBool()
	groupsKnown := !data.AccessGroups.IsUnknown()
	hasGroups := groupsKnown && !data.AccessGroups.IsNull()

	if !private && hasGroups {
		resp.Diagnostics.AddAttributeError(path.Root("access_groups"), "Invalid Attribute Combination",
			"access_groups applies only to a private service. Set private = true, or remove access_groups.")
		return
	}
	if !private {
		return
	}

	if groupsKnown && len(data.AccessGroups.Elements()) == 0 {
		resp.Diagnostics.AddAttributeError(path.Root("access_groups"), "Invalid Attribute Combination",
			"A private service needs at least one access group: no peer could reach it otherwise.")
	}
	if !data.Mode.IsNull() && !data.Mode.IsUnknown() && data.Mode.ValueString() != "http" {
		resp.Diagnostics.AddAttributeError(path.Root("mode"), "Invalid Attribute Combination",
			fmt.Sprintf("A private service must use mode \"http\", not %q.", data.Mode.ValueString()))
	}
	if bearerAuthEnabled(data.Auth) {
		resp.Diagnostics.AddAttributeError(path.Root("auth").AtName("bearer_auth").AtName("enabled"), "Invalid Attribute Combination",
			"A private service authenticates peers by their NetBird identity and cannot also enable bearer auth (SSO).")
	}
}

// bearerAuthEnabled reports whether auth is known to enable bearer auth. Any
// unknown along the way reads as not enabled, so plan-time values pass.
func bearerAuthEnabled(auth types.Object) bool {
	if auth.IsNull() || auth.IsUnknown() {
		return false
	}
	bearer, ok := auth.Attributes()["bearer_auth"].(types.Object)
	if !ok || bearer.IsNull() || bearer.IsUnknown() {
		return false
	}
	enabled, ok := bearer.Attributes()["enabled"].(types.Bool)
	return ok && !enabled.IsUnknown() && enabled.ValueBool()
}

func (r *ReverseProxyService) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*netbird.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *netbird.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

func targetOptionsAPIToTerraform(ctx context.Context, opts *api.ServiceTargetOptions) (types.Object, diag.Diagnostics) {
	if opts == nil {
		return types.ObjectNull(ReverseProxyTargetOptionsModel{}.TFType().AttrTypes), nil
	}

	// If all fields are at zero/nil, treat as no options set.
	if opts.SkipTlsVerify == nil && opts.RequestTimeout == nil && opts.PathRewrite == nil &&
		opts.CustomHeaders == nil && opts.SessionIdleTimeout == nil &&
		!isTrue(opts.ProxyProtocol) && !isTrue(opts.DirectUpstream) {
		return types.ObjectNull(ReverseProxyTargetOptionsModel{}.TFType().AttrTypes), nil
	}

	// Treat proxy_protocol and direct_upstream false the same as nil so they
	// don't appear in state when the user never configured them.
	model := ReverseProxyTargetOptionsModel{
		SkipTLSVerify:  types.BoolPointerValue(opts.SkipTlsVerify),
		RequestTimeout: types.StringPointerValue(opts.RequestTimeout),
		ProxyProtocol:  trueOrNull(opts.ProxyProtocol),
		DirectUpstream: trueOrNull(opts.DirectUpstream),
	}

	if opts.PathRewrite != nil {
		model.PathRewrite = types.StringValue(string(*opts.PathRewrite))
	} else {
		model.PathRewrite = types.StringNull()
	}

	if opts.SessionIdleTimeout != nil {
		model.SessionIdleTimeout = types.StringValue(*opts.SessionIdleTimeout)
	} else {
		model.SessionIdleTimeout = types.StringNull()
	}

	var d diag.Diagnostics
	if opts.CustomHeaders != nil {
		model.CustomHeaders, d = types.MapValueFrom(ctx, types.StringType, *opts.CustomHeaders)
	} else {
		model.CustomHeaders = types.MapNull(types.StringType)
	}

	obj, objD := types.ObjectValueFrom(ctx, ReverseProxyTargetOptionsModel{}.TFType().AttrTypes, model)
	d.Append(objD...)
	return obj, d
}

func isTrue(b *bool) bool {
	return b != nil && *b
}

func trueOrNull(b *bool) types.Bool {
	if isTrue(b) {
		return types.BoolValue(true)
	}
	return types.BoolNull()
}

func targetOptionsTerraformToAPI(ctx context.Context, opts types.Object) (*api.ServiceTargetOptions, diag.Diagnostics) {
	if opts.IsNull() || opts.IsUnknown() {
		return nil, nil
	}

	var ret diag.Diagnostics
	attrs := opts.Attributes()
	result := &api.ServiceTargetOptions{}
	hasValue := false

	if v, ok := attrs["skip_tls_verify"].(types.Bool); ok && !v.IsNull() && !v.IsUnknown() {
		b := v.ValueBool()
		result.SkipTlsVerify = &b
		hasValue = true
	}
	if v, ok := attrs["request_timeout"].(types.String); ok && !v.IsNull() && !v.IsUnknown() {
		s := v.ValueString()
		result.RequestTimeout = &s
		hasValue = true
	}
	if v, ok := attrs["path_rewrite"].(types.String); ok && !v.IsNull() && !v.IsUnknown() {
		pr := api.ServiceTargetOptionsPathRewrite(v.ValueString())
		result.PathRewrite = &pr
		hasValue = true
	}
	if v, ok := attrs["custom_headers"].(types.Map); ok && !v.IsNull() && !v.IsUnknown() {
		var headers map[string]string
		ret.Append(v.ElementsAs(ctx, &headers, false)...)
		result.CustomHeaders = &headers
		hasValue = true
	}
	if v, ok := attrs["proxy_protocol"].(types.Bool); ok && !v.IsNull() && !v.IsUnknown() {
		b := v.ValueBool()
		result.ProxyProtocol = &b
		hasValue = true
	}
	if v, ok := attrs["session_idle_timeout"].(types.String); ok && !v.IsNull() && !v.IsUnknown() {
		s := v.ValueString()
		result.SessionIdleTimeout = &s
		hasValue = true
	}
	if v, ok := attrs["direct_upstream"].(types.Bool); ok && !v.IsNull() && !v.IsUnknown() {
		b := v.ValueBool()
		result.DirectUpstream = &b
		hasValue = true
	}

	if !hasValue {
		return nil, ret
	}
	return result, ret
}

func reverseProxyServiceAPIToTerraform(ctx context.Context, svc *api.Service, data *ReverseProxyServiceModel) diag.Diagnostics {
	var ret diag.Diagnostics
	var d diag.Diagnostics

	data.Id = types.StringValue(svc.Id)
	data.Name = types.StringValue(svc.Name)
	data.Domain = types.StringValue(svc.Domain)
	data.Enabled = types.BoolValue(svc.Enabled)

	if svc.Mode != nil {
		data.Mode = types.StringValue(string(*svc.Mode))
	} else {
		data.Mode = types.StringValue("http")
	}

	if svc.ListenPort != nil {
		data.ListenPort = types.Int64Value(int64(*svc.ListenPort))
	} else {
		data.ListenPort = types.Int64Null()
	}

	if svc.PortAutoAssigned != nil {
		data.PortAutoAssigned = types.BoolValue(*svc.PortAutoAssigned)
	} else {
		data.PortAutoAssigned = types.BoolValue(false)
	}

	if svc.PassHostHeader != nil {
		data.PassHostHeader = types.BoolValue(*svc.PassHostHeader)
	} else {
		data.PassHostHeader = types.BoolValue(false)
	}

	if svc.RewriteRedirects != nil {
		data.RewriteRedirects = types.BoolValue(*svc.RewriteRedirects)
	} else {
		data.RewriteRedirects = types.BoolValue(false)
	}

	data.ProxyCluster = types.StringPointerValue(svc.ProxyCluster)
	data.Private = types.BoolValue(isTrue(svc.Private))

	// The server omits access_groups when the list is empty, and a private
	// service cannot have an empty one, so empty and absent are both null.
	if svc.AccessGroups != nil && len(*svc.AccessGroups) > 0 {
		data.AccessGroups, d = types.ListValueFrom(ctx, types.StringType, *svc.AccessGroups)
		ret.Append(d...)
	} else {
		data.AccessGroups = types.ListNull(types.StringType)
	}

	var targets []ReverseProxyServiceTargetModel
	for _, t := range svc.Targets {
		opts, optsDiags := targetOptionsAPIToTerraform(ctx, t.Options)
		ret.Append(optsDiags...)

		target := ReverseProxyServiceTargetModel{
			TargetId:   types.StringValue(t.TargetId),
			TargetType: types.StringValue(string(t.TargetType)),
			Port:       types.Int64Value(int64(t.Port)),
			Protocol:   types.StringValue(string(t.Protocol)),
			Enabled:    types.BoolValue(t.Enabled),
			Host:       types.StringPointerValue(t.Host),
			Path:       types.StringPointerValue(t.Path),
			Options:    opts,
		}
		targets = append(targets, target)
	}
	data.Targets, d = types.ListValueFrom(ctx, ReverseProxyServiceTargetModel{}.TFType(), targets)
	ret.Append(d...)

	authModel := ReverseProxyServiceAuthModel{}

	if svc.Auth.PasswordAuth != nil {
		authModel.PasswordAuth, d = types.ObjectValueFrom(ctx, ReverseProxyPasswordAuthModel{}.TFType().AttrTypes, ReverseProxyPasswordAuthModel{
			Enabled:  types.BoolValue(svc.Auth.PasswordAuth.Enabled),
			Password: types.StringValue(svc.Auth.PasswordAuth.Password),
		})
		ret.Append(d...)
	} else {
		authModel.PasswordAuth = types.ObjectNull(ReverseProxyPasswordAuthModel{}.TFType().AttrTypes)
	}

	if svc.Auth.PinAuth != nil {
		authModel.PinAuth, d = types.ObjectValueFrom(ctx, ReverseProxyPinAuthModel{}.TFType().AttrTypes, ReverseProxyPinAuthModel{
			Enabled: types.BoolValue(svc.Auth.PinAuth.Enabled),
			Pin:     types.StringValue(svc.Auth.PinAuth.Pin),
		})
		ret.Append(d...)
	} else {
		authModel.PinAuth = types.ObjectNull(ReverseProxyPinAuthModel{}.TFType().AttrTypes)
	}

	if svc.Auth.BearerAuth != nil {
		bearerModel := ReverseProxyBearerAuthModel{
			Enabled: types.BoolValue(svc.Auth.BearerAuth.Enabled),
		}
		if svc.Auth.BearerAuth.DistributionGroups != nil {
			bearerModel.DistributionGroups, d = types.ListValueFrom(ctx, types.StringType, *svc.Auth.BearerAuth.DistributionGroups)
			ret.Append(d...)
		} else {
			bearerModel.DistributionGroups = types.ListNull(types.StringType)
		}
		authModel.BearerAuth, d = types.ObjectValueFrom(ctx, ReverseProxyBearerAuthModel{}.TFType().AttrTypes, bearerModel)
		ret.Append(d...)
	} else {
		authModel.BearerAuth = types.ObjectNull(ReverseProxyBearerAuthModel{}.TFType().AttrTypes)
	}

	if svc.Auth.LinkAuth != nil {
		authModel.LinkAuth, d = types.ObjectValueFrom(ctx, ReverseProxyLinkAuthModel{}.TFType().AttrTypes, ReverseProxyLinkAuthModel{
			Enabled: types.BoolValue(svc.Auth.LinkAuth.Enabled),
		})
		ret.Append(d...)
	} else {
		authModel.LinkAuth = types.ObjectNull(ReverseProxyLinkAuthModel{}.TFType().AttrTypes)
	}

	if svc.Auth.HeaderAuths != nil && len(*svc.Auth.HeaderAuths) > 0 {
		var headerAuthModels []ReverseProxyHeaderAuthModel
		for _, h := range *svc.Auth.HeaderAuths {
			headerAuthModels = append(headerAuthModels, ReverseProxyHeaderAuthModel{
				Enabled: types.BoolValue(h.Enabled),
				Header:  types.StringValue(h.Header),
				Value:   types.StringValue(h.Value),
			})
		}
		authModel.HeaderAuths, d = types.ListValueFrom(ctx, ReverseProxyHeaderAuthModel{}.TFType(), headerAuthModels)
		ret.Append(d...)
	} else {
		authModel.HeaderAuths = types.ListNull(ReverseProxyHeaderAuthModel{}.TFType())
	}

	data.Auth, d = types.ObjectValueFrom(ctx, ReverseProxyServiceAuthModel{}.TFType().AttrTypes, authModel)
	ret.Append(d...)

	if svc.AccessRestrictions != nil {
		arModel := ReverseProxyAccessRestrictionsModel{}
		if svc.AccessRestrictions.AllowedCidrs != nil {
			arModel.AllowedCidrs, d = types.ListValueFrom(ctx, types.StringType, *svc.AccessRestrictions.AllowedCidrs)
			ret.Append(d...)
		} else {
			arModel.AllowedCidrs = types.ListNull(types.StringType)
		}
		if svc.AccessRestrictions.BlockedCidrs != nil {
			arModel.BlockedCidrs, d = types.ListValueFrom(ctx, types.StringType, *svc.AccessRestrictions.BlockedCidrs)
			ret.Append(d...)
		} else {
			arModel.BlockedCidrs = types.ListNull(types.StringType)
		}
		if svc.AccessRestrictions.AllowedCountries != nil {
			arModel.AllowedCountries, d = types.ListValueFrom(ctx, types.StringType, *svc.AccessRestrictions.AllowedCountries)
			ret.Append(d...)
		} else {
			arModel.AllowedCountries = types.ListNull(types.StringType)
		}
		if svc.AccessRestrictions.BlockedCountries != nil {
			arModel.BlockedCountries, d = types.ListValueFrom(ctx, types.StringType, *svc.AccessRestrictions.BlockedCountries)
			ret.Append(d...)
		} else {
			arModel.BlockedCountries = types.ListNull(types.StringType)
		}
		if svc.AccessRestrictions.CrowdsecMode != nil {
			arModel.CrowdsecMode = types.StringValue(string(*svc.AccessRestrictions.CrowdsecMode))
		} else {
			arModel.CrowdsecMode = types.StringNull()
		}
		data.AccessRestrictions, d = types.ObjectValueFrom(ctx, ReverseProxyAccessRestrictionsModel{}.TFType().AttrTypes, arModel)
		ret.Append(d...)
	} else {
		data.AccessRestrictions = types.ObjectNull(ReverseProxyAccessRestrictionsModel{}.TFType().AttrTypes)
	}

	return ret
}

// keepUnconfiguredTargetFields plans a target's host and path, when the
// configuration leaves them out, as the values the server holds for that target
// instead of as unknown. The PUT replaces the whole service, so an unknown would
// be omitted from the request: the server then resets the path and refuses a
// cluster or subnet target for having no host.
//
// Targets are matched on target_id and target_type, so reordering the list does
// not move one target's values onto another. Targets sharing a resource cannot
// be told apart that way and fall back to their position.
type keepUnconfiguredTargetFields struct{}

func (keepUnconfiguredTargetFields) Description(context.Context) string {
	return "Keeps the server's host and path for targets that do not configure them."
}

func (m keepUnconfiguredTargetFields) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (keepUnconfiguredTargetFields) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	if req.StateValue.IsNull() || req.StateValue.IsUnknown() || req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}

	prior := req.StateValue.Elements()
	planned := req.PlanValue.Elements()
	priorKeys := make([]string, len(prior))
	priorCount := map[string]int{}
	for i, e := range prior {
		priorKeys[i] = targetKey(e)
		priorCount[priorKeys[i]]++
	}
	plannedCount := map[string]int{}
	for _, e := range planned {
		plannedCount[targetKey(e)]++
	}

	changed := false
	for i, e := range planned {
		obj, ok := e.(types.Object)
		key := targetKey(e)
		if !ok || key == "" {
			continue
		}
		attrs := obj.Attributes()
		host, _ := attrs["host"].(types.String)
		targetPath, _ := attrs["path"].(types.String)
		if !host.IsUnknown() && !targetPath.IsUnknown() {
			continue
		}

		match := -1
		if priorCount[key] == 1 && plannedCount[key] == 1 {
			match = slices.Index(priorKeys, key)
		} else if i < len(prior) && priorKeys[i] == key {
			match = i
		}
		if match < 0 {
			continue
		}

		priorObj, ok := prior[match].(types.Object)
		if !ok {
			continue
		}
		priorAttrs := priorObj.Attributes()
		if host.IsUnknown() {
			attrs["host"] = priorAttrs["host"]
		}
		if targetPath.IsUnknown() {
			attrs["path"] = priorAttrs["path"]
		}
		kept, d := types.ObjectValue(obj.AttributeTypes(ctx), attrs)
		resp.Diagnostics.Append(d...)
		planned[i] = kept
		changed = true
	}
	if !changed || resp.Diagnostics.HasError() {
		return
	}

	list, d := types.ListValue(req.PlanValue.ElementType(ctx), planned)
	resp.Diagnostics.Append(d...)
	resp.PlanValue = list
}

// targetKey identifies a target by what it points at, or returns "" when that
// is not known yet.
func targetKey(v attr.Value) string {
	obj, ok := v.(types.Object)
	if !ok || obj.IsNull() || obj.IsUnknown() {
		return ""
	}
	id, _ := obj.Attributes()["target_id"].(types.String)
	typ, _ := obj.Attributes()["target_type"].(types.String)
	if id.IsNull() || id.IsUnknown() || typ.IsNull() || typ.IsUnknown() {
		return ""
	}
	return typ.ValueString() + "/" + id.ValueString()
}

// preserveAuthSecrets copies sensitive auth fields (password, pin) from prior state/plan
// into the current model since the API redacts these values on read.
// It also preserves the structure of optional auth blocks (like link_auth) that the API
// may not return when disabled, ensuring state matches plan.
func preserveAuthSecrets(priorAuth, currentAuth types.Object) (types.Object, diag.Diagnostics) {
	var ret diag.Diagnostics

	if priorAuth.IsNull() || priorAuth.IsUnknown() || currentAuth.IsNull() || currentAuth.IsUnknown() {
		return currentAuth, ret
	}

	priorAttrs := priorAuth.Attributes()
	currentAttrs := currentAuth.Attributes()

	// Preserve password_auth sensitive field from plan/prior state.
	if priorPw, ok := priorAttrs["password_auth"].(types.Object); ok && !priorPw.IsNull() {
		if curPw, ok := currentAttrs["password_auth"].(types.Object); ok && !curPw.IsNull() {
			priorPwAttrs := priorPw.Attributes()
			curPwAttrs := curPw.Attributes()
			// Always use prior password value — API redacts it on read.
			if pw, ok := priorPwAttrs["password"]; ok {
				curPwAttrs["password"] = pw
				obj, d := types.ObjectValue(ReverseProxyPasswordAuthModel{}.TFType().AttrTypes, curPwAttrs)
				ret.Append(d...)
				currentAttrs["password_auth"] = obj
			}
		}
	}

	// Preserve pin_auth sensitive field from plan/prior state.
	if priorPin, ok := priorAttrs["pin_auth"].(types.Object); ok && !priorPin.IsNull() {
		if curPin, ok := currentAttrs["pin_auth"].(types.Object); ok && !curPin.IsNull() {
			priorPinAttrs := priorPin.Attributes()
			curPinAttrs := curPin.Attributes()
			// Always use prior pin value — API redacts it on read.
			if pin, ok := priorPinAttrs["pin"]; ok {
				curPinAttrs["pin"] = pin
				obj, d := types.ObjectValue(ReverseProxyPinAuthModel{}.TFType().AttrTypes, curPinAttrs)
				ret.Append(d...)
				currentAttrs["pin_auth"] = obj
			}
		}
	}

	// Preserve link_auth from plan/prior when API returns null.
	if priorLink, ok := priorAttrs["link_auth"].(types.Object); ok && !priorLink.IsNull() {
		if curLink, ok := currentAttrs["link_auth"].(types.Object); ok && curLink.IsNull() {
			currentAttrs["link_auth"] = priorLink
		}
	}

	// Preserve header_auths sensitive values from plan/prior state.
	if priorHeaders, ok := priorAttrs["header_auths"].(types.List); ok && !priorHeaders.IsNull() {
		if curHeaders, ok := currentAttrs["header_auths"].(types.List); ok && !curHeaders.IsNull() {
			var priorModels, curModels []ReverseProxyHeaderAuthModel
			ret.Append(priorHeaders.ElementsAs(context.Background(), &priorModels, false)...)
			ret.Append(curHeaders.ElementsAs(context.Background(), &curModels, false)...)
			// Match by index (order is stable) and restore redacted values.
			for i := range curModels {
				if i < len(priorModels) {
					curModels[i].Value = priorModels[i].Value
				}
			}
			newList, d := types.ListValueFrom(context.Background(), ReverseProxyHeaderAuthModel{}.TFType(), curModels)
			ret.Append(d...)
			currentAttrs["header_auths"] = newList
		}
	}

	result, d := types.ObjectValue(ReverseProxyServiceAuthModel{}.TFType().AttrTypes, currentAttrs)
	ret.Append(d...)
	return result, ret
}

// derivedHostTargets are the target types whose host management resolves from
// the peer or network resource on every read, whatever the request carried.
var derivedHostTargets = map[string]bool{"peer": true, "host": true, "domain": true}

// durationOptions are the target options management parses as durations and
// reports back in canonical form ("60s" as "1m0s").
var durationOptions = map[string]bool{"request_timeout": true, "session_idle_timeout": true}

// reconcileTargets returns the targets the API reported, keeping a prior value
// only where the API reports the same setting differently: a host the server
// derives for peer, host and domain targets, and options it omits when false or
// writes back in canonical form. Everything else follows the API, so a change
// made outside Terraform shows up as drift. prior is the plan on create and
// update and the prior state on read.
func reconcileTargets(ctx context.Context, prior, current types.List) (types.List, diag.Diagnostics) {
	var ret diag.Diagnostics
	if prior.IsNull() || prior.IsUnknown() || current.IsNull() || current.IsUnknown() {
		return current, ret
	}

	priorByID := map[string]types.Object{}
	for _, e := range prior.Elements() {
		obj, ok := e.(types.Object)
		if !ok || obj.IsNull() || obj.IsUnknown() {
			continue
		}
		if id, ok := obj.Attributes()["target_id"].(types.String); ok {
			priorByID[id.ValueString()] = obj
		}
	}

	out := current.Elements()
	for i, e := range out {
		cur, ok := e.(types.Object)
		if !ok || cur.IsNull() || cur.IsUnknown() {
			continue
		}
		attrs := cur.Attributes()
		id, _ := attrs["target_id"].(types.String)
		match, ok := priorByID[id.ValueString()]
		if !ok {
			continue
		}
		priorAttrs := match.Attributes()

		typ, _ := attrs["target_type"].(types.String)
		if host, ok := priorAttrs["host"].(types.String); ok && derivedHostTargets[typ.ValueString()] &&
			!host.IsNull() && !host.IsUnknown() {
			attrs["host"] = host
		}
		if opts, ok := attrs["options"].(types.Object); ok {
			priorOpts, _ := priorAttrs["options"].(types.Object)
			attrs["options"] = reconcileObject(ctx, priorOpts, opts)
		}

		obj, d := types.ObjectValue(cur.AttributeTypes(ctx), attrs)
		ret.Append(d...)
		out[i] = obj
	}
	if ret.HasError() {
		return current, ret
	}

	result, d := types.ListValue(current.ElementType(ctx), out)
	ret.Append(d...)
	return result, ret
}

// reconcileObject returns current, keeping each prior attribute that means the
// same as the reported one. The server omits a block whose settings are all
// empty, so a prior block holding only empty settings is kept when current is
// null.
func reconcileObject(ctx context.Context, prior, current types.Object) types.Object {
	if prior.IsNull() || prior.IsUnknown() {
		return current
	}
	if current.IsNull() {
		for _, v := range prior.Attributes() {
			if !isEmptySetting(v) {
				return current
			}
		}
		return prior
	}

	attrs := current.Attributes()
	for name, pv := range prior.Attributes() {
		if sameSetting(name, pv, attrs[name]) {
			attrs[name] = pv
		}
	}
	obj, d := types.ObjectValue(current.AttributeTypes(ctx), attrs)
	if d.HasError() {
		return current
	}
	return obj
}

// isEmptySetting reports whether v is a value the server does not report: null,
// false, or an empty collection.
func isEmptySetting(v attr.Value) bool {
	if v == nil || v.IsNull() {
		return true
	}
	if v.IsUnknown() {
		return false
	}
	switch tv := v.(type) {
	case types.Bool:
		return !tv.ValueBool()
	case types.Map:
		return len(tv.Elements()) == 0
	case types.List:
		return len(tv.Elements()) == 0
	}
	return false
}

// sameSetting reports whether a prior and a reported value mean the same to the
// server.
func sameSetting(name string, prior, current attr.Value) bool {
	if prior == nil || current == nil || prior.IsUnknown() || current.IsUnknown() {
		return false
	}
	if isEmptySetting(prior) && isEmptySetting(current) {
		return true
	}
	if durationOptions[name] {
		p, pok := prior.(types.String)
		c, cok := current.(types.String)
		if pok && cok && !p.IsNull() && !c.IsNull() {
			pd, perr := time.ParseDuration(p.ValueString())
			cd, cerr := time.ParseDuration(c.ValueString())
			if perr == nil && cerr == nil {
				return pd == cd
			}
		}
	}
	return prior.Equal(current)
}

func reverseProxyServiceTerraformToAPI(ctx context.Context, data *ReverseProxyServiceModel) (api.ServiceRequest, diag.Diagnostics) {
	var ret diag.Diagnostics

	req := api.ServiceRequest{
		Name:    data.Name.ValueString(),
		Domain:  data.Domain.ValueString(),
		Enabled: data.Enabled.ValueBool(),
	}

	if !data.Mode.IsNull() && !data.Mode.IsUnknown() {
		v := api.ServiceRequestMode(data.Mode.ValueString())
		req.Mode = &v
	}

	if !data.ListenPort.IsNull() && !data.ListenPort.IsUnknown() {
		v := int(data.ListenPort.ValueInt64())
		req.ListenPort = &v
	}

	if !data.PassHostHeader.IsNull() && !data.PassHostHeader.IsUnknown() {
		v := data.PassHostHeader.ValueBool()
		req.PassHostHeader = &v
	}
	if !data.RewriteRedirects.IsNull() && !data.RewriteRedirects.IsUnknown() {
		v := data.RewriteRedirects.ValueBool()
		req.RewriteRedirects = &v
	}
	if !data.Private.IsNull() && !data.Private.IsUnknown() {
		v := data.Private.ValueBool()
		req.Private = &v
	}
	if !data.AccessGroups.IsNull() && !data.AccessGroups.IsUnknown() {
		var groups []string
		ret.Append(data.AccessGroups.ElementsAs(ctx, &groups, false)...)
		req.AccessGroups = &groups
	}

	var targetModels []ReverseProxyServiceTargetModel
	ret.Append(data.Targets.ElementsAs(ctx, &targetModels, false)...)
	if ret.HasError() {
		return req, ret
	}

	targets := make([]api.ServiceTarget, 0, len(targetModels))
	for _, t := range targetModels {
		target := api.ServiceTarget{
			TargetId:   t.TargetId.ValueString(),
			TargetType: api.ServiceTargetTargetType(t.TargetType.ValueString()),
			Port:       int(t.Port.ValueInt64()),
			Protocol:   api.ServiceTargetProtocol(t.Protocol.ValueString()),
			Enabled:    t.Enabled.ValueBool(),
		}
		if !t.Host.IsNull() && !t.Host.IsUnknown() {
			v := t.Host.ValueString()
			target.Host = &v
		}
		if !t.Path.IsNull() && !t.Path.IsUnknown() {
			v := t.Path.ValueString()
			target.Path = &v
		}

		opts, d := targetOptionsTerraformToAPI(ctx, t.Options)
		ret.Append(d...)
		target.Options = opts

		targets = append(targets, target)
	}
	req.Targets = &targets

	authAttrs := data.Auth.Attributes()
	req.Auth = &api.ServiceAuthConfig{}

	authCfg := &api.ServiceAuthConfig{}

	if v, ok := authAttrs["password_auth"].(types.Object); ok && !v.IsNull() && !v.IsUnknown() {
		pwAttrs := v.Attributes()
		enabled, _ := pwAttrs["enabled"].(types.Bool)
		password, _ := pwAttrs["password"].(types.String)
		authCfg.PasswordAuth = &api.PasswordAuthConfig{
			Enabled:  enabled.ValueBool(),
			Password: password.ValueString(),
		}
	}

	if v, ok := authAttrs["pin_auth"].(types.Object); ok && !v.IsNull() && !v.IsUnknown() {
		pinAttrs := v.Attributes()
		enabled, _ := pinAttrs["enabled"].(types.Bool)
		pin, _ := pinAttrs["pin"].(types.String)
		authCfg.PinAuth = &api.PINAuthConfig{
			Enabled: enabled.ValueBool(),
			Pin:     pin.ValueString(),
		}
	}

	if v, ok := authAttrs["bearer_auth"].(types.Object); ok && !v.IsNull() && !v.IsUnknown() {
		bearerAttrs := v.Attributes()
		enabled, _ := bearerAttrs["enabled"].(types.Bool)
		bearerAuth := &api.BearerAuthConfig{
			Enabled: enabled.ValueBool(),
		}
		if groupsList, ok := bearerAttrs["distribution_groups"].(types.List); ok && !groupsList.IsNull() && !groupsList.IsUnknown() {
			var groups []string
			ret.Append(groupsList.ElementsAs(ctx, &groups, false)...)
			bearerAuth.DistributionGroups = &groups
		}
		authCfg.BearerAuth = bearerAuth
	}

	if v, ok := authAttrs["link_auth"].(types.Object); ok && !v.IsNull() && !v.IsUnknown() {
		linkAttrs := v.Attributes()
		enabled, _ := linkAttrs["enabled"].(types.Bool)
		authCfg.LinkAuth = &api.LinkAuthConfig{
			Enabled: enabled.ValueBool(),
		}
	}

	if v, ok := authAttrs["header_auths"].(types.List); ok && !v.IsNull() && !v.IsUnknown() {
		var headerAuthModels []ReverseProxyHeaderAuthModel
		ret.Append(v.ElementsAs(ctx, &headerAuthModels, false)...)
		var headerAuths []api.HeaderAuthConfig
		for _, h := range headerAuthModels {
			headerAuths = append(headerAuths, api.HeaderAuthConfig{
				Enabled: h.Enabled.ValueBool(),
				Header:  h.Header.ValueString(),
				Value:   h.Value.ValueString(),
			})
		}
		authCfg.HeaderAuths = &headerAuths
	}

	req.Auth = authCfg

	if !data.AccessRestrictions.IsNull() && !data.AccessRestrictions.IsUnknown() {
		arAttrs := data.AccessRestrictions.Attributes()
		ar := &api.AccessRestrictions{}
		hasAR := false
		if v, ok := arAttrs["allowed_cidrs"].(types.List); ok && !v.IsNull() && !v.IsUnknown() {
			var cidrs []string
			ret.Append(v.ElementsAs(ctx, &cidrs, false)...)
			ar.AllowedCidrs = &cidrs
			hasAR = true
		}
		if v, ok := arAttrs["blocked_cidrs"].(types.List); ok && !v.IsNull() && !v.IsUnknown() {
			var cidrs []string
			ret.Append(v.ElementsAs(ctx, &cidrs, false)...)
			ar.BlockedCidrs = &cidrs
			hasAR = true
		}
		if v, ok := arAttrs["allowed_countries"].(types.List); ok && !v.IsNull() && !v.IsUnknown() {
			var countries []string
			ret.Append(v.ElementsAs(ctx, &countries, false)...)
			ar.AllowedCountries = &countries
			hasAR = true
		}
		if v, ok := arAttrs["blocked_countries"].(types.List); ok && !v.IsNull() && !v.IsUnknown() {
			var countries []string
			ret.Append(v.ElementsAs(ctx, &countries, false)...)
			ar.BlockedCountries = &countries
			hasAR = true
		}
		if v, ok := arAttrs["crowdsec_mode"].(types.String); ok && !v.IsNull() && !v.IsUnknown() {
			mode := api.AccessRestrictionsCrowdsecMode(v.ValueString())
			ar.CrowdsecMode = &mode
			hasAR = true
		}
		if hasAR {
			req.AccessRestrictions = ar
		}
	}

	return req, ret
}

// Create creates a new reverse proxy service.
func (r *ReverseProxyService) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ReverseProxyServiceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	serviceReq, d := reverseProxyServiceTerraformToAPI(ctx, &data)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	svc, err := r.client.ReverseProxyServices.Create(ctx, serviceReq)
	if err != nil {
		resp.Diagnostics.AddError("Error creating reverse proxy service", err.Error())
		return
	}

	// Save plan values to preserve fields the API may override
	planAuth := data.Auth
	planTargets := data.Targets

	resp.Diagnostics.Append(reverseProxyServiceAPIToTerraform(ctx, svc, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	auth, authDiags := preserveAuthSecrets(planAuth, data.Auth)
	resp.Diagnostics.Append(authDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Auth = auth

	targets, targetDiags := reconcileTargets(ctx, planTargets, data.Targets)
	resp.Diagnostics.Append(targetDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Targets = targets

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Read refreshes the Terraform state with the latest data from the API.
func (r *ReverseProxyService) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ReverseProxyServiceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Save prior state to preserve fields the API may override
	priorAuth := data.Auth
	priorTargets := data.Targets

	svc, err := r.client.ReverseProxyServices.Get(ctx, data.Id.ValueString())
	if err != nil {
		if netbird.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error getting reverse proxy service", err.Error())
		return
	}

	resp.Diagnostics.Append(reverseProxyServiceAPIToTerraform(ctx, svc, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	auth, authDiags := preserveAuthSecrets(priorAuth, data.Auth)
	resp.Diagnostics.Append(authDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Auth = auth

	targets, targetDiags := reconcileTargets(ctx, priorTargets, data.Targets)
	resp.Diagnostics.Append(targetDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Targets = targets

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update modifies an existing reverse proxy service.
func (r *ReverseProxyService) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ReverseProxyServiceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	serviceReq, d := reverseProxyServiceTerraformToAPI(ctx, &data)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	svc, err := r.client.ReverseProxyServices.Update(ctx, data.Id.ValueString(), serviceReq)
	if err != nil {
		resp.Diagnostics.AddError("Error updating reverse proxy service", err.Error())
		return
	}

	// Save plan values to preserve fields the API may override
	planAuth := data.Auth
	planTargets := data.Targets

	resp.Diagnostics.Append(reverseProxyServiceAPIToTerraform(ctx, svc, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	auth, authDiags := preserveAuthSecrets(planAuth, data.Auth)
	resp.Diagnostics.Append(authDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Auth = auth

	targets, targetDiags := reconcileTargets(ctx, planTargets, data.Targets)
	resp.Diagnostics.Append(targetDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Targets = targets

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete removes a reverse proxy service.
func (r *ReverseProxyService) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ReverseProxyServiceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.ReverseProxyServices.Delete(ctx, data.Id.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting reverse proxy service", err.Error())
	}
}

// ImportState imports an existing reverse proxy service into Terraform state.
func (r *ReverseProxyService) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

var (
	_ resource.Resource                   = &ReverseProxyService{}
	_ resource.ResourceWithImportState    = &ReverseProxyService{}
	_ resource.ResourceWithValidateConfig = &ReverseProxyService{}
)
