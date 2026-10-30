// Package provider implements the Terraform provider for NETGEAR WAX210
// access points.
package provider

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/negineri/terraform-provider-netgear-ap/internal/client"
)

var _ provider.Provider = &netgearProvider{}

type netgearProvider struct {
	version string
}

type providerModel struct {
	Endpoint     types.String `tfsdk:"endpoint"`
	Username     types.String `tfsdk:"username"`
	Password     types.String `tfsdk:"password"`
	Insecure     types.Bool   `tfsdk:"insecure"`
	ApplyTimeout types.Int64  `tfsdk:"apply_timeout"`
}

// New returns a constructor of the provider.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &netgearProvider{version: version}
	}
}

func (p *netgearProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "netgear"
	resp.Version = p.version
}

func (p *netgearProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages NETGEAR WAX210 (AX1800) Wi-Fi 6 access points in standalone mode through their web UI.\n\n" +
			"The device allows only one logged in session at a time. Running Terraform logs out a user of the web UI and vice versa.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "Base URL of the access point, e.g. `https://192.168.0.100`. Can also be set with the `NETGEAR_AP_ENDPOINT` environment variable.",
				Optional:            true,
			},
			"username": schema.StringAttribute{
				MarkdownDescription: "Login user name. Defaults to `admin`. Can also be set with the `NETGEAR_AP_USERNAME` environment variable.",
				Optional:            true,
			},
			"password": schema.StringAttribute{
				MarkdownDescription: "Login password. Can also be set with the `NETGEAR_AP_PASSWORD` environment variable.",
				Optional:            true,
				Sensitive:           true,
			},
			"insecure": schema.BoolAttribute{
				MarkdownDescription: "Skip TLS certificate verification. Defaults to `true` because the device uses a self-signed certificate. Can also be set with the `NETGEAR_AP_INSECURE` environment variable.",
				Optional:            true,
			},
			"apply_timeout": schema.Int64Attribute{
				MarkdownDescription: "Maximum number of seconds to wait for the device to apply changes. Defaults to `180`.",
				Optional:            true,
			},
		},
	}
}

func (p *netgearProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	for _, a := range []struct {
		name string
		v    interface{ IsUnknown() bool }
	}{
		{"endpoint", cfg.Endpoint}, {"username", cfg.Username}, {"password", cfg.Password},
		{"insecure", cfg.Insecure}, {"apply_timeout", cfg.ApplyTimeout},
	} {
		if a.v.IsUnknown() {
			resp.Diagnostics.AddAttributeError(path.Root(a.name), "Unknown provider configuration value",
				"The provider cannot be configured with a value that is unknown until apply. Set the value statically or use the environment variable.")
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := stringOrEnv(cfg.Endpoint, "NETGEAR_AP_ENDPOINT")
	username := stringOrEnv(cfg.Username, "NETGEAR_AP_USERNAME")
	password := stringOrEnv(cfg.Password, "NETGEAR_AP_PASSWORD")
	insecure := true
	if !cfg.Insecure.IsNull() {
		insecure = cfg.Insecure.ValueBool()
	} else if v := os.Getenv("NETGEAR_AP_INSECURE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			resp.Diagnostics.AddError("Invalid NETGEAR_AP_INSECURE", err.Error())
			return
		}
		insecure = b
	}

	if endpoint == "" {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Missing endpoint",
			"Set the endpoint attribute or the NETGEAR_AP_ENDPOINT environment variable.")
	}
	if password == "" {
		resp.Diagnostics.AddAttributeError(path.Root("password"), "Missing password",
			"Set the password attribute or the NETGEAR_AP_PASSWORD environment variable.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	ccfg := client.Config{
		Endpoint: endpoint,
		Username: username,
		Password: password,
		Insecure: insecure,
	}
	if !cfg.ApplyTimeout.IsNull() {
		ccfg.ApplyTimeout = time.Duration(cfg.ApplyTimeout.ValueInt64()) * time.Second
	}
	c, err := client.New(ccfg)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create NETGEAR AP client", err.Error())
		return
	}
	resp.DataSourceData = c
	resp.ResourceData = c
}

func stringOrEnv(v types.String, env string) string {
	if !v.IsNull() {
		return v.ValueString()
	}
	return os.Getenv(env)
}

func (p *netgearProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewSSIDResource,
		NewRadioResource,
	}
}

func (p *netgearProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewDeviceDataSource,
	}
}
