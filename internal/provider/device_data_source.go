package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/negineri/terraform-provider-netgear-ap/internal/client"
)

var (
	_ datasource.DataSource              = &deviceDataSource{}
	_ datasource.DataSourceWithConfigure = &deviceDataSource{}
)

// NewDeviceDataSource returns the netgear_device data source.
func NewDeviceDataSource() datasource.DataSource {
	return &deviceDataSource{}
}

type deviceDataSource struct {
	client *client.Client
}

type deviceModel struct {
	ID              types.String `tfsdk:"id"`
	Model           types.String `tfsdk:"model"`
	Name            types.String `tfsdk:"name"`
	SerialNumber    types.String `tfsdk:"serial_number"`
	FirmwareVersion types.String `tfsdk:"firmware_version"`
	LANMACAddress   types.String `tfsdk:"lan_mac_address"`
	WLAN2GMAC       types.String `tfsdk:"wlan_2g_mac_address"`
	WLAN5GMAC       types.String `tfsdk:"wlan_5g_mac_address"`
	Country         types.String `tfsdk:"country"`
	IPAddress       types.String `tfsdk:"ip_address"`
	Netmask         types.String `tfsdk:"netmask"`
	Gateway         types.String `tfsdk:"gateway"`
	DNSServers      types.List   `tfsdk:"dns_servers"`
}

func (d *deviceDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_device"
}

func (d *deviceDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	computed := func(desc string) schema.StringAttribute {
		return schema.StringAttribute{MarkdownDescription: desc, Computed: true}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads information about the access point.",
		Attributes: map[string]schema.Attribute{
			"id":                  computed("The serial number."),
			"model":               computed("Model name, e.g. `WAX210`."),
			"name":                computed("AP name."),
			"serial_number":       computed("Serial number."),
			"firmware_version":    computed("Firmware version."),
			"lan_mac_address":     computed("MAC address of the LAN interface."),
			"wlan_2g_mac_address": computed("MAC address of the 2.4 GHz radio."),
			"wlan_5g_mac_address": computed("MAC address of the 5 GHz radio."),
			"country":             computed("Configured country/region."),
			"ip_address":          computed("IPv4 address of the management interface."),
			"netmask":             computed("IPv4 netmask of the management interface."),
			"gateway":             computed("IPv4 default gateway."),
			"dns_servers": schema.ListAttribute{
				MarkdownDescription: "DNS servers.",
				Computed:            true,
				ElementType:         types.StringType,
			},
		},
	}
}

func (d *deviceDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *client.Client, got %T", req.ProviderData))
		return
	}
	d.client = c
}

func (d *deviceDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	info, err := d.client.GetDeviceInfo(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read device information", err.Error())
		return
	}
	dns, diags := types.ListValueFrom(ctx, types.StringType, info.DNS)
	resp.Diagnostics.Append(diags...)
	m := deviceModel{
		ID:              types.StringValue(info.SerialNumber),
		Model:           types.StringValue(info.Model),
		Name:            types.StringValue(info.Name),
		SerialNumber:    types.StringValue(info.SerialNumber),
		FirmwareVersion: types.StringValue(info.FirmwareVersion),
		LANMACAddress:   types.StringValue(info.LANMACAddress),
		WLAN2GMAC:       types.StringValue(info.WLAN2GMAC),
		WLAN5GMAC:       types.StringValue(info.WLAN5GMAC),
		Country:         types.StringValue(info.Country),
		IPAddress:       types.StringValue(info.IPAddress),
		Netmask:         types.StringValue(info.Netmask),
		Gateway:         types.StringValue(info.Gateway),
		DNSServers:      dns,
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
