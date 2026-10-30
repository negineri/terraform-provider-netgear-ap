package provider

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/negineri/terraform-provider-netgear-ap/internal/client"
)

var (
	_ resource.Resource                   = &ssidResource{}
	_ resource.ResourceWithConfigure      = &ssidResource{}
	_ resource.ResourceWithImportState    = &ssidResource{}
	_ resource.ResourceWithValidateConfig = &ssidResource{}

	rePassphrase = regexp.MustCompile(`^([0-9a-fA-F]{64}|[ -~]{8,63})$`)
	reMAC        = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
)

// NewSSIDResource returns the netgear_ssid resource.
func NewSSIDResource() resource.Resource {
	return &ssidResource{}
}

type ssidResource struct {
	client *client.Client
}

type ssidModel struct {
	ID                 types.String `tfsdk:"id"`
	Slot               types.Int64  `tfsdk:"slot"`
	SSID               types.String `tfsdk:"ssid"`
	Enabled2G          types.Bool   `tfsdk:"enabled_2g"`
	Enabled5G          types.Bool   `tfsdk:"enabled_5g"`
	Security           types.String `tfsdk:"security"`
	Passphrase         types.String `tfsdk:"passphrase"`
	Hidden             types.Bool   `tfsdk:"hidden"`
	ClientIsolation    types.Bool   `tfsdk:"client_isolation"`
	VLANID             types.Int64  `tfsdk:"vlan_id"`
	FastRoaming        types.Bool   `tfsdk:"fast_roaming"`
	BandSteering       types.Bool   `tfsdk:"band_steering"`
	GroupRekeyInterval types.Int64  `tfsdk:"group_rekey_interval"`
	RadiusServer       types.String `tfsdk:"radius_server"`
	RadiusPort         types.Int64  `tfsdk:"radius_port"`
	RadiusSecret       types.String `tfsdk:"radius_secret"`
	AccountingEnabled  types.Bool   `tfsdk:"accounting_enabled"`
	AccountingServer   types.String `tfsdk:"accounting_server"`
	AccountingPort     types.Int64  `tfsdk:"accounting_port"`
	AccountingSecret   types.String `tfsdk:"accounting_secret"`
	AccountingInterval types.Int64  `tfsdk:"accounting_interval"`
	MACFilter          types.String `tfsdk:"mac_filter"`
	MACAddresses       types.Set    `tfsdk:"mac_addresses"`
}

func (r *ssidResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ssid"
}

func (r *ssidResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages one of the SSID slots of the access point. The SSID is shared by the 2.4 GHz and 5 GHz radios " +
			"and can be enabled per radio.\n\n" +
			"The slots always exist on the device, so creating this resource takes over the slot and destroying it only disables the SSID " +
			"on both radios (the other settings are left as they are).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The slot number.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"slot": schema.Int64Attribute{
				MarkdownDescription: fmt.Sprintf("SSID slot number (`1`-`%d`), as listed in the web UI.", client.MaxSSIDSlot),
				Required:            true,
				Validators:          []validator.Int64{int64validator.Between(1, client.MaxSSIDSlot)},
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"ssid": schema.StringAttribute{
				MarkdownDescription: "Network name (1-32 characters).",
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthBetween(1, 32)},
			},
			"enabled_2g": schema.BoolAttribute{
				MarkdownDescription: "Broadcast the SSID on the 2.4 GHz radio. Defaults to `true`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"enabled_5g": schema.BoolAttribute{
				MarkdownDescription: "Broadcast the SSID on the 5 GHz radio. Defaults to `true`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"security": schema.StringAttribute{
				MarkdownDescription: "Security mode. One of `none`, `owe` (Enhanced Open), `psk2` (WPA2-Personal), `sae` (WPA3-Personal), " +
					"`sae-mixed` (WPA2/WPA3-Personal), `wpa2` (WPA2-Enterprise), `wpa3-mixed` (WPA2/WPA3-Enterprise), `wpa3` (WPA3-Enterprise). " +
					"Defaults to `sae-mixed`.",
				Optional:   true,
				Computed:   true,
				Default:    stringdefault.StaticString(client.SecurityWPA23PSK),
				Validators: []validator.String{stringvalidator.OneOf(client.SecurityModes...)},
			},
			"passphrase": schema.StringAttribute{
				MarkdownDescription: "Pre-shared key (8-63 printable ASCII characters or 64 hex digits). Required for the personal security modes.",
				Optional:            true,
				Sensitive:           true,
				Validators: []validator.String{stringvalidator.RegexMatches(rePassphrase,
					"must be 8-63 printable ASCII characters or 64 hexadecimal digits")},
			},
			"hidden": schema.BoolAttribute{
				MarkdownDescription: "Hide the SSID (do not broadcast it). Defaults to `false`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"client_isolation": schema.BoolAttribute{
				MarkdownDescription: "Prevent wireless clients of this SSID from communicating with each other. Defaults to `false`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"vlan_id": schema.Int64Attribute{
				MarkdownDescription: "Enable VLAN isolation and tag the traffic of this SSID with the given VLAN ID (`1`-`4094`). " +
					"When omitted, VLAN isolation is disabled.",
				Optional:   true,
				Validators: []validator.Int64{int64validator.Between(1, 4094)},
			},
			"fast_roaming": schema.BoolAttribute{
				MarkdownDescription: "Enable fast roaming (802.11r). Defaults to `false`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"band_steering": schema.BoolAttribute{
				MarkdownDescription: "Steer dual band clients to the 5 GHz radio. Requires `enabled_2g` and `enabled_5g` to be `true`. Defaults to `false`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"group_rekey_interval": schema.Int64Attribute{
				MarkdownDescription: "WPA group key update interval in seconds (`30`-`3600`, `0` disables). Defaults to `3600`.",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(3600),
				Validators: []validator.Int64{int64validator.Any(
					int64validator.OneOf(0), int64validator.Between(30, 3600))},
			},
			"radius_server": schema.StringAttribute{
				MarkdownDescription: "RADIUS authentication server address. Required for the enterprise security modes.",
				Optional:            true,
			},
			"radius_port": schema.Int64Attribute{
				MarkdownDescription: "RADIUS authentication server port. Defaults to `1812`.",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(1812),
				Validators:          []validator.Int64{int64validator.Between(1, 65535)},
			},
			"radius_secret": schema.StringAttribute{
				MarkdownDescription: "RADIUS shared secret (1-64 characters). Required for the enterprise security modes.",
				Optional:            true,
				Sensitive:           true,
				Validators:          []validator.String{stringvalidator.LengthBetween(1, 64)},
			},
			"accounting_enabled": schema.BoolAttribute{
				MarkdownDescription: "Enable RADIUS accounting. Defaults to `false`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"accounting_server": schema.StringAttribute{
				MarkdownDescription: "RADIUS accounting server address. Required when `accounting_enabled` is `true`.",
				Optional:            true,
			},
			"accounting_port": schema.Int64Attribute{
				MarkdownDescription: "RADIUS accounting server port. Defaults to `1813`.",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(1813),
				Validators:          []validator.Int64{int64validator.Between(1, 65535)},
			},
			"accounting_secret": schema.StringAttribute{
				MarkdownDescription: "RADIUS accounting shared secret. Required when `accounting_enabled` is `true`.",
				Optional:            true,
				Sensitive:           true,
				Validators:          []validator.String{stringvalidator.LengthBetween(1, 64)},
			},
			"accounting_interval": schema.Int64Attribute{
				MarkdownDescription: "Interim accounting update interval in seconds (`60`-`600`). Defaults to `600`.",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(600),
				Validators:          []validator.Int64{int64validator.Between(60, 600)},
			},
			"mac_filter": schema.StringAttribute{
				MarkdownDescription: "MAC address filter mode: `disabled`, `allow` (only listed clients may connect) or `deny` (listed clients are rejected). Defaults to `disabled`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(client.MACFilterDisabled),
				Validators: []validator.String{stringvalidator.OneOf(
					client.MACFilterDisabled, client.MACFilterAllow, client.MACFilterDeny)},
			},
			"mac_addresses": schema.SetAttribute{
				MarkdownDescription: "Client MAC addresses for the MAC filter, in lower case (e.g. `aa:bb:cc:dd:ee:ff`). Up to 64 entries. Required when `mac_filter` is not `disabled`.",
				Optional:            true,
				ElementType:         types.StringType,
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, 64),
					setvalidator.ValueStringsAre(stringvalidator.RegexMatches(reMAC, "must be a lower case MAC address like aa:bb:cc:dd:ee:ff")),
				},
			},
		},
	}
}

func (r *ssidResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m ssidModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || m.Security.IsUnknown() {
		return
	}
	sec := client.SecurityWPA23PSK
	if !m.Security.IsNull() {
		sec = m.Security.ValueString()
	}

	requireIf := func(cond bool, v attr.Value, name, why string) {
		if v.IsUnknown() {
			return
		}
		switch {
		case cond && v.IsNull():
			resp.Diagnostics.AddAttributeError(path.Root(name), "Missing attribute", fmt.Sprintf("%s is required %s.", name, why))
		case !cond && !v.IsNull():
			resp.Diagnostics.AddAttributeError(path.Root(name), "Unexpected attribute", fmt.Sprintf("%s can only be set %s.", name, why))
		}
	}
	requireIf(client.IsPersonal(sec), m.Passphrase, "passphrase", "for the personal security modes (psk2, sae, sae-mixed)")
	requireIf(client.IsEnterprise(sec), m.RadiusServer, "radius_server", "for the enterprise security modes (wpa2, wpa3-mixed, wpa3)")
	requireIf(client.IsEnterprise(sec), m.RadiusSecret, "radius_secret", "for the enterprise security modes (wpa2, wpa3-mixed, wpa3)")
	if !m.AccountingEnabled.IsUnknown() {
		acct := m.AccountingEnabled.ValueBool()
		requireIf(acct, m.AccountingServer, "accounting_server", "when accounting_enabled is true")
		requireIf(acct, m.AccountingSecret, "accounting_secret", "when accounting_enabled is true")
	}
	if m.BandSteering.ValueBool() && !m.Enabled2G.IsUnknown() && !m.Enabled5G.IsUnknown() &&
		((!m.Enabled2G.IsNull() && !m.Enabled2G.ValueBool()) || (!m.Enabled5G.IsNull() && !m.Enabled5G.ValueBool())) {
		resp.Diagnostics.AddAttributeError(path.Root("band_steering"), "Invalid band steering",
			"band_steering requires the SSID to be enabled on both radios (enabled_2g and enabled_5g).")
	}
	if !m.MACFilter.IsUnknown() {
		filter := !m.MACFilter.IsNull() && m.MACFilter.ValueString() != client.MACFilterDisabled
		requireIf(filter, m.MACAddresses, "mac_addresses", "when mac_filter is allow or deny")
	}
}

func (r *ssidResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *client.Client, got %T", req.ProviderData))
		return
	}
	r.client = c
}

func (m *ssidModel) toClient(ctx context.Context) (*client.SSID, diag.Diagnostics) {
	var diags diag.Diagnostics
	s := &client.SSID{
		Slot:               int(m.Slot.ValueInt64()),
		Name:               m.SSID.ValueString(),
		Enabled2G:          m.Enabled2G.ValueBool(),
		Enabled5G:          m.Enabled5G.ValueBool(),
		Security:           m.Security.ValueString(),
		Passphrase:         m.Passphrase.ValueString(),
		Hidden:             m.Hidden.ValueBool(),
		ClientIsolation:    m.ClientIsolation.ValueBool(),
		VLANEnabled:        !m.VLANID.IsNull(),
		FastRoaming:        m.FastRoaming.ValueBool(),
		BandSteering:       m.BandSteering.ValueBool(),
		GroupRekeyInterval: m.GroupRekeyInterval.ValueInt64(),
		RadiusServer:       m.RadiusServer.ValueString(),
		RadiusPort:         m.RadiusPort.ValueInt64(),
		RadiusSecret:       m.RadiusSecret.ValueString(),
		AccountingEnabled:  m.AccountingEnabled.ValueBool(),
		AccountingServer:   m.AccountingServer.ValueString(),
		AccountingPort:     m.AccountingPort.ValueInt64(),
		AccountingSecret:   m.AccountingSecret.ValueString(),
		AccountingInterval: m.AccountingInterval.ValueInt64(),
		MACFilter:          m.MACFilter.ValueString(),
	}
	if !m.VLANID.IsNull() {
		s.VLANID = m.VLANID.ValueInt64()
	}
	if !m.MACAddresses.IsNull() && !m.MACAddresses.IsUnknown() {
		diags.Append(m.MACAddresses.ElementsAs(ctx, &s.MACList, false)...)
		sort.Strings(s.MACList)
	}
	return s, diags
}

// fromClient updates the model with the values read from the device.
//
// Some settings are only sent to the device when they are relevant (e.g. the
// RADIUS port for enterprise security). The device keeps or resets the
// others, so for those the prior value is kept to avoid spurious diffs.
// prior is nil on import.
func (m *ssidModel) fromClient(s *client.SSID, prior *ssidModel) {
	m.ID = types.StringValue(strconv.Itoa(s.Slot))
	m.Slot = types.Int64Value(int64(s.Slot))
	m.SSID = types.StringValue(s.Name)
	m.Enabled2G = types.BoolValue(s.Enabled2G)
	m.Enabled5G = types.BoolValue(s.Enabled5G)
	m.Security = types.StringValue(s.Security)
	m.Hidden = types.BoolValue(s.Hidden)
	m.ClientIsolation = types.BoolValue(s.ClientIsolation)
	m.FastRoaming = types.BoolValue(s.FastRoaming)
	m.BandSteering = types.BoolValue(s.BandSteering)
	m.AccountingEnabled = types.BoolValue(s.AccountingEnabled)
	m.MACFilter = types.StringValue(s.MACFilter)

	keep := func(cond bool, dev attr.Value, priorVal func(*ssidModel) attr.Value) attr.Value {
		if cond || prior == nil {
			return dev
		}
		return priorVal(prior)
	}

	if s.VLANEnabled {
		m.VLANID = types.Int64Value(s.VLANID)
	} else {
		m.VLANID = types.Int64Null()
	}

	personal := client.IsPersonal(s.Security)
	enterprise := client.IsEnterprise(s.Security)
	m.Passphrase = types.StringNull()
	if personal {
		m.Passphrase = types.StringValue(s.Passphrase)
	}
	m.RadiusServer, m.RadiusSecret = types.StringNull(), types.StringNull()
	if enterprise {
		m.RadiusServer = types.StringValue(s.RadiusServer)
		m.RadiusSecret = types.StringValue(s.RadiusSecret)
	}
	m.AccountingServer, m.AccountingSecret = types.StringNull(), types.StringNull()
	if s.AccountingEnabled {
		m.AccountingServer = types.StringValue(s.AccountingServer)
		m.AccountingSecret = types.StringValue(s.AccountingSecret)
	}

	m.GroupRekeyInterval = keep(s.Security != client.SecurityNone && s.Security != client.SecurityOWE,
		types.Int64Value(s.GroupRekeyInterval), func(p *ssidModel) attr.Value { return p.GroupRekeyInterval }).(types.Int64)
	m.RadiusPort = keep(enterprise, types.Int64Value(s.RadiusPort),
		func(p *ssidModel) attr.Value { return p.RadiusPort }).(types.Int64)
	m.AccountingPort = keep(s.AccountingEnabled, types.Int64Value(s.AccountingPort),
		func(p *ssidModel) attr.Value { return p.AccountingPort }).(types.Int64)
	m.AccountingInterval = keep(s.AccountingEnabled, types.Int64Value(s.AccountingInterval),
		func(p *ssidModel) attr.Value { return p.AccountingInterval }).(types.Int64)

	if s.MACFilter == client.MACFilterDisabled {
		m.MACAddresses = types.SetNull(types.StringType)
	} else {
		elems := make([]attr.Value, 0, len(s.MACList))
		for _, mac := range s.MACList {
			elems = append(elems, types.StringValue(mac))
		}
		m.MACAddresses = types.SetValueMust(types.StringType, elems)
	}
}

func (r *ssidResource) write(ctx context.Context, plan *ssidModel, diags *diag.Diagnostics) {
	s, d := plan.toClient(ctx)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	if err := r.client.UpdateSSID(ctx, s); err != nil {
		diags.AddError("Unable to update SSID", err.Error())
		return
	}
	got, err := r.client.GetSSID(ctx, s.Slot)
	if err != nil {
		diags.AddError("Unable to read SSID", err.Error())
		return
	}
	prior := *plan
	plan.fromClient(got, &prior)
}

func (r *ssidResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ssidModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ssidResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ssidModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetSSID(ctx, int(state.Slot.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Unable to read SSID", err.Error())
		return
	}
	var prior *ssidModel
	if !state.SSID.IsNull() { // nil right after import
		p := state
		prior = &p
	}
	state.fromClient(got, prior)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ssidResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ssidModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ssidResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ssidModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DisableSSID(ctx, int(state.Slot.ValueInt64())); err != nil {
		resp.Diagnostics.AddError("Unable to disable SSID", err.Error())
	}
}

func (r *ssidResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	slot, err := strconv.Atoi(req.ID)
	if err != nil || slot < 1 || slot > client.MaxSSIDSlot {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("expected an SSID slot number between 1 and %d, got %q", client.MaxSSIDSlot, req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("slot"), int64(slot))...)
}
