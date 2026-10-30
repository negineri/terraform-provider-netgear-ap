package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/negineri/terraform-provider-netgear-ap/internal/client"
)

var (
	_ resource.Resource                = &radioResource{}
	_ resource.ResourceWithConfigure   = &radioResource{}
	_ resource.ResourceWithImportState = &radioResource{}
)

// NewRadioResource returns the netgear_radio resource.
func NewRadioResource() resource.Resource {
	return &radioResource{}
}

type radioResource struct {
	client *client.Client
}

type radioModel struct {
	ID                 types.String `tfsdk:"id"`
	Band               types.String `tfsdk:"band"`
	WirelessMode       types.String `tfsdk:"wireless_mode"`
	ChannelWidth       types.String `tfsdk:"channel_width"`
	Channel            types.String `tfsdk:"channel"`
	TxPower            types.String `tfsdk:"tx_power"`
	RTSThreshold       types.Int64  `tfsdk:"rts_threshold"`
	ClientLimitEnabled types.Bool   `tfsdk:"client_limit_enabled"`
	ClientLimit        types.Int64  `tfsdk:"client_limit"`
	GreenMode          types.Bool   `tfsdk:"green_mode"`
	AggregationEnabled types.Bool   `tfsdk:"aggregation_enabled"`
	AggregationFrames  types.Int64  `tfsdk:"aggregation_frames"`
	AggregationBytes   types.Int64  `tfsdk:"aggregation_bytes"`
}

func (r *radioResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_radio"
}

func (r *radioResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	str := func(desc string, v ...validator.String) schema.StringAttribute {
		return schema.StringAttribute{
			MarkdownDescription: desc, Optional: true, Computed: true, Validators: v,
			PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		}
	}
	num := func(desc string, v ...validator.Int64) schema.Int64Attribute {
		return schema.Int64Attribute{
			MarkdownDescription: desc, Optional: true, Computed: true, Validators: v,
			PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
		}
	}
	flag := func(desc string) schema.BoolAttribute {
		return schema.BoolAttribute{
			MarkdownDescription: desc, Optional: true, Computed: true,
			PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
		}
	}

	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the settings of one radio of the access point. Attributes that are not set keep the current " +
			"value of the device. Destroying this resource leaves the device unchanged.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Same as `band`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"band": schema.StringAttribute{
				MarkdownDescription: "Radio band: `2.4GHz` or `5GHz`.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.OneOf(client.Band2G, client.Band5G)},
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"wireless_mode": str("Wireless mode: `11axg` or `11ng` for 2.4 GHz, `11axa` or `11ac` for 5 GHz.",
				stringvalidator.OneOf("11axg", "11ng", "11axa", "11ac")),
			"channel_width": str("Channel width: `HT20`, `HT40` or `HT20_40` for 2.4 GHz, `HT20`, `HT40`, `HT80` or `HT160` for 5 GHz.",
				stringvalidator.OneOf("HT20", "HT40", "HT20_40", "HT80", "HT160")),
			"channel": str("Channel number or `auto`. The available channels depend on the country and the channel width."),
			"tx_power": str("Transmit power: `full`, `half` or `quarter`.",
				stringvalidator.OneOf(client.TxPowerFull, client.TxPowerHalf, client.TxPowerQuarter)),
			"rts_threshold":        num("RTS threshold in bytes (`1`-`2346`).", int64validator.Between(1, 2346)),
			"client_limit_enabled": flag("Limit the number of associated clients."),
			"client_limit":         num("Maximum number of associated clients (`1`-`64`).", int64validator.Between(1, 64)),
			"green_mode":           flag("Green mode (obey the regulatory power limit)."),
			"aggregation_enabled":  flag("Enable frame aggregation. 2.4 GHz only."),
			"aggregation_frames":   num("Maximum number of aggregated frames (`1`-`255`). 2.4 GHz only.", int64validator.Between(1, 255)),
			"aggregation_bytes":    num("Maximum aggregation size in bytes (`2304`-`65535`). 2.4 GHz only.", int64validator.Between(2304, 65535)),
		},
	}
}

func (r *radioResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (m *radioModel) fromClient(r *client.Radio) {
	m.ID = types.StringValue(r.Band)
	m.Band = types.StringValue(r.Band)
	m.WirelessMode = types.StringValue(r.WirelessMode)
	m.ChannelWidth = types.StringValue(r.ChannelWidth)
	m.Channel = types.StringValue(r.Channel)
	m.TxPower = types.StringValue(r.TxPower)
	m.RTSThreshold = types.Int64Value(r.RTSThreshold)
	m.ClientLimitEnabled = types.BoolValue(r.ClientLimitEnabled)
	m.ClientLimit = types.Int64Value(r.ClientLimit)
	m.GreenMode = types.BoolValue(r.GreenMode)
	if r.HasAggregation {
		m.AggregationEnabled = types.BoolValue(r.AggregationEnabled)
		m.AggregationFrames = types.Int64Value(r.AggregationFrames)
		m.AggregationBytes = types.Int64Value(r.AggregationBytes)
	} else {
		m.AggregationEnabled = types.BoolNull()
		m.AggregationFrames = types.Int64Null()
		m.AggregationBytes = types.Int64Null()
	}
}

// merge overlays the known values of the plan onto the current radio
// settings and validates them against the choices offered by the device.
func (m *radioModel) merge(cur *client.Radio) diag.Diagnostics {
	var diags diag.Diagnostics
	known := func(v attr.Value) bool { return !v.IsNull() && !v.IsUnknown() }
	choice := func(name, opt string, v types.String, dst *string) {
		if !known(v) {
			return
		}
		if opts := cur.Options[opt]; len(opts) > 0 && !slices.Contains(opts, v.ValueString()) {
			diags.AddAttributeError(path.Root(name), "Unsupported value",
				fmt.Sprintf("%q is not available on the %s radio with the current settings. Available values: %s",
					v.ValueString(), cur.Band, strings.Join(opts, ", ")))
			return
		}
		*dst = v.ValueString()
	}
	choice("wireless_mode", "hwmode", m.WirelessMode, &cur.WirelessMode)
	choice("channel_width", "htmode", m.ChannelWidth, &cur.ChannelWidth)
	if known(m.Channel) {
		// The channel list offered depends on the channel width currently
		// configured, so it is only validated when the width does not change.
		if known(m.ChannelWidth) && m.ChannelWidth.ValueString() != cur.ChannelWidth {
			cur.Channel = m.Channel.ValueString()
		} else {
			choice("channel", "channel", m.Channel, &cur.Channel)
		}
	}
	if known(m.TxPower) {
		cur.TxPower = m.TxPower.ValueString()
	}
	if known(m.RTSThreshold) {
		cur.RTSThreshold = m.RTSThreshold.ValueInt64()
	}
	if known(m.ClientLimitEnabled) {
		cur.ClientLimitEnabled = m.ClientLimitEnabled.ValueBool()
	}
	if known(m.ClientLimit) {
		cur.ClientLimit = m.ClientLimit.ValueInt64()
	}
	if known(m.GreenMode) {
		cur.GreenMode = m.GreenMode.ValueBool()
	}
	for name, v := range map[string]attr.Value{
		"aggregation_enabled": m.AggregationEnabled, "aggregation_frames": m.AggregationFrames, "aggregation_bytes": m.AggregationBytes,
	} {
		if known(v) && !cur.HasAggregation {
			diags.AddAttributeError(path.Root(name), "Unsupported attribute",
				fmt.Sprintf("%s is not available on the %s radio.", name, cur.Band))
		}
	}
	if cur.HasAggregation {
		if known(m.AggregationEnabled) {
			cur.AggregationEnabled = m.AggregationEnabled.ValueBool()
		}
		if known(m.AggregationFrames) {
			cur.AggregationFrames = m.AggregationFrames.ValueInt64()
		}
		if known(m.AggregationBytes) {
			cur.AggregationBytes = m.AggregationBytes.ValueInt64()
		}
	}
	return diags
}

func (r *radioResource) write(ctx context.Context, plan *radioModel, diags *diag.Diagnostics) {
	band := plan.Band.ValueString()
	cur, err := r.client.GetRadio(ctx, band)
	if err != nil {
		diags.AddError("Unable to read radio settings", err.Error())
		return
	}
	before := *cur
	diags.Append(plan.merge(cur)...)
	if diags.HasError() {
		return
	}
	if !radioEqual(&before, cur) {
		if err := r.client.UpdateRadio(ctx, cur); err != nil {
			diags.AddError("Unable to update radio settings", err.Error())
			return
		}
		if cur, err = r.client.GetRadio(ctx, band); err != nil {
			diags.AddError("Unable to read radio settings", err.Error())
			return
		}
	}
	plan.fromClient(cur)
}

func radioEqual(a, b *client.Radio) bool {
	a2, b2 := *a, *b
	a2.Options, b2.Options = nil, nil
	return fmt.Sprintf("%+v", a2) == fmt.Sprintf("%+v", b2)
}

func (r *radioResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan radioModel
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

func (r *radioResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state radioModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	cur, err := r.client.GetRadio(ctx, state.Band.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read radio settings", err.Error())
		return
	}
	state.fromClient(cur)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *radioResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan radioModel
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

func (r *radioResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// The radio cannot be removed; its settings are left as they are.
}

func (r *radioResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if _, err := client.RadioDevice(req.ID); err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("band"), req.ID)...)
}
