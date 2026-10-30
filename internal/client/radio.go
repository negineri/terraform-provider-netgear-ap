package client

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
)

// Radio bands.
const (
	Band2G = "2.4GHz"
	Band5G = "5GHz"
)

// Transmit power levels.
const (
	TxPowerFull    = "full"
	TxPowerHalf    = "half"
	TxPowerQuarter = "quarter"
)

var txPowerToUCI = map[string]string{TxPowerFull: "0", TxPowerHalf: "18", TxPowerQuarter: "15"}

// Radio is the configuration of one radio (wifi0 = 2.4 GHz, wifi1 = 5 GHz).
type Radio struct {
	Band string
	// WirelessMode is the UCI hwmode, e.g. "11axg", "11ng", "11axa", "11ac".
	WirelessMode string
	// ChannelWidth is the UCI htmode, e.g. "HT20", "HT40", "HT20_40", "HT80", "HT160".
	ChannelWidth string
	// Channel is "auto" or a channel number.
	Channel            string
	TxPower            string
	RTSThreshold       int64
	ClientLimitEnabled bool
	ClientLimit        int64
	GreenMode          bool
	// Aggregation settings exist on the 2.4 GHz radio only.
	HasAggregation     bool
	AggregationEnabled bool
	AggregationFrames  int64
	AggregationBytes   int64

	// Options lists the values offered by the device for select fields,
	// keyed by UCI option name (hwmode, htmode, channel).
	Options map[string][]string
}

// RadioDevice returns the UCI device name for a band.
func RadioDevice(band string) (string, error) {
	switch band {
	case Band2G:
		return "wifi0", nil
	case Band5G:
		return "wifi1", nil
	}
	return "", fmt.Errorf("invalid band %q: must be %q or %q", band, Band2G, Band5G)
}

func (c *Client) radioFragment(ctx context.Context, dev string) (*Form, string, error) {
	body, err := c.do(ctx, http.MethodGet, "admin/network/wifi_device?device="+dev, nil)
	if err != nil {
		return nil, "", err
	}
	f := ParseForm(body, "")
	if _, ok := f.Get("cbid.wireless." + dev + ".htmode"); !ok {
		return nil, "", fmt.Errorf("unexpected response from the device: radio settings of %s not found: %s", dev, truncate(body, 300))
	}
	return f, body, nil
}

var reOption = regexp.MustCompile(`<option id="cbi-wireless-(wifi[0-9])-([a-z_]+)-[^"]*" value="([^"]*)"`)

// GetRadio reads the configuration of a radio.
func (c *Client) GetRadio(ctx context.Context, band string) (*Radio, error) {
	dev, err := RadioDevice(band)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	f, body, err := c.radioFragment(ctx, dev)
	if err != nil {
		return nil, err
	}
	get := func(opt string) string {
		v, _ := f.Get("cbid.wireless." + dev + "." + opt)
		return v
	}
	r := &Radio{
		Band:               band,
		WirelessMode:       get("hwmode"),
		ChannelWidth:       get("htmode"),
		Channel:            get("channel"),
		RTSThreshold:       atoiDefault(get("rts"), 2346),
		ClientLimitEnabled: get("clientlimits_enable") == "1",
		ClientLimit:        atoiDefault(get("clientlimits_number"), 64),
		GreenMode:          get("obeyregpower") == "1",
		Options:            map[string][]string{},
	}
	for name, v := range txPowerToUCI {
		if v == get("txpower") {
			r.TxPower = name
		}
	}
	if r.TxPower == "" {
		r.TxPower = get("txpower")
	}
	if _, ok := f.Get("cbid.wireless." + dev + ".aggregation_frame"); ok {
		r.HasAggregation = true
		r.AggregationEnabled = get("aggregation_enable") == "1"
		r.AggregationFrames = atoiDefault(get("aggregation_frame"), 0)
		r.AggregationBytes = atoiDefault(get("aggregation_byte"), 0)
	}
	for _, m := range reOption.FindAllStringSubmatch(body, -1) {
		if m[1] == dev {
			r.Options[m[2]] = append(r.Options[m[2]], m[3])
		}
	}
	return r, nil
}

var (
	reChannelHidden = regexp.MustCompile(`\$\("input\[name='(wireless\.wifi[0-9]\.channel[a-z_]*)'\]"\)\.val\("([^"]*)"\);`)
	reMgmtVLAN      = regexp.MustCompile(`WLANVLANEnable"\]\[value="'\+(\d+)\+'"\]`)
	reGuestEnabled  = regexp.MustCompile(`var gn_value = '([^']*)'`)
)

// buildWirelessForm reconstructs the main "Wireless" settings form the
// browser submits, including the radio sub forms that are loaded with AJAX.
func buildWirelessForm(page string, radios map[string]*Form) (*Form, error) {
	f := ParseForm(page, "cbi")
	if _, ok := f.Get("cbid.system.system.SystemName"); !ok {
		return nil, fmt.Errorf("unexpected response from the device: wireless settings form not found: %s", truncate(page, 300))
	}
	// Values filled in by JavaScript on page load.
	for _, m := range reChannelHidden.FindAllStringSubmatch(page, -1) {
		f.SetIfPresent(m[1], m[2])
	}
	guest := false
	for _, m := range reGuestEnabled.FindAllStringSubmatch(page, -1) {
		if m[1] != "" && m[1] != "Disable" {
			guest = true
		}
	}
	f.Set("cbid.dhcp.guest.ignore", b01(!guest))
	f.SetIfPresent("cbid.wireless.wifi1.nochannel", "0")
	vlan := "0"
	if m := reMgmtVLAN.FindStringSubmatch(page); m != nil {
		vlan = m[1]
	}
	f.Set("cbid.network.sys.WLANVLANEnable", vlan)

	for _, dev := range []string{"wifi0", "wifi1"} {
		rf, ok := radios[dev]
		if !ok {
			continue
		}
		f.Fields = append(f.Fields, rf.Fields...)
	}
	return f, nil
}

// UpdateRadio writes the configuration of a radio and applies it.
func (c *Client) UpdateRadio(ctx context.Context, r *Radio) error {
	dev, err := RadioDevice(r.Band)
	if err != nil {
		return err
	}
	return c.stageAndApply(ctx, func() error {
		page, err := c.do(ctx, http.MethodGet, "admin/network/wireless_device", nil)
		if err != nil {
			return err
		}
		radios := map[string]*Form{}
		for _, d := range []string{"wifi0", "wifi1"} {
			rf, _, err := c.radioFragment(ctx, d)
			if err != nil {
				return err
			}
			radios[d] = rf
		}

		rf := radios[dev]
		p := "cbid.wireless." + dev + "."
		if r.WirelessMode != "" {
			rf.Set(p+"hwmode", r.WirelessMode)
		}
		if r.ChannelWidth != "" {
			rf.Set(p+"htmode", r.ChannelWidth)
		}
		if r.TxPower != "" {
			v, ok := txPowerToUCI[r.TxPower]
			if !ok {
				return fmt.Errorf("invalid tx power %q", r.TxPower)
			}
			rf.Set(p+"txpower", v)
		}
		rf.Set(p+"rts", strconv.FormatInt(r.RTSThreshold, 10))
		rf.Set(p+"clientlimits_enable", b01(r.ClientLimitEnabled))
		rf.Set(p+"clientlimits_number", strconv.FormatInt(r.ClientLimit, 10))
		// Green mode is a checkbox with a "cbi.cbe" companion.
		rf.Del(p + "obeyregpower")
		if r.GreenMode {
			rf.Set(p+"obeyregpower", "1")
		}
		if r.HasAggregation {
			rf.Set(p+"aggregation_enable", b01(r.AggregationEnabled))
			rf.Set(p+"aggregation_frame", strconv.FormatInt(r.AggregationFrames, 10))
			rf.Set(p+"aggregation_byte", strconv.FormatInt(r.AggregationBytes, 10))
		}

		f, err := buildWirelessForm(page, radios)
		if err != nil {
			return err
		}
		if r.Channel != "" {
			f.Set(p+"channel", r.Channel)
			f.SetIfPresent("wireless."+dev+".channel", r.Channel)
		}
		ifaces, err := c.wirelessInterfaces(ctx)
		if err != nil {
			return err
		}
		setSSIDCounts(f, ifaces, nil)
		return c.submit(ctx, "admin/network/wireless_device", f)
	})
}
