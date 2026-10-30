package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// MaxSSIDSlot is the number of SSIDs (per radio) the WAX210 supports.
const MaxSSIDSlot = 4

// Security modes accepted by the device.
const (
	SecurityNone      = "none"
	SecurityOWE       = "owe"
	SecurityWPA2PSK   = "psk2"
	SecurityWPA3SAE   = "sae"
	SecurityWPA23PSK  = "sae-mixed"
	SecurityWPA2EAP   = "wpa2"
	SecurityWPA23EAP  = "wpa3-mixed"
	SecurityWPA3EAP   = "wpa3"
	MACFilterDisabled = "disabled"
	MACFilterAllow    = "allow"
	MACFilterDeny     = "deny"
)

// SecurityModes lists every supported security mode.
var SecurityModes = []string{
	SecurityNone, SecurityOWE, SecurityWPA2PSK, SecurityWPA3SAE, SecurityWPA23PSK,
	SecurityWPA2EAP, SecurityWPA23EAP, SecurityWPA3EAP,
}

// IsPersonal reports whether the security mode uses a pre-shared passphrase.
func IsPersonal(sec string) bool {
	return sec == SecurityWPA2PSK || sec == SecurityWPA3SAE || sec == SecurityWPA23PSK
}

// IsEnterprise reports whether the security mode uses RADIUS (802.1X).
func IsEnterprise(sec string) bool {
	return sec == SecurityWPA2EAP || sec == SecurityWPA23EAP || sec == SecurityWPA3EAP
}

// SSID is the combined (2.4 GHz + 5 GHz) configuration of one SSID slot.
// The web UI keeps wifi0_ssid_N and wifi1_ssid_N in sync, except for the
// per-radio enable flag.
type SSID struct {
	Slot            int
	Name            string
	Enabled2G       bool
	Enabled5G       bool
	Security        string
	Passphrase      string
	Hidden          bool
	ClientIsolation bool
	VLANEnabled     bool
	VLANID          int64
	FastRoaming     bool
	// BandSteering steers dual band clients to the 5 GHz radio. It requires
	// the SSID to be enabled on both radios.
	BandSteering       bool
	GroupRekeyInterval int64

	RadiusServer string
	RadiusPort   int64
	RadiusSecret string

	AccountingEnabled  bool
	AccountingServer   string
	AccountingPort     int64
	AccountingSecret   string
	AccountingInterval int64

	// MACFilter is one of MACFilterDisabled, MACFilterAllow, MACFilterDeny.
	MACFilter string
	MACList   []string
}

func validSlot(slot int) error {
	if slot < 1 || slot > MaxSSIDSlot {
		return fmt.Errorf("invalid SSID slot %d: must be between 1 and %d", slot, MaxSSIDSlot)
	}
	return nil
}

type ifaceEntry struct {
	ID json.RawMessage `json:"id"`
}

type ifaceID struct {
	SID    string         `json:"sid"`
	IWData map[string]any `json:"iwdata"`
}

// wirelessInterfaces returns the raw UCI options of every wifi-iface section,
// keyed by section name (e.g. "wifi0_ssid_1"). Must be called with c.mu held.
func (c *Client) wirelessInterfaces(ctx context.Context) (map[string]map[string]string, error) {
	body, err := c.do(ctx, http.MethodGet, "admin/network/iface_status2/99,app,guest,lan,mgmt", nil)
	if err != nil {
		return nil, err
	}
	var entries []json.RawMessage
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		return nil, fmt.Errorf("decoding interface status: %w", err)
	}
	out := map[string]map[string]string{}
	for _, raw := range entries {
		var e ifaceEntry
		if json.Unmarshal(raw, &e) != nil || len(e.ID) == 0 || e.ID[0] != '{' {
			continue
		}
		var id ifaceID
		if json.Unmarshal(e.ID, &id) != nil || id.SID == "" {
			continue
		}
		opts := make(map[string]string, len(id.IWData))
		for k, v := range id.IWData {
			switch t := v.(type) {
			case string:
				opts[k] = t
			case bool:
				opts[k] = strconv.FormatBool(t)
			case float64:
				opts[k] = strconv.FormatFloat(t, 'f', -1, 64)
			case nil:
			default:
				b, _ := json.Marshal(t)
				opts[k] = string(b)
			}
		}
		out[id.SID] = opts
	}
	return out, nil
}

// GetSSID reads the configuration of an SSID slot.
func (c *Client) GetSSID(ctx context.Context, slot int) (*SSID, error) {
	if err := validSlot(slot); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	ifaces, err := c.wirelessInterfaces(ctx)
	if err != nil {
		return nil, err
	}
	w0, ok := ifaces[fmt.Sprintf("wifi0_ssid_%d", slot)]
	if !ok {
		return nil, fmt.Errorf("SSID slot %d (wifi0_ssid_%d) not found on the device", slot, slot)
	}
	w1 := ifaces[fmt.Sprintf("wifi1_ssid_%d", slot)]
	return ssidFromUCI(slot, w0, w1)
}

func ssidFromUCI(slot int, w0, w1 map[string]string) (*SSID, error) {
	s := &SSID{
		Slot:               slot,
		Name:               w0["ssid"],
		Enabled2G:          w0["disabled"] != "1",
		Enabled5G:          w1 != nil && w1["disabled"] != "1",
		Security:           securityFromUCI(w0),
		Hidden:             w0["hidden"] == "1",
		ClientIsolation:    w0["isolate"] == "1",
		VLANEnabled:        w0["isolation"] == "1",
		VLANID:             atoiDefault(w0["vlan_id"], int64(slot)),
		FastRoaming:        w0["fastroamingEnable"] == "1",
		BandSteering:       w0["bandsteer_en"] == "1",
		GroupRekeyInterval: atoiDefault(w0["wpa_group_rekey"], 3600),
		RadiusServer:       w0["auth_server"],
		RadiusPort:         atoiDefault(w0["auth_port"], 1812),
		AccountingEnabled:  w0["acct_enabled"] == "1",
		AccountingServer:   w0["acct_server"],
		AccountingPort:     atoiDefault(w0["acct_port"], 1813),
		AccountingInterval: atoiDefault(w0["acct_interval"], 600),
		MACFilter:          MACFilterDisabled,
	}
	var err error
	if s.Passphrase, err = decryptSecret(w0["key"]); err != nil {
		return nil, fmt.Errorf("SSID slot %d passphrase: %w", slot, err)
	}
	if s.RadiusSecret, err = decryptSecret(w0["auth_secret"]); err != nil {
		return nil, fmt.Errorf("SSID slot %d RADIUS secret: %w", slot, err)
	}
	if s.AccountingSecret, err = decryptSecret(w0["acct_secret"]); err != nil {
		return nil, fmt.Errorf("SSID slot %d accounting secret: %w", slot, err)
	}
	switch w0["macfilter"] {
	case "allow":
		s.MACFilter = MACFilterAllow
		s.MACList = strings.Fields(w0["allowmaclist"])
	case "deny":
		s.MACFilter = MACFilterDeny
		s.MACList = strings.Fields(w0["denymaclist"])
	}
	return s, nil
}

// securityFromUCI derives the web UI security mode. The "security" option
// holds the mode selected in the web UI, "encryption" is what is passed to
// the driver.
func securityFromUCI(o map[string]string) string {
	if sec, ok := o["security"]; ok && sec != "" {
		return strings.TrimSuffix(strings.TrimSuffix(sec, "+ccmp"), "+tkip")
	}
	enc := o["encryption"]
	switch {
	case enc == "" || enc == "none":
		return SecurityNone
	case strings.HasPrefix(enc, "psk2"):
		if o["sae"] == "1" {
			return SecurityWPA23PSK
		}
		return SecurityWPA2PSK
	case strings.HasPrefix(enc, "wpa2"):
		return SecurityWPA2EAP
	case enc == "ccmp" && o["owe"] == "1":
		return SecurityOWE
	case enc == "ccmp":
		return SecurityWPA3SAE
	}
	return strings.TrimSuffix(enc, "+ccmp")
}

// encryptionFormValue is what the web UI posts as the "encryption" field:
// the selected mode with the cipher appended, for modes that have a cipher.
func encryptionFormValue(sec string) string {
	switch sec {
	case SecurityNone, SecurityOWE, SecurityWPA3EAP:
		return sec
	}
	return sec + "+ccmp"
}

func ssidPopupPath(slot int) string {
	q := url.Values{}
	q.Set("wifi0_select_opmode", "ap")
	q.Set("wifi1_select_opmode", "ap")
	q.Set("displayMode", "ap")
	q.Set("checkbox2G", "0")
	q.Set("checkbox5G", "0")
	q.Set("guestEn", "0")
	q.Set("netId", fmt.Sprintf("wifi0.network%d", slot))
	q.Set("countryId", "")
	q.Set("select_opmode", "ap")
	q.Set("select_hwmode", "11axg")
	q.Set("tmpOpmode", "ap")
	q.Set("ssid_name", "")
	return "admin/network/wifi_Encryption_P2P?" + q.Encode()
}

func b01(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// buildSSIDForm turns the server rendered "edit SSID" popup into the form
// the browser would submit after its JavaScript has run, with the desired
// settings applied.
func buildSSIDForm(popup string, s *SSID) (*Form, error) {
	f := ParseForm(popup, "guestNetworkEncryption")
	p := fmt.Sprintf("cbid.wireless.wifi0_ssid_%d.", s.Slot)
	if _, ok := f.Get(p + "ssid"); !ok {
		return nil, fmt.Errorf("unexpected response from the device: SSID form for slot %d not found: %s", s.Slot, truncate(popup, 300))
	}

	f.Set("wifi0_opmode", "")
	f.Set("wifi1_opmode", "")
	f.Set("wifi0Disabled_tmp", b01(!s.Enabled2G))
	f.Set("wifi1Disabled_tmp", b01(!s.Enabled5G))
	f.Set("vlan_isolation_enable", b01(s.VLANEnabled))

	// Checkboxes: the UI renames the "cbi.cbe" hidden companion of an
	// unchecked checkbox to the checkbox name with the inverted value.
	cbe := fmt.Sprintf("cbi.cbe.wireless.wifi0_ssid_%d.disabled", s.Slot)
	f.Del(cbe)
	f.Del(p + "disabled")
	if s.Enabled2G {
		f.Add(cbe, "1")
		f.Add(p+"disabled", "0")
	} else {
		f.Add(p+"disabled", "1")
	}
	w1disabled := fmt.Sprintf("cbid.wireless.wifi1_ssid_%d.disabled", s.Slot)
	f.Del(w1disabled)
	if s.Enabled5G {
		f.Add(w1disabled, "0")
	}
	pb := fmt.Sprintf("cbi.cbe.wireless.wifi0_ssid_%d.preferbssid_enable", s.Slot)
	if _, ok := f.Get(p + "preferbssid_enable"); !ok {
		f.Del(pb)
		f.Set(p+"preferbssid_enable", "0")
	}

	f.Set(p+"ssid", s.Name)
	f.Set(p+"hidden", b01(s.Hidden))
	f.Set(p+"isolate", b01(s.ClientIsolation))
	f.Set(p+"isolation", b01(s.VLANEnabled))
	f.Del(p + "vlan_id")
	if s.VLANEnabled {
		f.Set(p+"vlan_id", strconv.FormatInt(s.VLANID, 10))
	}
	f.Set(p+"fastroamingEnable", b01(s.FastRoaming))

	// Band steering. The steering mode select and its thresholds of the web
	// UI are not stored by the device, only the enable flag is.
	f.Set(p+"bandsteer_en", b01(s.BandSteering))
	f.Del(p + "bandsteerrssi")
	f.Del(p + "bandsteerpersent")

	// Security
	f.Del(p + "cipher")
	f.Set(p+"encryption", encryptionFormValue(s.Security))
	if IsPersonal(s.Security) {
		f.Set(p+"key", encryptSecret(s.Passphrase))
	}
	if s.Security != SecurityNone && s.Security != SecurityOWE {
		f.Set(p+"wpa_group_rekey", strconv.FormatInt(s.GroupRekeyInterval, 10))
	}
	// The device keeps the RADIUS server and secret of a disabled feature, so
	// they are cleared to not leave secrets behind.
	if IsEnterprise(s.Security) {
		f.Set(p+"auth_server", s.RadiusServer)
		f.Set(p+"auth_port", strconv.FormatInt(s.RadiusPort, 10))
		f.Set(p+"auth_secret", encryptSecret(s.RadiusSecret))
	} else {
		f.Set(p+"auth_server", "")
		f.Set(p+"auth_secret", "")
	}
	f.Set(p+"acct_enabled", b01(s.AccountingEnabled))
	if s.AccountingEnabled {
		f.Set(p+"acct_server", s.AccountingServer)
		f.Set(p+"acct_port", strconv.FormatInt(s.AccountingPort, 10))
		f.Set(p+"acct_secret", encryptSecret(s.AccountingSecret))
		f.Set(p+"acct_interval", strconv.FormatInt(s.AccountingInterval, 10))
	} else {
		f.Set(p+"acct_server", "")
		f.Set(p+"acct_secret", "")
	}

	// MAC filter
	list := strings.Join(s.MACList, " ")
	switch s.MACFilter {
	case MACFilterAllow:
		f.Set(p+"macfilter", "allow")
		f.Set(p+"allowmaclist", list)
	case MACFilterDeny:
		f.Set(p+"macfilter", "deny")
		f.Set(p+"denymaclist", list)
	default:
		f.Set(p+"macfilter", "")
	}

	// The NAS-ID/PORT/IP hidden flags are initialized from their GUI
	// checkboxes on page load.
	for _, n := range []string{"nasid_enable", "nasport_enable", "nasip_enable"} {
		if v, ok := f.Get(p + n); ok && v == "" {
			f.Set(p+n, "0")
		}
	}
	return f, nil
}

// setSSIDCounts adds the number of enabled SSIDs of each radio to a form
// posted to the wireless page, like the web UI does when saving. The device
// only brings up that many SSIDs per radio on apply, so an SSID enabled
// without updating the count is configured but not broadcast. s, if not nil,
// overrides the state of its slot.
func setSSIDCounts(f *Form, ifaces map[string]map[string]string, s *SSID) {
	for i, dev := range []string{"wifi0", "wifi1"} {
		n := 0
		for slot := 1; slot <= MaxSSIDSlot; slot++ {
			enabled := false
			if s != nil && s.Slot == slot {
				enabled = []bool{s.Enabled2G, s.Enabled5G}[i]
			} else if o, ok := ifaces[fmt.Sprintf("%s_ssid_%d", dev, slot)]; ok {
				enabled = o["disabled"] != "1"
			}
			if enabled {
				n++
			}
		}
		f.Set("cbid.wireless."+dev+".ath_count", strconv.Itoa(n))
	}
}

// UpdateSSID writes the configuration of an SSID slot and applies it.
func (c *Client) UpdateSSID(ctx context.Context, s *SSID) error {
	if err := validSlot(s.Slot); err != nil {
		return err
	}
	return c.stageAndApply(ctx, func() error {
		ifaces, err := c.wirelessInterfaces(ctx)
		if err != nil {
			return err
		}
		popup, err := c.do(ctx, http.MethodGet, ssidPopupPath(s.Slot), nil)
		if err != nil {
			return err
		}
		f, err := buildSSIDForm(popup, s)
		if err != nil {
			return err
		}
		setSSIDCounts(f, ifaces, s)
		return c.submit(ctx, "admin/network/wireless_device", f)
	})
}

// DisableSSID turns off an SSID slot on both radios, keeping its settings.
func (c *Client) DisableSSID(ctx context.Context, slot int) error {
	s, err := c.GetSSID(ctx, slot)
	if err != nil {
		return err
	}
	if !s.Enabled2G && !s.Enabled5G {
		return nil
	}
	s.Enabled2G, s.Enabled5G = false, false
	return c.UpdateSSID(ctx, s)
}
