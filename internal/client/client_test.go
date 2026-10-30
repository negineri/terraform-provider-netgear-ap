package client

import (
	"strings"
	"testing"
)

func TestHashPassword(t *testing.T) {
	// printf 'password\n' | shasum -a 512
	const want = "9151440965cf9c5e07f81eee6241c042a7b78e9bb2dd4f928a8f6da5e369cdffdd2b70c70663ee30d02115731d35f1ece5aad9b362aaa9850efa99e3d197212a"
	if got := hashPassword("password"); got != want {
		t.Errorf("hashPassword() = %s, want %s", got, want)
	}
}

func TestSecretRoundTrip(t *testing.T) {
	for _, s := range []string{"", "a", "Passw0rd!", "exactly16bytes!!", strings.Repeat("x", 63)} {
		enc := encryptSecret(s)
		dec, err := decryptSecret(enc)
		if err != nil {
			t.Fatalf("decryptSecret(%q): %v", enc, err)
		}
		if dec != s {
			t.Errorf("round trip of %q = %q", s, dec)
		}
	}
	// Value produced by the web UI (CryptoJS) for "sharedsecret".
	if got, err := decryptSecret("FyvyFJpYIKefmsyf0mUlsQ=="); err != nil || got != "sharedsecret" {
		t.Errorf("decryptSecret(web UI value) = %q, %v", got, err)
	}
	if _, err := decryptSecret("not base64!"); err == nil {
		t.Error("expected an error for invalid input")
	}
}

const testForm = `
<form name="other"><input name="ignored" value="x"></form>
<form method="post" name="cbi">
  <input type="hidden" name="h" value="1">
  <input type="text" name="t" value="text">
  <input type="text" name="d" value="v" disabled>
  <input type="checkbox" name="c1" value="0" checked>
  <input type="checkbox" name="c2" value="0">
  <input type="radio" name="r" value="1">
  <input type="radio" name="r" value="0" checked="checked">
  <input type="button" name="b" value="Save">
  <select name="s1"><option value="a">A</option><option value="b" selected="selected">B</option></select>
  <select name="s2"><option value="first">F</option><option value="second">S</option></select>
  <select name="s3" disabled><option value="x">X</option></select>
  <input name="noval">
</form>`

func TestParseForm(t *testing.T) {
	f := ParseForm(testForm, "cbi")
	want := []Field{
		{"h", "1"}, {"t", "text"}, {"c1", "0"}, {"r", "0"}, {"s1", "b"}, {"s2", "first"}, {"noval", ""},
	}
	if len(f.Fields) != len(want) {
		t.Fatalf("got %v, want %v", f.Fields, want)
	}
	for i := range want {
		if f.Fields[i] != want[i] {
			t.Errorf("field %d = %v, want %v", i, f.Fields[i], want[i])
		}
	}

	all := ParseForm(testForm, "")
	if v, ok := all.Get("ignored"); !ok || v != "x" {
		t.Errorf("ParseForm without name should collect every control, got %v", all.Fields)
	}
}

func TestFormEditing(t *testing.T) {
	f := &Form{}
	f.Add("a", "1")
	f.Add("b", "2")
	f.Add("a", "3")
	f.Set("a", "x")
	f.Set("c", "y")
	if got := f.Encode(); got != "a=x&b=2&a=x&c=y" {
		t.Errorf("Encode() = %s", got)
	}
	f.Del("a")
	if !f.SetIfPresent("b", "z") || f.SetIfPresent("missing", "z") {
		t.Error("SetIfPresent returned a wrong result")
	}
	if got := f.Encode(); got != "b=z&c=y" {
		t.Errorf("Encode() = %s", got)
	}
}

func TestSecurityFromUCI(t *testing.T) {
	tests := []struct {
		opts map[string]string
		want string
	}{
		{map[string]string{"security": "sae-mixed+ccmp", "encryption": "psk2+ccmp"}, SecurityWPA23PSK},
		{map[string]string{"security": "wpa3"}, SecurityWPA3EAP},
		{map[string]string{"security": "owe", "encryption": "ccmp"}, SecurityOWE},
		{map[string]string{"encryption": "psk2+ccmp", "sae": "1"}, SecurityWPA23PSK},
		{map[string]string{"encryption": "psk2+ccmp"}, SecurityWPA2PSK},
		{map[string]string{"encryption": "ccmp", "owe": "1"}, SecurityOWE},
		{map[string]string{"encryption": "none"}, SecurityNone},
	}
	for _, tt := range tests {
		if got := securityFromUCI(tt.opts); got != tt.want {
			t.Errorf("securityFromUCI(%v) = %s, want %s", tt.opts, got, tt.want)
		}
	}
}

const testPopup = `
<form method="post" name="guestNetworkEncryption">
<input type="hidden" id="wifi0Disabled_tmp" name="wifi0Disabled_tmp" />
<input type="hidden" id="wifi1Disabled_tmp" name="wifi1Disabled_tmp" />
<input type="hidden" id="vlan_isolation_enable" name="vlan_isolation_enable" />
<input type="hidden" name="fromEncr" value="wifi0.network2">
<input type="hidden" value="1" name="cbi.cbe.wireless.wifi0_ssid_2.disabled" />
<input class="cbi-input-checkbox" type="checkbox" name="cbid.wireless.wifi0_ssid_2.disabled" value="0" checked="checked" />
<input type="radio" name="cbid.wireless.wifi0_ssid_2.hidden" value="1" />
<input type="radio" name="cbid.wireless.wifi0_ssid_2.hidden" value="0" checked="checked" />
<input type="radio" name="cbid.wireless.wifi0_ssid_2.bandsteer_en" value="1" />
<input type="radio" name="cbid.wireless.wifi0_ssid_2.bandsteer_en" value="0" checked="checked" />
<select name="select.bandsteer"><option value="2">Prefer 5GHz</option></select>
<input name="cbid.wireless.wifi0_ssid_2.bandsteerrssi" type="text" value="-75"/>
<select name="cbid.wireless.wifi0_ssid_2.encryption"><option value="psk2" selected="selected">WPA2</option></select>
<select name="cbid.wireless.wifi0_ssid_2.cipher"><option value="ccmp" selected="selected">AES</option></select>
<input type="text" name="cbid.wireless.wifi0_ssid_2.key" value="FyvyFJpYIKefmsyf0mUlsQ==" />
<input type="text" name="cbid.wireless.wifi0_ssid_2.wpa_group_rekey" value="3600" />
<select name="cbid.wireless.wifi0_ssid_2.macfilter"><option value="">Disabled</option></select>
<input type="hidden" value="1" name="cbi.cbe.wireless.wifi0_ssid_2.preferbssid_enable" />
<input type="checkbox" name="cbid.wireless.wifi0_ssid_2.preferbssid_enable" value="1" />
<input type="text" name="cbid.wireless.wifi0_ssid_2.ssid" value="old" />
<input type="hidden" name="cbid.wireless.wifi0_ssid_2.nasid_enable">
<input type="hidden" id="form_submit" value="0" name="form_submit"/>
<input type="hidden" id="val_csrf" name="val_csrf"/>
</form>`

func TestBuildSSIDForm(t *testing.T) {
	s := &SSID{
		Slot: 2, Name: "new", Enabled2G: false, Enabled5G: true, Security: SecurityWPA3SAE,
		Passphrase: "passphrase", Hidden: true, VLANEnabled: true, VLANID: 20,
		GroupRekeyInterval: 1800, MACFilter: MACFilterAllow, MACList: []string{"aa:bb:cc:dd:ee:ff"},
	}
	f, err := buildSSIDForm(testPopup, s)
	if err != nil {
		t.Fatal(err)
	}
	p := "cbid.wireless.wifi0_ssid_2."
	want := map[string]string{
		"wifi0Disabled_tmp":                   "1",
		"wifi1Disabled_tmp":                   "0",
		"vlan_isolation_enable":               "1",
		"fromEncr":                            "wifi0.network2",
		p + "disabled":                        "1",
		"cbid.wireless.wifi1_ssid_2.disabled": "0",
		p + "hidden":                          "1",
		p + "isolation":                       "1",
		p + "vlan_id":                         "20",
		p + "encryption":                      "sae+ccmp",
		p + "wpa_group_rekey":                 "1800",
		p + "macfilter":                       "allow",
		p + "allowmaclist":                    "aa:bb:cc:dd:ee:ff",
		p + "preferbssid_enable":              "0",
		p + "ssid":                            "new",
		p + "bandsteer_en":                    "0",
		p + "nasid_enable":                    "0",
		p + "auth_server":                     "",
		p + "auth_secret":                     "",
		p + "acct_enabled":                    "0",
		p + "acct_server":                     "",
		p + "acct_secret":                     "",
	}
	for name, v := range want {
		if got, ok := f.Get(name); !ok || got != v {
			t.Errorf("%s = %q (present %v), want %q", name, got, ok, v)
		}
	}
	for _, name := range []string{p + "cipher", "cbi.cbe.wireless.wifi0_ssid_2.disabled", "cbi.cbe.wireless.wifi0_ssid_2.preferbssid_enable", p + "bandsteerrssi"} {
		if _, ok := f.Get(name); ok {
			t.Errorf("%s should not be submitted", name)
		}
	}
	key, _ := f.Get(p + "key")
	if dec, err := decryptSecret(key); err != nil || dec != "passphrase" {
		t.Errorf("key = %q (%v)", dec, err)
	}

	if _, err := buildSSIDForm("<html>error</html>", s); err == nil {
		t.Error("expected an error for an unexpected page")
	}
}

func TestSSIDFromUCI(t *testing.T) {
	w0 := map[string]string{
		"ssid": "net", "disabled": "0", "security": "psk2+ccmp", "key": encryptSecret("secret123"),
		"isolation": "1", "vlan_id": "30", "bandsteer_en": "1", "macfilter": "deny", "denymaclist": "aa:bb:cc:dd:ee:ff 11:22:33:44:55:66",
	}
	w1 := map[string]string{"disabled": "1"}
	s, err := ssidFromUCI(3, w0, w1)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "net" || !s.Enabled2G || s.Enabled5G || s.Security != SecurityWPA2PSK || s.Passphrase != "secret123" ||
		!s.VLANEnabled || s.VLANID != 30 || !s.BandSteering || s.MACFilter != MACFilterDeny || len(s.MACList) != 2 ||
		s.RadiusPort != 1812 || s.GroupRekeyInterval != 3600 {
		t.Errorf("unexpected result: %+v", *s)
	}
}

func TestNewValidation(t *testing.T) {
	for _, ep := range []string{"", "ftp://x", "https://"} {
		if _, err := New(Config{Endpoint: ep}); err == nil {
			t.Errorf("New(%q) should fail", ep)
		}
	}
	c, err := New(Config{Endpoint: "https://192.0.2.1/cgi-bin/luci"})
	if err != nil {
		t.Fatal(err)
	}
	if c.endpoint != "https://192.0.2.1" || c.username != "admin" {
		t.Errorf("unexpected client: %s %s", c.endpoint, c.username)
	}
}

func TestSetSSIDCounts(t *testing.T) {
	ifaces := map[string]map[string]string{
		"wifi0_ssid_1": {"disabled": "0"},
		"wifi1_ssid_1": {"disabled": "0"},
		"wifi0_ssid_2": {"disabled": "1"},
		"wifi1_ssid_2": {"disabled": "0"},
		"wifi0_ssid_3": {"disabled": "1"},
		"wifi1_ssid_3": {"disabled": "1"},
		"wifi0_ssid_4": {"disabled": "0"},
		"wifi1_ssid_4": {"disabled": "0"},
		"wifi0_ssid_5": {"disabled": "0"}, // not shown in the web UI
	}
	tests := []struct {
		name         string
		s            *SSID
		wifi0, wifi1 string
	}{
		{"current state", nil, "2", "3"},
		{"enable slot 3", &SSID{Slot: 3, Enabled2G: true, Enabled5G: true}, "3", "4"},
		{"disable slot 4 on 5 GHz", &SSID{Slot: 4, Enabled2G: true}, "2", "2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Form{}
			setSSIDCounts(f, ifaces, tt.s)
			for name, want := range map[string]string{
				"cbid.wireless.wifi0.ath_count": tt.wifi0,
				"cbid.wireless.wifi1.ath_count": tt.wifi1,
			} {
				if got, _ := f.Get(name); got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
		})
	}
}

func TestServiceRestartFromApplyPage(t *testing.T) {
	page := `<script type="text/javascript">//<![CDATA[
		var apply_xhr = new XHR();
		apply_xhr.get('/cgi-bin/luci/;stok=c8c7f566d3d62e41d61e595a2944ad81/servicectl/restart/wireless,network', null,`
	m := reServiceRestart.FindStringSubmatch(page)
	if m == nil || m[1] != "wireless,network" {
		t.Errorf("restart target = %v, want wireless,network", m)
	}
}
