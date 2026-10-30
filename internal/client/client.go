// Package client implements a client for the LuCI based web management UI of
// NETGEAR WAX210 (AX1800) access points.
//
// The device does not expose a REST API. Everything is done by emulating what
// the browser based UI does: logging in with a SHA-512 hashed password,
// posting CBI forms with a CSRF token and finally applying the staged UCI
// changes.
package client

import (
	"context"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultTimeout      = 60 * time.Second
	defaultApplyTimeout = 180 * time.Second
	userAgent           = "terraform-provider-netgear-ap"
)

var (
	reSysauth = regexp.MustCompile(`sysauth=([0-9a-fA-F]+)`)
	reStok    = regexp.MustCompile(`stok=([0-9a-fA-F]+)`)

	// ErrAuthentication is returned when the device rejects the credentials.
	ErrAuthentication = errors.New("authentication failed")
	errSessionExpired = errors.New("session expired")
)

// Config holds the settings used to create a Client.
type Config struct {
	// Endpoint is the base URL of the device, e.g. https://192.168.0.100
	Endpoint string
	Username string
	Password string
	// Insecure disables TLS certificate verification. The device ships with
	// a self-signed certificate, so this is usually required.
	Insecure bool
	// Timeout of a single HTTP request.
	Timeout time.Duration
	// ApplyTimeout is the maximum time to wait for the device to finish
	// reloading after applying changes.
	ApplyTimeout time.Duration
}

// Client talks to the web UI of the access point.
//
// The device only supports a single concurrent login session and keeps the
// staged (not yet applied) changes globally, so every operation is
// serialized with a mutex.
type Client struct {
	endpoint     string
	username     string
	password     string
	http         *http.Client
	applyTimeout time.Duration

	mu      sync.Mutex
	sysauth string
	stok    string
}

// New creates a new client. It does not log in until the first request.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(cfg.Endpoint, "/"))
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("invalid endpoint %q: scheme must be http or https", cfg.Endpoint)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid endpoint %q: host is missing", cfg.Endpoint)
	}
	if cfg.Username == "" {
		cfg.Username = "admin"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.ApplyTimeout == 0 {
		cfg.ApplyTimeout = defaultApplyTimeout
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: cfg.Insecure} //nolint:gosec // user controlled, device uses a self-signed certificate.
	// The lighttpd of the device misbehaves with HTTP/2.
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}

	return &Client{
		endpoint: u.Scheme + "://" + u.Host,
		username: cfg.Username,
		password: cfg.Password,
		http: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		applyTimeout: cfg.ApplyTimeout,
	}, nil
}

// hashPassword reproduces sha512sum(password + "\n") done by the login page.
func hashPassword(password string) string {
	sum := sha512.Sum512([]byte(password + "\n"))
	return hex.EncodeToString(sum[:])
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", userAgent)
	// The device answers 403 to form posts without these headers.
	req.Header.Set("Origin", c.endpoint)
	req.Header.Set("Referer", c.endpoint+"/cgi-bin/luci/;stok="+c.stok+"/admin/network/wireless_device")
	cookie := "is_login=1"
	if c.sysauth != "" {
		cookie += "; sysauth=" + c.sysauth
	}
	req.Header.Set("Cookie", cookie)
}

// login must be called with c.mu held.
func (c *Client) login(ctx context.Context) error {
	form := url.Values{}
	form.Set("username", c.username)
	form.Set("password", hashPassword(c.password))
	form.Set("agree", "1")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/cgi-bin/luci", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	c.sysauth, c.stok = "", ""
	c.setHeaders(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusFound {
		if strings.Contains(string(body), "try again after") {
			return fmt.Errorf("%w: login is temporarily blocked by the device after too many failures", ErrAuthentication)
		}
		return fmt.Errorf("%w: unexpected status %d", ErrAuthentication, resp.StatusCode)
	}

	for _, sc := range resp.Header.Values("Set-Cookie") {
		if m := reSysauth.FindStringSubmatch(sc); m != nil {
			c.sysauth = m[1]
		}
		if m := reStok.FindStringSubmatch(sc); m != nil {
			c.stok = m[1]
		}
	}
	if c.stok == "" {
		if m := reStok.FindStringSubmatch(resp.Header.Get("Location")); m != nil {
			c.stok = m[1]
		}
	}
	if c.sysauth == "" || c.stok == "" {
		return fmt.Errorf("%w: device did not return a session", ErrAuthentication)
	}
	return nil
}

// isLoginPage reports whether the response is the login form, which is what
// the device returns when the session has expired.
func isLoginPage(body string) bool {
	return strings.Contains(body, `name="formname"`) && strings.Contains(body, "password_plain_text")
}

// do performs a request against an authenticated LuCI path (relative to
// /cgi-bin/luci/;stok=XXX/). It must be called with c.mu held. It logs in
// lazily and retries once when the session has expired.
func (c *Client) do(ctx context.Context, method, path string, form *Form) (string, error) {
	for range 2 {
		if c.stok == "" {
			if err := c.login(ctx); err != nil {
				return "", err
			}
		}
		body, err := c.doOnce(ctx, method, path, form)
		if errors.Is(err, errSessionExpired) {
			c.stok, c.sysauth = "", ""
			continue
		}
		return body, err
	}
	return "", fmt.Errorf("request %s %s: session expired repeatedly", method, path)
}

func (c *Client) doOnce(ctx context.Context, method, path string, form *Form) (string, error) {
	u := c.endpoint + "/cgi-bin/luci/;stok=" + c.stok + "/" + strings.TrimLeft(path, "/")
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return "", err
	}
	c.setHeaders(req)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("request %s %s failed: %w", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response of %s %s: %w", method, path, err)
	}
	s := string(b)

	switch {
	case resp.StatusCode == http.StatusForbidden:
		return "", errSessionExpired
	case resp.StatusCode == http.StatusFound:
		// A redirect to the login page (without stok) means our session is gone.
		if loc := resp.Header.Get("Location"); !strings.Contains(loc, "stok=") {
			return "", errSessionExpired
		}
		return s, nil
	case resp.StatusCode != http.StatusOK:
		return "", fmt.Errorf("request %s %s: unexpected status %d: %s", method, path, resp.StatusCode, truncate(s, 300))
	case isLoginPage(s):
		return "", errSessionExpired
	}
	return s, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// getCSRF fetches a CSRF token and registers it, like the web UI does before
// every form submission. Must be called with c.mu held.
func (c *Client) getCSRF(ctx context.Context) (string, error) {
	body, err := c.do(ctx, http.MethodGet, "admin/system/ajax_getCsrf", nil)
	if err != nil {
		return "", err
	}
	var res struct {
		ValCSRF json.Number `json:"val_csrf"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		return "", fmt.Errorf("decoding CSRF token: %w", err)
	}
	if res.ValCSRF == "" {
		return "", errors.New("device returned an empty CSRF token")
	}
	if _, err := c.do(ctx, http.MethodGet, "admin/system/ajax_setCsrf", nil); err != nil {
		return "", err
	}
	return res.ValCSRF.String(), nil
}

// submit posts a CBI form. The form must contain a "val_csrf" field, which is
// filled in automatically. Must be called with c.mu held.
func (c *Client) submit(ctx context.Context, path string, f *Form) error {
	token, err := c.getCSRF(ctx)
	if err != nil {
		return err
	}
	f.Set("val_csrf", token)
	f.Set("form_submit", "1")
	_, err = c.do(ctx, http.MethodPost, path, f)
	return err
}

// apply commits and applies all staged UCI changes, then waits for the device
// to finish reloading. Must be called with c.mu held.
func (c *Client) apply(ctx context.Context) error {
	token, err := c.getCSRF(ctx)
	if err != nil {
		return err
	}
	q := url.Values{}
	q.Set("redir", "")
	q.Set("apply_form_submit", "1")
	q.Set("apply_val_csrf", token)
	if _, err := c.do(ctx, http.MethodGet, "admin/uci/saveapply?"+q.Encode(), nil); err != nil {
		return fmt.Errorf("applying changes: %w", err)
	}
	return c.waitReload(ctx)
}

func (c *Client) waitReload(ctx context.Context) error {
	deadline := time.Now().Add(c.applyTimeout)
	// Give the device a moment to start reloading.
	if err := sleep(ctx, 2*time.Second); err != nil {
		return err
	}
	for {
		reloading, err := c.isReloading(ctx)
		if err == nil && !reloading {
			n, err := c.pendingChanges(ctx)
			if err == nil && n == 0 {
				return nil
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				return fmt.Errorf("waiting for the device to apply changes: %w", err)
			}
			return errors.New("timed out waiting for the device to apply changes")
		}
		if err := sleep(ctx, 2*time.Second); err != nil {
			return err
		}
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) isReloading(ctx context.Context) (bool, error) {
	body, err := c.do(ctx, http.MethodGet, "admin/system/ajax_get_reload_state", nil)
	if err != nil {
		return false, err
	}
	var res struct {
		IsReloading bool `json:"is_reloading"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		return false, fmt.Errorf("decoding reload state: %w", err)
	}
	return res.IsReloading, nil
}

var reChangeEntry = regexp.MustCompile(`<(ins|del)>`)

// pendingChanges returns the number of staged, not yet applied UCI changes.
func (c *Client) pendingChanges(ctx context.Context) (int, error) {
	body, err := c.do(ctx, http.MethodGet, "admin/uci/changes", nil)
	if err != nil {
		return 0, err
	}
	i := strings.Index(body, "uci-change-list")
	if i < 0 {
		return 0, nil
	}
	end := strings.Index(body[i:], "</div>")
	if end < 0 {
		end = len(body) - i
	}
	return len(reChangeEntry.FindAllStringIndex(body[i:i+end], -1)), nil
}

// revert discards all staged UCI changes. Must be called with c.mu held.
func (c *Client) revert(ctx context.Context) error {
	token, err := c.getCSRF(ctx)
	if err != nil {
		return err
	}
	q := url.Values{}
	q.Set("redir", "")
	q.Set("revert_form_submit", "1")
	q.Set("revert_val_csrf", token)
	_, err = c.do(ctx, http.MethodGet, "admin/uci/revert?"+q.Encode(), nil)
	return err
}

// ensureNoPendingChanges refuses to continue when somebody else (e.g. a user
// in the web UI) has staged changes, because applying would commit them too.
func (c *Client) ensureNoPendingChanges(ctx context.Context) error {
	n, err := c.pendingChanges(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("the device has %d unapplied change(s) staged by another session; apply or revert them in the web UI first", n)
	}
	return nil
}

// stageAndApply runs stage (which posts one or more forms), then applies the
// changes. If staging or applying fails, staged changes are reverted.
func (c *Client) stageAndApply(ctx context.Context, stage func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureNoPendingChanges(ctx); err != nil {
		return err
	}
	if err := stage(); err != nil {
		_ = c.revert(context.WithoutCancel(ctx))
		return err
	}
	if err := c.apply(ctx); err != nil {
		return err
	}
	return nil
}

func atoiDefault(s string, def int64) int64 {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return def
	}
	return v
}
