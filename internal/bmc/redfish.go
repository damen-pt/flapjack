package bmc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Redfish drives a DMTF Redfish BMC. It manages the first ComputerSystem
// and Chassis the service lists, which is right for one-system-per-BMC
// servers; multi-node chassis set SystemPath and ChassisPath explicitly.
type Redfish struct {
	Endpoint string // https://10.1.12.7
	User     string
	Password string
	// HTTP should carry the site CA for BMC certificates; nil uses
	// http.DefaultClient.
	HTTP        *http.Client
	SystemPath  string
	ChassisPath string
	// TaskPoll and TaskTimeout bound waits on asynchronous BMC tasks
	// (firmware updates); defaults are 10s and 2h.
	TaskPoll    time.Duration
	TaskTimeout time.Duration
	// BeforePower, if set, runs before every power action that can boot
	// the node (on, cycle, reset); its error stops the action.
	BeforePower func(ctx context.Context, a PowerAction) error

	mu sync.Mutex
}

type odataRef struct {
	ID string `json:"@odata.id"`
}

type collection struct {
	Members []odataRef `json:"Members"`
}

// maxBody bounds a Redfish response; real resources are a few KiB.
const maxBody = 16 << 20

// request sends one request and returns the response status, headers and
// body. Non-2xx statuses are errors.
func (r *Redfish) request(ctx context.Context, method, p string, body any) (int, http.Header, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(r.Endpoint, "/")+p, rd)
	if err != nil {
		return 0, nil, nil, err
	}
	req.SetBasicAuth(r.User, r.Password)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("OData-Version", "4.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method == http.MethodPatch {
		// Some BMCs require If-Match on PATCH; "*" satisfies them without a
		// GET-for-ETag round trip.
		req.Header.Set("If-Match", "*")
	}
	c := r.HTTP
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return resp.StatusCode, resp.Header, nil, err
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, resp.Header, b, &HTTPError{Method: method, Path: p, Status: resp.Status, Code: resp.StatusCode, Body: string(bytes.TrimSpace(b[:min(len(b), 4096)]))}
	}
	return resp.StatusCode, resp.Header, b, nil
}

// HTTPError is a non-2xx Redfish response.
type HTTPError struct {
	Method, Path, Status, Body string
	Code                       int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("redfish %s %s: %s: %s", e.Method, e.Path, e.Status, e.Body)
}

func (r *Redfish) do(ctx context.Context, method, p string, body, out any) error {
	_, _, b, err := r.request(ctx, method, p, body)
	if err != nil || out == nil || len(bytes.TrimSpace(b)) == 0 {
		return err
	}
	return json.Unmarshal(b, out)
}

// discover finds the system (or, if chassis is set, the chassis) to
// manage. Only successful lookups are cached, so a transient BMC error is
// retried on the next call.
func (r *Redfish) discover(ctx context.Context, chassis bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	first := func(p string) (string, error) {
		var c collection
		if err := r.do(ctx, http.MethodGet, p, nil, &c); err != nil {
			return "", err
		}
		if len(c.Members) == 0 {
			return "", fmt.Errorf("redfish: %s is empty", p)
		}
		return c.Members[0].ID, nil
	}
	var err error
	switch {
	case chassis && r.ChassisPath == "":
		r.ChassisPath, err = first("/redfish/v1/Chassis")
	case !chassis && r.SystemPath == "":
		r.SystemPath, err = first("/redfish/v1/Systems")
	}
	return err
}

type system struct {
	Manufacturer string
	Model        string
	SerialNumber string
	BiosVersion  string
	PowerState   string
	Bios         odataRef
}

func (r *Redfish) system(ctx context.Context) (system, error) {
	var s system
	if err := r.discover(ctx, false); err != nil {
		return s, err
	}
	return s, r.do(ctx, http.MethodGet, r.SystemPath, nil, &s)
}

func (r *Redfish) PowerState(ctx context.Context) (string, error) {
	s, err := r.system(ctx)
	if err != nil {
		return "", err
	}
	return strings.ToLower(s.PowerState), nil
}

var resetTypes = map[PowerAction]string{
	PowerOn:    "On",
	PowerOff:   "ForceOff",
	PowerSoft:  "GracefulShutdown",
	PowerCycle: "PowerCycle",
	PowerReset: "ForceRestart",
}

func (r *Redfish) SetPower(ctx context.Context, a PowerAction) error {
	t, ok := resetTypes[a]
	if !ok {
		return fmt.Errorf("unknown power action %q", a)
	}
	if err := r.discover(ctx, false); err != nil {
		return err
	}
	if err := beforePower(ctx, r.BeforePower, a); err != nil {
		return err
	}
	return r.do(ctx, http.MethodPost, r.SystemPath+"/Actions/ComputerSystem.Reset", map[string]string{"ResetType": t}, nil)
}

var bootTargets = map[BootDevice]string{BootPXE: "Pxe", BootHTTP: "UefiHttp", BootDisk: "Hdd", BootBIOSMenu: "BiosSetup"}

func (r *Redfish) SetBootOnce(ctx context.Context, d BootDevice, uefi bool) error {
	t, ok := bootTargets[d]
	if !ok {
		return fmt.Errorf("unknown boot device %q", d)
	}
	if err := r.discover(ctx, false); err != nil {
		return err
	}
	mode := "Legacy"
	if uefi {
		mode = "UEFI"
	}
	body := map[string]any{"Boot": map[string]string{
		"BootSourceOverrideEnabled": "Once",
		"BootSourceOverrideTarget":  t,
		"BootSourceOverrideMode":    mode,
	}}
	return r.do(ctx, http.MethodPatch, r.SystemPath, body, nil)
}

func (r *Redfish) Inventory(ctx context.Context) (Inventory, error) {
	s, err := r.system(ctx)
	if err != nil {
		return Inventory{}, err
	}
	inv := Inventory{Manufacturer: s.Manufacturer, Model: s.Model, Serial: s.SerialNumber, Firmware: map[string]string{}, FirmwareIDs: map[string]string{}}
	if s.BiosVersion != "" {
		inv.Firmware["BIOS"] = s.BiosVersion
	}
	var fw collection
	if err := r.do(ctx, http.MethodGet, "/redfish/v1/UpdateService/FirmwareInventory", nil, &fw); err == nil {
		for _, m := range fw.Members {
			var item struct{ Id, Name, Version string }
			if err := r.do(ctx, http.MethodGet, m.ID, nil, &item); err != nil {
				return inv, err
			}
			name := item.Name
			if name == "" {
				name = item.Id
			}
			if item.Version != "" {
				inv.Firmware[name] = item.Version
				inv.FirmwareIDs[name] = m.ID
			}
		}
	}
	attrs, err := r.biosAttributes(ctx, s)
	if err != nil {
		return inv, err
	}
	inv.BIOS = map[string]string{}
	for k, v := range attrs {
		inv.BIOS[k] = fmt.Sprint(v)
	}
	return inv, nil
}

func (r *Redfish) biosPath(s system) string {
	if s.Bios.ID != "" {
		return s.Bios.ID
	}
	return r.SystemPath + "/Bios"
}

func (r *Redfish) biosAttributes(ctx context.Context, s system) (map[string]any, error) {
	var bios struct{ Attributes map[string]any }
	if err := r.do(ctx, http.MethodGet, r.biosPath(s), nil, &bios); err != nil {
		return nil, err
	}
	return bios.Attributes, nil
}

// SetBIOS stages attribute changes in the pending settings object. Values
// are converted to the JSON type the BMC currently reports for each
// attribute, because most BMCs reject "1" where they expect 1.
func (r *Redfish) SetBIOS(ctx context.Context, attrs map[string]string) error {
	s, err := r.system(ctx)
	if err != nil {
		return err
	}
	cur, err := r.biosAttributes(ctx, s)
	if err != nil {
		return err
	}
	typed := map[string]any{}
	for k, v := range attrs {
		switch cur[k].(type) {
		case float64:
			n, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return fmt.Errorf("BIOS attribute %s wants a number, got %q", k, v)
			}
			typed[k] = n
		case bool:
			b, err := strconv.ParseBool(v)
			if err != nil {
				return fmt.Errorf("BIOS attribute %s wants a boolean, got %q", k, v)
			}
			typed[k] = b
		default:
			typed[k] = v
		}
	}
	var bios struct {
		Settings struct {
			SettingsObject odataRef
		} `json:"@Redfish.Settings"`
	}
	if err := r.do(ctx, http.MethodGet, r.biosPath(s), nil, &bios); err != nil {
		return err
	}
	target := bios.Settings.SettingsObject.ID
	if target == "" {
		target = r.biosPath(s) + "/Settings"
	}
	return r.do(ctx, http.MethodPatch, target, map[string]any{"Attributes": typed}, nil)
}

// UpdateFirmware starts a SimpleUpdate and waits for the BMC's task to
// finish. Rebooting while a flash is still being written can brick a
// component, so this only returns nil once the BMC reports the task
// Completed without a Critical status. Targets are FirmwareInventory
// @odata.ids (Inventory.FirmwareIDs).
func (r *Redfish) UpdateFirmware(ctx context.Context, imageURI string, targets []string) error {
	body := map[string]any{"ImageURI": imageURI}
	if len(targets) > 0 {
		body["Targets"] = targets
	}
	if u, err := url.Parse(imageURI); err == nil && u.Scheme != "" {
		// Without TransferProtocol some BMCs assume TFTP.
		body["TransferProtocol"] = strings.ToUpper(u.Scheme)
	}
	_, hdr, b, err := r.request(ctx, http.MethodPost, "/redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate", body)
	if err != nil {
		return err
	}
	task := hdr.Get("Location")
	if task == "" {
		var t struct {
			ID string `json:"@odata.id"`
		}
		json.Unmarshal(b, &t)
		task = t.ID
	}
	if task == "" {
		// Synchronous BMC: the update finished before responding.
		return nil
	}
	return r.WaitTask(ctx, task)
}

// TaskState values that end a task.
var taskDone = map[string]bool{"Completed": true, "Exception": true, "Killed": true, "Cancelled": true}

// ErrTaskGone means the BMC forgot a task before reporting its outcome,
// which BMCs do when they reset to activate their own firmware. The
// outcome must then be read from the inventory.
var ErrTaskGone = errors.New("redfish task disappeared before completing")

// WaitTask polls a Task or TaskMonitor URI until it ends. Transient errors
// (the BMC restarting, 5xx) are retried until the context or TaskTimeout
// expires; only a terminal state or a vanished task stops the wait.
func (r *Redfish) WaitTask(ctx context.Context, uri string) error {
	poll := r.TaskPoll
	if poll <= 0 {
		poll = 10 * time.Second
	}
	timeout := r.TaskTimeout
	if timeout <= 0 {
		timeout = 2 * time.Hour
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if u, err := url.Parse(uri); err == nil && u.IsAbs() {
		uri = u.RequestURI() // BMCs sometimes return an absolute Location
	}
	var lastErr error
	for {
		code, _, b, err := r.request(ctx, http.MethodGet, uri, nil)
		var he *HTTPError
		switch {
		case errors.As(err, &he) && (he.Code == http.StatusNotFound || he.Code == http.StatusGone):
			return fmt.Errorf("%s: %w", uri, ErrTaskGone)
		case errors.As(err, &he) && he.Code < 500:
			return err
		case err != nil:
			lastErr = err // BMC busy or restarting: keep polling
		default:
			var t struct {
				TaskState  string
				TaskStatus string
				Messages   []struct{ Message string }
			}
			json.Unmarshal(b, &t)
			if t.TaskState == "" && code != http.StatusAccepted {
				// A TaskMonitor returns the operation's own response, not a
				// Task, once it is done.
				return nil
			}
			if taskDone[t.TaskState] {
				var msgs []string
				for _, m := range t.Messages {
					msgs = append(msgs, m.Message)
				}
				if t.TaskState != "Completed" || t.TaskStatus == "Critical" {
					return fmt.Errorf("redfish task %s ended %s/%s: %s", uri, t.TaskState, t.TaskStatus, strings.Join(msgs, "; "))
				}
				return nil
			}
		}
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("waiting for task %s: %w (last error: %v)", uri, ctx.Err(), lastErr)
			}
			return fmt.Errorf("waiting for task %s: %w", uri, ctx.Err())
		case <-time.After(poll):
		}
	}
}

type chassis struct {
	Controls           odataRef
	EnvironmentMetrics odataRef
	Power              odataRef
}

func (r *Redfish) chassis(ctx context.Context) (chassis, error) {
	var c chassis
	if err := r.discover(ctx, true); err != nil {
		return c, err
	}
	err := r.do(ctx, http.MethodGet, r.ChassisPath, nil, &c)
	var he *HTTPError
	if errors.As(err, &he) && he.Code == http.StatusNotFound {
		// Minimal BMCs list a chassis without serving it; use the classic
		// Chassis/Power path.
		return chassis{}, nil
	}
	return c, err
}

// SetPowerLimit caps chassis power. BMCs implementing the 2020+ power
// model expose a Control of type Power under Chassis/Controls; older ones
// only have the deprecated Chassis/Power PowerControl array.
func (r *Redfish) SetPowerLimit(ctx context.Context, watts int) error {
	c, err := r.chassis(ctx)
	if err != nil {
		return err
	}
	if c.Controls.ID != "" {
		ok, err := r.setPowerControl(ctx, c.Controls.ID, watts)
		if ok || err != nil {
			return err
		}
	}
	p := c.Power.ID
	if p == "" {
		p = r.ChassisPath + "/Power"
	}
	body := map[string]any{"PowerControl": []any{map[string]any{"PowerLimit": map[string]any{"LimitInWatts": watts}}}}
	return r.do(ctx, http.MethodPatch, p, body, nil)
}

// setPowerControl sets the SetPoint of the chassis power Control, enabling
// it if disabled. It reports false if there is no such control.
func (r *Redfish) setPowerControl(ctx context.Context, controls string, watts int) (bool, error) {
	var col collection
	if err := r.do(ctx, http.MethodGet, controls, nil, &col); err != nil {
		return false, err
	}
	for _, m := range col.Members {
		var ctl struct {
			ControlType     string
			ControlMode     string
			PhysicalContext string
		}
		if err := r.do(ctx, http.MethodGet, m.ID, nil, &ctl); err != nil {
			return false, err
		}
		if ctl.ControlType != "Power" || (ctl.PhysicalContext != "" && ctl.PhysicalContext != "Chassis") {
			continue
		}
		body := map[string]any{"SetPoint": watts}
		if ctl.ControlMode == "Disabled" {
			body["ControlMode"] = "Automatic"
		}
		return true, r.do(ctx, http.MethodPatch, m.ID, body, nil)
	}
	return false, nil
}

// PowerReading returns current chassis draw, from EnvironmentMetrics when
// the BMC has it and the classic Power resource otherwise.
func (r *Redfish) PowerReading(ctx context.Context) (float64, error) {
	c, err := r.chassis(ctx)
	if err != nil {
		return 0, err
	}
	if c.EnvironmentMetrics.ID != "" {
		var em struct {
			PowerWatts *struct{ Reading *float64 }
		}
		if err := r.do(ctx, http.MethodGet, c.EnvironmentMetrics.ID, nil, &em); err != nil {
			return 0, err
		}
		if em.PowerWatts != nil && em.PowerWatts.Reading != nil {
			return *em.PowerWatts.Reading, nil
		}
	}
	p := c.Power.ID
	if p == "" {
		p = r.ChassisPath + "/Power"
	}
	var pw struct {
		PowerControl []struct{ PowerConsumedWatts *float64 }
	}
	if err := r.do(ctx, http.MethodGet, p, nil, &pw); err != nil {
		return 0, err
	}
	if len(pw.PowerControl) == 0 || pw.PowerControl[0].PowerConsumedWatts == nil {
		return 0, fmt.Errorf("redfish: %s reports no power reading", r.ChassisPath)
	}
	return *pw.PowerControl[0].PowerConsumedWatts, nil
}

// NewRedfish returns a Redfish client for endpoint ("10.1.12.7" or
// "https://10.1.12.7") that trusts only the certificates in caFile:
// never plain HTTP, and never the system trust store.
func NewRedfish(endpoint, user, password, caFile string) (*Redfish, error) {
	if caFile == "" {
		return nil, errors.New("redfish: a BMC CA is required (the system trust store is never used for BMCs)")
	}
	if strings.HasPrefix(endpoint, "http://") {
		return nil, fmt.Errorf("redfish: %s is plain HTTP; BMCs are only reached over HTTPS", endpoint)
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s: no PEM certificates", caFile)
	}
	// Many BMCs still top out at TLS 1.2.
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	return &Redfish{Endpoint: endpoint, User: user, Password: password,
		HTTP: &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 2 * time.Minute}}, nil
}
