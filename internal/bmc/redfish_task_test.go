package bmc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// taskBMC answers SimpleUpdate with 202 and a task, then serves the task
// through the given sequence of (status, body) replies, repeating the last.
type taskBMC struct {
	mu      sync.Mutex
	replies []taskReply
	polls   int
	update  map[string]any
}

type taskReply struct {
	code int
	body map[string]any
}

func (b *taskBMC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch r.URL.Path {
	case "/redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate":
		json.NewDecoder(r.Body).Decode(&b.update)
		w.Header().Set("Location", "https://"+r.Host+"/redfish/v1/TaskService/Tasks/7")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{"@odata.id": "/redfish/v1/TaskService/Tasks/7", "TaskState": "New"})
	case "/redfish/v1/TaskService/Tasks/7":
		rep := b.replies[min(b.polls, len(b.replies)-1)]
		b.polls++
		w.WriteHeader(rep.code)
		if rep.body != nil {
			json.NewEncoder(w).Encode(rep.body)
		}
	default:
		http.NotFound(w, r)
	}
}

func taskServer(t *testing.T, replies ...taskReply) (*taskBMC, *Redfish) {
	b := &taskBMC{replies: replies}
	srv := httptest.NewTLSServer(b)
	t.Cleanup(srv.Close)
	return b, &Redfish{Endpoint: srv.URL, HTTP: srv.Client(), TaskPoll: time.Millisecond, TaskTimeout: 5 * time.Second}
}

func running(pct int) taskReply {
	return taskReply{200, map[string]any{"TaskState": "Running", "PercentComplete": pct}}
}

func TestUpdateFirmwareWaitsForTask(t *testing.T) {
	b, r := taskServer(t,
		running(10),
		taskReply{503, nil}, // BMC busy: retried
		running(90),
		taskReply{200, map[string]any{"TaskState": "Completed", "TaskStatus": "OK"}},
	)
	if err := r.UpdateFirmware(context.Background(), "http://origin/fw/nic.bin", []string{"/redfish/v1/UpdateService/FirmwareInventory/NIC1"}); err != nil {
		t.Fatal(err)
	}
	if b.polls != 4 {
		t.Fatalf("returned after %d polls, before the task completed", b.polls)
	}
	if b.update["TransferProtocol"] != "HTTP" {
		t.Fatalf("update body = %v", b.update)
	}
}

func TestUpdateFirmwareReportsTaskFailure(t *testing.T) {
	_, r := taskServer(t, running(50), taskReply{200, map[string]any{
		"TaskState": "Exception", "TaskStatus": "Critical", "Messages": []any{map[string]any{"Message": "image signature invalid"}},
	}})
	err := r.UpdateFirmware(context.Background(), "http://origin/fw/bad.bin", nil)
	if err == nil || !strings.Contains(err.Error(), "image signature invalid") {
		t.Fatalf("err = %v", err)
	}
	_, r = taskServer(t, running(50), taskReply{404, nil})
	if err := r.UpdateFirmware(context.Background(), "http://origin/fw/bmc.bin", nil); !errors.Is(err, ErrTaskGone) {
		t.Fatalf("vanished task: %v", err)
	}
	_, r = taskServer(t, taskReply{400, map[string]any{"error": "bad"}})
	if err := r.UpdateFirmware(context.Background(), "http://origin/fw/x.bin", nil); err == nil || errors.Is(err, ErrTaskGone) {
		t.Fatalf("4xx must fail immediately: %v", err)
	}
}

func TestTaskMonitorFinalResponse(t *testing.T) {
	// A TaskMonitor answers 202 while running, then the operation result.
	_, r := taskServer(t, taskReply{202, map[string]any{"TaskState": "Running"}}, taskReply{204, nil})
	if err := r.UpdateFirmware(context.Background(), "http://origin/fw/nic.bin", nil); err != nil {
		t.Fatal(err)
	}
}

func TestTaskTimeout(t *testing.T) {
	_, r := taskServer(t, running(1))
	r.TaskTimeout = 20 * time.Millisecond
	if err := r.UpdateFirmware(context.Background(), "http://origin/fw/nic.bin", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

// modernPower serves the 2020+ power model: Controls and EnvironmentMetrics.
type modernPower struct {
	mu      sync.Mutex
	patched map[string]map[string]any
}

func (m *modernPower) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.Method == http.MethodPatch {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		m.patched[r.URL.Path] = body
		w.WriteHeader(http.StatusNoContent)
		return
	}
	resp := map[string]any{
		"/redfish/v1/Chassis": map[string]any{"Members": []any{map[string]string{"@odata.id": "/redfish/v1/Chassis/C1"}}},
		"/redfish/v1/Chassis/C1": map[string]any{
			"Controls":           map[string]string{"@odata.id": "/redfish/v1/Chassis/C1/Controls"},
			"EnvironmentMetrics": map[string]string{"@odata.id": "/redfish/v1/Chassis/C1/EnvironmentMetrics"},
		},
		"/redfish/v1/Chassis/C1/Controls": map[string]any{"Members": []any{
			map[string]string{"@odata.id": "/redfish/v1/Chassis/C1/Controls/Fan"},
			map[string]string{"@odata.id": "/redfish/v1/Chassis/C1/Controls/PowerLimit"},
		}},
		"/redfish/v1/Chassis/C1/Controls/Fan":        map[string]any{"ControlType": "Percent"},
		"/redfish/v1/Chassis/C1/Controls/PowerLimit": map[string]any{"ControlType": "Power", "ControlMode": "Disabled", "PhysicalContext": "Chassis"},
		"/redfish/v1/Chassis/C1/EnvironmentMetrics":  map[string]any{"PowerWatts": map[string]any{"Reading": 1430.0}},
	}[r.URL.Path]
	if resp == nil {
		http.NotFound(w, r)
		return
	}
	json.NewEncoder(w).Encode(resp)
}

func TestRedfishModernPowerModel(t *testing.T) {
	m := &modernPower{patched: map[string]map[string]any{}}
	srv := httptest.NewTLSServer(m)
	t.Cleanup(srv.Close)
	r := &Redfish{Endpoint: srv.URL, HTTP: srv.Client()}
	if err := r.SetPowerLimit(context.Background(), 9000); err != nil {
		t.Fatal(err)
	}
	got := m.patched["/redfish/v1/Chassis/C1/Controls/PowerLimit"]
	if got["SetPoint"] != 9000.0 || got["ControlMode"] != "Automatic" || len(m.patched) != 1 {
		t.Fatalf("patched = %v", m.patched)
	}
	if w, err := r.PowerReading(context.Background()); err != nil || w != 1430 {
		t.Fatalf("reading = %v %v", w, err)
	}
}

func TestRedfishClassicPowerReading(t *testing.T) {
	_, r := newSim(t)
	if w, err := r.PowerReading(context.Background()); err != nil || w != 812.5 {
		t.Fatalf("reading = %v %v", w, err)
	}
}
