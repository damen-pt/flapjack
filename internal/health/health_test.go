package health

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	v1 "github.com/damen-pt/flapjack/api/v1alpha1"
	"github.com/damen-pt/flapjack/internal/sys"
)

func pciDev(fsys fstest.MapFS, addr, vendor, class, curW, maxW, curS, maxS string) {
	p := "bus/pci/devices/" + addr + "/"
	for k, v := range map[string]string{
		"vendor": vendor, "class": class,
		"current_link_width": curW, "max_link_width": maxW,
		"current_link_speed": curS, "max_link_speed": maxS,
	} {
		fsys[p+k] = &fstest.MapFile{Data: []byte(v + "\n")}
	}
}

func TestPCIeWidthFailsAndIdleGPUSpeedWarns(t *testing.T) {
	fsys := fstest.MapFS{}
	pciDev(fsys, "0000:17:00.0", "0x10de", "0x030200", "16", "16", "2.5 GT/s PCIe", "32.0 GT/s PCIe")
	pciDev(fsys, "0000:3b:00.0", "0x10de", "0x030200", "16", "16", "32.0 GT/s PCIe", "32.0 GT/s PCIe")
	pciDev(fsys, "0000:00:14.0", "0x8086", "0x0c0330", "1", "1", "", "") // ignored: Intel USB
	res := PCIeLink{Sys: fsys}.Run(context.Background())
	if res.Status != Warn {
		t.Fatalf("idle GPU speed should only warn: %v %s", res.Status, res.Message)
	}

	pciDev(fsys, "0000:5e:00.0", "0x15b3", "0x020700", "8", "16", "32.0 GT/s PCIe", "32.0 GT/s PCIe")
	res = PCIeLink{Sys: fsys}.Run(context.Background())
	if res.Status != Fail || !strings.Contains(res.Message, "0000:5e:00.0 width x8") {
		t.Fatalf("degraded NIC width should fail: %v %s", res.Status, res.Message)
	}
	if res.Metrics["devices"] != 3 {
		t.Fatalf("devices = %v", res.Metrics["devices"])
	}
}

func ibPort(fsys fstest.MapFS, hca, port, state, rate string, linkDowned string) {
	p := "class/infiniband/" + hca + "/ports/" + port + "/"
	fsys[p+"state"] = &fstest.MapFile{Data: []byte(state)}
	fsys[p+"phys_state"] = &fstest.MapFile{Data: []byte("5: LinkUp")}
	fsys[p+"rate"] = &fstest.MapFile{Data: []byte(rate)}
	fsys[p+"link_layer"] = &fstest.MapFile{Data: []byte("InfiniBand")}
	fsys[p+"counters/link_downed"] = &fstest.MapFile{Data: []byte(linkDowned)}
}

func TestIBPorts(t *testing.T) {
	fsys := fstest.MapFS{}
	ibPort(fsys, "mlx5_0", "1", "4: ACTIVE", "400 Gb/sec (4X NDR)", "0")
	ibPort(fsys, "mlx5_1", "1", "4: ACTIVE", "200 Gb/sec (4X HDR)", "0")
	res := IBPorts{Sys: fsys, MinRateGbps: 400, MaxLinkDowned: 2}.Run(context.Background())
	if res.Status != Fail || !strings.Contains(res.Message, "mlx5_1/1 rate") {
		t.Fatalf("down-rated port should fail: %v %s", res.Status, res.Message)
	}
	ibPort(fsys, "mlx5_1", "1", "1: DOWN", "10 Gb/sec (4X SDR)", "0")
	res = IBPorts{Sys: fsys, MinRateGbps: 400, MaxLinkDowned: 2}.Run(context.Background())
	if !strings.Contains(res.Message, `mlx5_1/1 state "1: DOWN"`) {
		t.Fatalf("down port: %s", res.Message)
	}
}

func gpuFake(csv string) *sys.Fake {
	return &sys.Fake{Responses: map[string]sys.FakeResponse{
		"nvidia-smi --query-gpu=" + strings.Join(GPUQueryFields, ",") + " --format=csv,noheader,nounits": {Out: []byte(csv)},
	}}
}

func TestGPUs(t *testing.T) {
	healthy := "0, 00000000:17:00.0, NVIDIA H200, 0, No, No, Not Active, 41\n" +
		"1, 00000000:3B:00.0, NVIDIA H200, 0, No, No, Not Active, 43\n"
	if res := (GPUs{Exec: gpuFake(healthy), Expect: 2}).Run(context.Background()); res.Status != Pass {
		t.Fatalf("healthy: %v %s", res.Status, res.Message)
	}
	if res := (GPUs{Exec: gpuFake(healthy), Expect: 8}).Run(context.Background()); res.Status != Fail {
		t.Fatal("missing GPUs should fail")
	}
	pending := "0, 00000000:17:00.0, NVIDIA H200, 0, Yes, No, Not Active, 41\n"
	if res := (GPUs{Exec: gpuFake(pending)}).Run(context.Background()); res.Status != Warn {
		t.Fatalf("pending remap should warn: %v", res.Status)
	}
	ecc := "0, 00000000:17:00.0, NVIDIA H200, 3, No, No, Not Active, [N/A]\n"
	if res := (GPUs{Exec: gpuFake(ecc)}).Run(context.Background()); res.Status != Fail || res.Metrics["gpu0.ecc_uncorrected"] != 3 {
		t.Fatalf("ECC errors should fail: %v %v", res.Status, res.Metrics)
	}
}

func TestXIDs(t *testing.T) {
	log := "random line\n" +
		"NVRM: Xid (PCI:0000:17:00): 13, pid=4242, Graphics Exception\n" +
		"NVRM: Xid (PCI:0000:3b:00): 79, pid=0, GPU has fallen off the bus.\n" +
		"NVRM: Xid (PCI:0000:3b:00): 79, pid=0, GPU has fallen off the bus.\n"
	f := &sys.Fake{Responses: map[string]sys.FakeResponse{"journalctl -k -b -o cat --no-pager": {Out: []byte(log)}}}
	res := XIDs{Exec: f}.Run(context.Background())
	if res.Status != Fail || res.Metrics["xid79"] != 2 || res.Metrics["xid13"] != 1 {
		t.Fatalf("%v %s %v", res.Status, res.Message, res.Metrics)
	}
	if !strings.Contains(res.Message, "Xid 79 on 0000:3b:00 (x2)") || strings.Contains(res.Message, "Xid 13") {
		t.Fatalf("message = %s", res.Message)
	}
}

func TestMemory(t *testing.T) {
	proc := fstest.MapFS{"meminfo": {Data: []byte("MemTotal:       996000000 kB\nMemFree: 1 kB\n")}}
	if res := (Memory{Proc: proc, ExpectGiB: 1024}).Run(context.Background()); res.Status != Fail {
		t.Fatalf("missing DIMMs should fail: %s", res.Message)
	}
	if res := (Memory{Proc: proc, ExpectGiB: 960}).Run(context.Background()); res.Status != Pass {
		t.Fatalf("%s", res.Message)
	}
}

func TestBenchmarkCommand(t *testing.T) {
	f := &sys.Fake{Responses: map[string]sys.FakeResponse{
		"all_reduce_perf -b 8G -e 8G": {Out: []byte("# Avg bus bandwidth    : 361.42 \n")},
	}}
	c := Command{CheckName: "nccl", Exec: f, Argv: []string{"all_reduce_perf", "-b", "8G", "-e", "8G"},
		Metric: "busbw", Pattern: regexp.MustCompile(`Avg bus bandwidth\s*:\s*([0-9.]+)`)}
	res := c.Run(context.Background())
	if res.Status != Pass || res.Metrics["busbw"] != 361.42 {
		t.Fatalf("%v %v", res.Status, res.Metrics)
	}
}

type slowCheck struct{}

func (slowCheck) Name() string { return "slow" }
func (slowCheck) Run(ctx context.Context) Result {
	<-ctx.Done()
	time.Sleep(10 * time.Millisecond)
	return Result{Status: Pass}
}

type panicCheck struct{}

func (panicCheck) Name() string               { return "panics" }
func (panicCheck) Run(context.Context) Result { panic("boom") }

func TestRunnerTimeoutsAndPanicsFail(t *testing.T) {
	rep := Runner{Checks: []Check{slowCheck{}, panicCheck{}}, Timeout: 20 * time.Millisecond}.Run(context.Background(), "n1")
	if rep.Status != Fail {
		t.Fatalf("status = %v", rep.Status)
	}
	for _, r := range rep.Results {
		if r.Status != Fail {
			t.Errorf("%s: %v %s", r.Check, r.Status, r.Message)
		}
	}
}

func report(status map[string]Status) Report {
	var rep Report
	for name, s := range status {
		rep.Results = append(rep.Results, Result{Check: name, Status: s, Message: s.String()})
	}
	return rep
}

func TestGate(t *testing.T) {
	policy := v1.HealthPolicy{Checks: []string{"gpu", "ib-ports", "nccl"}, Critical: []string{"gpu"}, ConsecutiveFailures: 2}
	ok := report(map[string]Status{"gpu": Pass, "ib-ports": Warn, "nccl": Pass})

	if d := Gate(v1.NodeStatus{Phase: v1.PhaseBurnIn}, policy, ok); d.Phase != v1.PhaseReady {
		t.Fatalf("burn-in pass with warnings should be Ready: %+v", d)
	}
	missing := report(map[string]Status{"gpu": Pass, "ib-ports": Pass})
	if d := Gate(v1.NodeStatus{Phase: v1.PhaseBurnIn}, policy, missing); d.Phase != v1.PhaseQuarantined || !strings.Contains(d.Reason, "nccl: did not run") {
		t.Fatalf("check that did not run must fail burn-in: %+v", d)
	}
	gpuFail := report(map[string]Status{"gpu": Fail, "ib-ports": Pass, "nccl": Pass})
	if d := Gate(v1.NodeStatus{Phase: v1.PhaseReady}, policy, gpuFail); d.Phase != v1.PhaseQuarantined {
		t.Fatalf("critical failure should quarantine immediately: %+v", d)
	}
	ncclFail := report(map[string]Status{"gpu": Pass, "ib-ports": Pass, "nccl": Fail})
	d := Gate(v1.NodeStatus{Phase: v1.PhaseReady}, policy, ncclFail)
	if d.Phase != v1.PhaseReady || d.Failures != 1 {
		t.Fatalf("first non-critical failure should only count: %+v", d)
	}
	if d = Gate(v1.NodeStatus{Phase: v1.PhaseReady, Failures: 1}, policy, ncclFail); d.Phase != v1.PhaseQuarantined {
		t.Fatalf("second consecutive failure should quarantine: %+v", d)
	}
	if d = Gate(v1.NodeStatus{Phase: v1.PhaseReady, Failures: 1}, policy, ok); d.Failures != 0 {
		t.Fatalf("pass should reset the counter: %+v", d)
	}
	if d = Gate(v1.NodeStatus{Phase: v1.PhaseQuarantined, Reason: "x"}, policy, ok); d.Phase != v1.PhaseQuarantined {
		t.Fatal("passing must not auto-release a quarantined node")
	}
}

func TestStragglers(t *testing.T) {
	busbw := map[string]float64{"n1": 360, "n2": 362, "n3": 359, "n4": 310, "n5": 361, "n6": 200}
	got := Stragglers(busbw, true, 0.05)
	if len(got) != 2 || got[0].Node != "n6" || got[1].Node != "n4" {
		t.Fatalf("got %+v", got)
	}
	latency := map[string]float64{"n1": 2.0, "n2": 2.1, "n3": 3.5}
	if got := Stragglers(latency, false, 0.2); len(got) != 1 || got[0].Node != "n3" {
		t.Fatalf("lower-is-better: %+v", got)
	}
	if Stragglers(map[string]float64{"a": 1, "b": 100}, true, 0.1) != nil {
		t.Fatal("two samples are not enough to judge")
	}
	if !Regressed([]float64{360, 361, 359}, 320, true, 0.05) || Regressed([]float64{360}, 355, true, 0.05) {
		t.Fatal("Regressed wrong")
	}
}

func TestEvidenceBundle(t *testing.T) {
	rep := Report{Node: "r07n12", Status: Fail, Results: []Result{
		{Check: "gpu", Status: Fail, Evidence: map[string][]byte{"nvidia-smi.csv": []byte("0, ...")}},
	}}
	var buf bytes.Buffer
	if err := WriteEvidence(&buf, rep, map[string][]byte{"bmc-sel.txt": []byte("SEL")}); err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	want := "r07n12/report.json r07n12/checks/gpu/nvidia-smi.csv r07n12/bmc-sel.txt"
	if strings.Join(names, " ") != want {
		t.Fatalf("bundle = %v", names)
	}
}
