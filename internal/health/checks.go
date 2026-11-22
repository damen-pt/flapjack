package health

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/damen-pt/flapjack/internal/sys"
)

// PCIeLink checks that GPUs and high-speed NICs trained at full link width.
// Width is the reliable signal: GPUs drop link speed at idle to save power,
// so a speed below maximum is only a warning unless StrictSpeed is set.
type PCIeLink struct {
	Sys         fs.FS // rooted at /sys
	StrictSpeed bool
}

// pcieVendors are the devices whose links matter for HPC performance.
var pcieVendors = map[string]string{"0x10de": "nvidia", "0x15b3": "mellanox", "0x1077": "qlogic", "0x17cb": "cornelis"}

func (PCIeLink) Name() string { return "pcie-link" }

func (c PCIeLink) Run(context.Context) Result {
	const dir = "bus/pci/devices"
	devs, err := fs.ReadDir(c.Sys, dir)
	if err != nil {
		return Result{Status: Fail, Message: err.Error()}
	}
	res := Result{Metrics: map[string]float64{}, Evidence: map[string][]byte{}}
	var problems []string
	var evidence bytes.Buffer
	checked := 0
	for _, d := range devs {
		p := path.Join(dir, d.Name())
		vendor := readTrim(c.Sys, p, "vendor")
		class := readTrim(c.Sys, p, "class")
		if _, ok := pcieVendors[vendor]; !ok || !(strings.HasPrefix(class, "0x03") || strings.HasPrefix(class, "0x02") || strings.HasPrefix(class, "0x0c06")) {
			continue
		}
		curW, maxW := readTrim(c.Sys, p, "current_link_width"), readTrim(c.Sys, p, "max_link_width")
		curS, maxS := readTrim(c.Sys, p, "current_link_speed"), readTrim(c.Sys, p, "max_link_speed")
		if curW == "" || maxW == "" {
			continue
		}
		checked++
		fmt.Fprintf(&evidence, "%s vendor=%s class=%s width=%s/%s speed=%s/%s\n", d.Name(), vendor, class, curW, maxW, curS, maxS)
		if curW != maxW {
			problems = append(problems, fmt.Sprintf("%s width x%s (max x%s)", d.Name(), curW, maxW))
			res.Status = Fail
		}
		if gts(curS) < gts(maxS) {
			problems = append(problems, fmt.Sprintf("%s speed %s (max %s)", d.Name(), curS, maxS))
			if c.StrictSpeed || !strings.HasPrefix(class, "0x03") {
				res.Status = Fail
			} else {
				res.Status = max(res.Status, Warn)
			}
		}
	}
	res.Metrics["devices"] = float64(checked)
	res.Evidence["pcie.txt"] = evidence.Bytes()
	res.Message = strings.Join(problems, "; ")
	if res.Message == "" {
		res.Message = fmt.Sprintf("%d devices at full width", checked)
	}
	return res
}

func gts(s string) float64 {
	f, _ := strconv.ParseFloat(strings.Fields(s + " 0")[0], 64)
	return f
}

// IBPorts checks every RDMA port is ACTIVE at or above MinRateGbps and
// records error counters as metrics.
type IBPorts struct {
	Sys         fs.FS // rooted at /sys
	MinRateGbps float64
	// MaxLinkDowned fails a port whose link_downed counter exceeds it;
	// negative disables the limit.
	MaxLinkDowned float64
}

func (IBPorts) Name() string { return "ib-ports" }

var ibCounters = []string{"symbol_error", "link_downed", "port_rcv_errors", "link_error_recovery"}

func (c IBPorts) Run(context.Context) Result {
	const dir = "class/infiniband"
	hcas, err := fs.ReadDir(c.Sys, dir)
	if err != nil {
		return Result{Status: Fail, Message: "no RDMA devices: " + err.Error()}
	}
	res := Result{Metrics: map[string]float64{}, Evidence: map[string][]byte{}}
	var problems []string
	var evidence bytes.Buffer
	for _, h := range hcas {
		ports, err := fs.ReadDir(c.Sys, path.Join(dir, h.Name(), "ports"))
		if err != nil {
			continue
		}
		for _, p := range ports {
			pp := path.Join(dir, h.Name(), "ports", p.Name())
			id := h.Name() + "/" + p.Name()
			state := readTrim(c.Sys, pp, "state")      // "4: ACTIVE"
			phys := readTrim(c.Sys, pp, "phys_state")  // "5: LinkUp"
			rate := readTrim(c.Sys, pp, "rate")        // "400 Gb/sec (4X NDR)"
			layer := readTrim(c.Sys, pp, "link_layer") // "InfiniBand" | "Ethernet"
			fmt.Fprintf(&evidence, "%s layer=%s state=%q phys=%q rate=%q", id, layer, state, phys, rate)
			gbps := gts(rate)
			res.Metrics[id+".rate_gbps"] = gbps
			if !strings.HasSuffix(state, "ACTIVE") {
				problems = append(problems, fmt.Sprintf("%s state %q", id, state))
				res.Status = Fail
			} else if gbps < c.MinRateGbps {
				problems = append(problems, fmt.Sprintf("%s rate %q below %g Gb/s", id, rate, c.MinRateGbps))
				res.Status = Fail
			}
			for _, name := range ibCounters {
				v, err := strconv.ParseFloat(readTrim(c.Sys, pp, "counters/"+name), 64)
				if err != nil {
					continue
				}
				res.Metrics[id+"."+name] = v
				fmt.Fprintf(&evidence, " %s=%g", name, v)
				if name == "link_downed" && c.MaxLinkDowned >= 0 && v > c.MaxLinkDowned {
					problems = append(problems, fmt.Sprintf("%s link_downed=%g", id, v))
					res.Status = Fail
				}
			}
			evidence.WriteByte('\n')
		}
	}
	res.Evidence["ib.txt"] = evidence.Bytes()
	res.Message = strings.Join(problems, "; ")
	if len(res.Metrics) == 0 {
		return Result{Status: Fail, Message: "no RDMA ports found", Evidence: res.Evidence}
	}
	if res.Message == "" {
		res.Message = "all ports active"
	}
	return res
}

// GPUQueryFields are the nvidia-smi fields GPUs is written against.
var GPUQueryFields = []string{
	"index", "pci.bus_id", "name",
	"ecc.errors.uncorrected.volatile.total",
	"remapped_rows.pending", "remapped_rows.failure",
	"clocks_throttle_reasons.hw_slowdown",
	"temperature.gpu",
}

// GPUs checks GPU count, uncorrectable ECC errors, row-remapping state,
// hardware slowdown and temperature via nvidia-smi.
type GPUs struct {
	Exec     sys.Runner
	Expect   int     // expected GPU count; 0 skips the count check
	MaxTempC float64 // 0 disables
}

func (GPUs) Name() string { return "gpu" }

func (c GPUs) Run(ctx context.Context) Result {
	out, err := c.Exec.Run(ctx, "nvidia-smi", "--query-gpu="+strings.Join(GPUQueryFields, ","), "--format=csv,noheader,nounits")
	res := Result{Metrics: map[string]float64{}, Evidence: map[string][]byte{"nvidia-smi.csv": out}}
	if err != nil {
		res.Status, res.Message = Fail, err.Error()
		return res
	}
	var problems []string
	flag := func(s Status, format string, args ...any) {
		res.Status = max(res.Status, s)
		problems = append(problems, fmt.Sprintf(format, args...))
	}
	count := 0
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ",")
		if len(f) != len(GPUQueryFields) {
			continue
		}
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		count++
		id := "gpu" + f[0]
		if n, ok := num(f[3]); ok {
			res.Metrics[id+".ecc_uncorrected"] = n
			if n > 0 {
				flag(Fail, "%s (%s) %g uncorrectable ECC errors", id, f[1], n)
			}
		}
		if yes(f[5]) {
			flag(Fail, "%s (%s) row remapping failed; RMA", id, f[1])
		} else if yes(f[4]) {
			flag(Warn, "%s (%s) row remap pending; needs GPU reset", id, f[1])
		}
		if f[6] == "Active" {
			flag(Warn, "%s (%s) hardware slowdown active", id, f[1])
		}
		if t, ok := num(f[7]); ok {
			res.Metrics[id+".temp_c"] = t
			if c.MaxTempC > 0 && t > c.MaxTempC {
				flag(Warn, "%s temperature %gC", id, t)
			}
		}
	}
	res.Metrics["count"] = float64(count)
	if c.Expect > 0 && count != c.Expect {
		flag(Fail, "found %d GPUs, expected %d", count, c.Expect)
	}
	res.Message = strings.Join(problems, "; ")
	if res.Message == "" {
		res.Message = fmt.Sprintf("%d GPUs healthy", count)
	}
	return res
}

func num(s string) (float64, bool) {
	f, err := strconv.ParseFloat(s, 64)
	return f, err == nil
}

func yes(s string) bool { return s == "Yes" || s == "1" }

// XIDSeverity classifies NVIDIA Xid codes. Codes not listed are reported
// as metrics but do not change the status; most of them (13, 31, 43, ...)
// are application faults rather than hardware faults.
var XIDSeverity = map[int]Status{
	48:  Fail, // double-bit ECC error
	63:  Warn, // row remap recorded
	64:  Fail, // row remap failure
	74:  Fail, // NVLink error
	79:  Fail, // GPU has fallen off the bus
	92:  Warn, // high single-bit ECC rate
	94:  Warn, // contained ECC error
	95:  Fail, // uncontained ECC error
	119: Fail, // GSP RPC timeout
	120: Fail, // GSP error
}

var xidLine = regexp.MustCompile(`NVRM: Xid \(PCI:([0-9a-fA-F:.]+)\): (\d+),`)

// XIDs scans the kernel log since boot for NVIDIA Xid events.
type XIDs struct {
	Exec sys.Runner
}

func (XIDs) Name() string { return "gpu-xid" }

func (c XIDs) Run(ctx context.Context) Result {
	out, err := c.Exec.Run(ctx, "journalctl", "-k", "-b", "-o", "cat", "--no-pager")
	res := Result{Metrics: map[string]float64{}, Evidence: map[string][]byte{"xid.log": nil}}
	if err != nil {
		res.Status, res.Message = Fail, err.Error()
		return res
	}
	type key struct {
		pci string
		xid int
	}
	counts := map[key]int{}
	var log bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		m := xidLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		log.WriteString(sc.Text() + "\n")
		x, _ := strconv.Atoi(m[2])
		counts[key{m[1], x}]++
	}
	res.Evidence["xid.log"] = log.Bytes()
	keys := make([]key, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].pci != keys[j].pci {
			return keys[i].pci < keys[j].pci
		}
		return keys[i].xid < keys[j].xid
	})
	var problems []string
	for _, k := range keys {
		res.Metrics[fmt.Sprintf("xid%d", k.xid)] += float64(counts[k])
		if s := XIDSeverity[k.xid]; s > Pass {
			res.Status = max(res.Status, s)
			problems = append(problems, fmt.Sprintf("Xid %d on %s (x%d)", k.xid, k.pci, counts[k]))
		}
	}
	res.Message = strings.Join(problems, "; ")
	if res.Message == "" {
		res.Message = "no hardware Xid events"
	}
	return res
}

// Memory checks installed memory against the expected size, catching DIMMs
// that failed or were mapped out at POST.
type Memory struct {
	Proc      fs.FS // rooted at /proc
	ExpectGiB float64
	Tolerance float64 // fraction; default 0.03 for kernel and firmware reservations
}

func (Memory) Name() string { return "memory" }

func (c Memory) Run(context.Context) Result {
	b, err := fs.ReadFile(c.Proc, "meminfo")
	if err != nil {
		return Result{Status: Fail, Message: err.Error()}
	}
	var kb float64
	for line := range strings.SplitSeq(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
			kb, _ = strconv.ParseFloat(f[1], 64)
		}
	}
	gib := kb / (1 << 20)
	tol := c.Tolerance
	if tol == 0 {
		tol = 0.03
	}
	res := Result{Metrics: map[string]float64{"total_gib": gib}, Message: fmt.Sprintf("%.1f GiB", gib)}
	if gib < c.ExpectGiB*(1-tol) {
		res.Status = Fail
		res.Message = fmt.Sprintf("%.1f GiB installed, expected %g GiB", gib, c.ExpectGiB)
	}
	return res
}

// Command runs an arbitrary tool (dcgmi diag, a site script) and passes if
// it exits zero. If Metric is set, its first capture group is parsed from
// the output as a benchmark result under that metric name, for straggler
// detection (for example NCCL bus bandwidth or STREAM triad).
type Command struct {
	CheckName string
	Exec      sys.Runner
	Argv      []string
	Metric    string
	Pattern   *regexp.Regexp
}

func (c Command) Name() string { return c.CheckName }

func (c Command) Run(ctx context.Context) Result {
	out, err := c.Exec.Run(ctx, c.Argv[0], c.Argv[1:]...)
	res := Result{Evidence: map[string][]byte{c.CheckName + ".out": out}}
	if err != nil {
		res.Status, res.Message = Fail, err.Error()
		return res
	}
	if c.Pattern != nil {
		m := c.Pattern.FindSubmatch(out)
		if m == nil || len(m) < 2 {
			res.Status, res.Message = Fail, "benchmark output did not match "+c.Pattern.String()
			return res
		}
		v, err := strconv.ParseFloat(string(m[1]), 64)
		if err != nil {
			res.Status, res.Message = Fail, err.Error()
			return res
		}
		res.Metrics = map[string]float64{c.Metric: v}
		res.Message = fmt.Sprintf("%s=%g", c.Metric, v)
		return res
	}
	res.Message = "ok"
	return res
}

func readTrim(fsys fs.FS, elem ...string) string {
	b, err := fs.ReadFile(fsys, path.Join(elem...))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
