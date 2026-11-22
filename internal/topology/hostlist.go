package topology

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Hostlist compresses host names into Slurm hostlist syntax:
// node01,node02,node03,node05 → node[01-03,05]. Names are grouped by prefix
// and digit width so node9 and node09 never merge into one range.
func Hostlist(names []string) string {
	type group struct {
		prefix string
		width  int
		nums   []int
	}
	groups := map[[2]string]*group{}
	var plain []string
	for _, n := range slices.Compact(slices.Sorted(slices.Values(names))) {
		i := len(n)
		for i > 0 && n[i-1] >= '0' && n[i-1] <= '9' {
			i--
		}
		if i == len(n) {
			plain = append(plain, n)
			continue
		}
		num, _ := strconv.Atoi(n[i:])
		k := [2]string{n[:i], strconv.Itoa(len(n) - i)}
		g := groups[k]
		if g == nil {
			g = &group{prefix: n[:i], width: len(n) - i}
			groups[k] = g
		}
		g.nums = append(g.nums, num)
	}
	var out []string
	for _, g := range groups {
		slices.Sort(g.nums)
		if len(g.nums) == 1 {
			out = append(out, fmt.Sprintf("%s%0*d", g.prefix, g.width, g.nums[0]))
			continue
		}
		var ranges []string
		for i := 0; i < len(g.nums); {
			j := i
			for j+1 < len(g.nums) && g.nums[j+1] == g.nums[j]+1 {
				j++
			}
			if i == j {
				ranges = append(ranges, fmt.Sprintf("%0*d", g.width, g.nums[i]))
			} else {
				ranges = append(ranges, fmt.Sprintf("%0*d-%0*d", g.width, g.nums[i], g.width, g.nums[j]))
			}
			i = j + 1
		}
		out = append(out, g.prefix+"["+strings.Join(ranges, ",")+"]")
	}
	out = append(out, plain...)
	slices.SortFunc(out, func(a, b string) int { return cmp.Compare(a, b) })
	return strings.Join(out, ",")
}
