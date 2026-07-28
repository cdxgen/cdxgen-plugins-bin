package bench

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/corpus"
	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// Digest is a compact, machine-independent fingerprint of a report, used as the
// golden artifact for real repositories.
//
// A full report for a medium repository runs to tens of megabytes, of which
// almost nothing is a stable assertion: absolute paths, timings, worker counts
// and Go versions all differ per machine. Storing the whole document therefore
// costs a great deal of repository weight while still not being comparable
// across machines. The digest keeps the parts that are both stable and
// meaningful — counts, category distributions, content hashes over sorted
// identifiers, and a bounded sample of fully spelled-out flows — so the
// comparison can be exact rather than a spot check of a handful of integers.
type Digest struct {
	Fixture       string `json:"fixture"`
	Commit        string `json:"commit,omitempty"`
	Config        string `json:"config"`
	SchemaVersion string `json:"schemaVersion"`

	Counts      map[string]int `json:"counts"`
	Diagnostics map[string]int `json:"diagnosticKinds,omitempty"`

	CallGraph *CallGraphDigest `json:"callGraph,omitempty"`
	DataFlow  *DataFlowDigest  `json:"dataFlow,omitempty"`
}

// CallGraphDigest fingerprints the call graph.
type CallGraphDigest struct {
	Algorithm      string         `json:"algorithm"`
	NodeCount      int            `json:"nodeCount"`
	EdgeCount      int            `json:"edgeCount"`
	NodesByKind    map[string]int `json:"nodesByKind"`
	EdgesByType    map[string]int `json:"edgesByCallType"`
	NodeSetHash    string         `json:"nodeSetHash"`
	EdgeSetHash    string         `json:"edgeSetHash"`
	SyntheticNodes int            `json:"syntheticNodes"`
	StdlibNodes    int            `json:"stdlibNodes"`
	ExternalNodes  int            `json:"externalNodes"`
}

// DataFlowDigest fingerprints the taint evidence.
type DataFlowDigest struct {
	Mode                string         `json:"mode"`
	NodeCount           int            `json:"nodeCount"`
	EdgeCount           int            `json:"edgeCount"`
	SliceCount          int            `json:"sliceCount"`
	UniqueFlowCount     int            `json:"uniqueFlowCount"`
	SummaryCount        int            `json:"summaryCount"`
	FlowsByCategoryPair map[string]int `json:"flowsByCategoryPair"`
	FlowsBySeverity     map[string]int `json:"flowsBySeverity"`
	FlowKeySetHash      string         `json:"flowKeySetHash"`
	EdgeConnectivity    float64        `json:"edgeConnectivity"`
	IntegrityViolations int            `json:"integrityViolations"`
	DepCrossingSlices   int            `json:"dependencyCrossingSlices"`
	TruncationReasons   []string       `json:"truncationReasons,omitempty"`
	SampleFlows         []SampleFlow   `json:"sampleFlows,omitempty"`
}

// SampleFlow is one fully described flow, kept so a diff shows what changed and
// not merely that a count moved.
type SampleFlow struct {
	FlowKey    string `json:"flowKey"`
	Source     string `json:"source"`
	Sink       string `json:"sink"`
	SourceAt   string `json:"sourceAt"`
	SinkAt     string `json:"sinkAt"`
	Severity   string `json:"severity,omitempty"`
	PathLength int    `json:"pathLength"`
	Connected  bool   `json:"connected"`
	TaintKinds string `json:"taintKinds,omitempty"`
}

// digestSampleFlows bounds how many flows are spelled out in a digest.
const digestSampleFlows = 25

// BuildDigest derives a digest from a report. root is stripped from positions so
// the result does not depend on where the fixture was checked out.
func BuildDigest(fixture, commit, config, root string, report *model.Report) *Digest {
	digest := &Digest{
		Fixture:       fixture,
		Commit:        commit,
		Config:        config,
		SchemaVersion: report.SchemaVersion,
		Counts: map[string]int{
			"packages":        report.Stats.PackageCount,
			"files":           report.Stats.FileCount,
			"modules":         report.Stats.ModuleCount,
			"imports":         report.Stats.ImportCount,
			"declarations":    report.Stats.DeclarationCount,
			"usages":          report.Stats.UsageCount,
			"apiEndpoints":    report.Stats.APIEndpointCount,
			"securitySignals": report.Stats.SecuritySignalCount,
			"nativeArtifacts": report.Stats.NativeArtifactCount,
			"buildDirectives": report.Stats.BuildDirectiveCount,
		},
	}
	if len(report.Diagnostics) > 0 {
		digest.Diagnostics = map[string]int{}
		for _, diagnostic := range report.Diagnostics {
			digest.Diagnostics[diagnostic.Kind]++
		}
	}

	if cg := report.CallGraph; cg != nil {
		nodeIDs := make([]string, 0, len(cg.Nodes))
		edgeKeys := make([]string, 0, len(cg.Edges))
		callGraph := &CallGraphDigest{Algorithm: cg.Algorithm, NodeCount: len(cg.Nodes), EdgeCount: len(cg.Edges), NodesByKind: map[string]int{}, EdgesByType: map[string]int{}}
		for _, node := range cg.Nodes {
			nodeIDs = append(nodeIDs, node.ID)
			callGraph.NodesByKind[nonEmpty(node.Kind, "unknown")]++
			if node.Synthetic {
				callGraph.SyntheticNodes++
			}
			if node.Standard {
				callGraph.StdlibNodes++
			}
			if node.External {
				callGraph.ExternalNodes++
			}
		}
		for _, edge := range cg.Edges {
			edgeKeys = append(edgeKeys, edge.SourceID+"\x00"+edge.TargetID+"\x00"+edge.CallType)
			callGraph.EdgesByType[nonEmpty(edge.CallType, "unknown")]++
		}
		callGraph.NodeSetHash = hashStrings(nodeIDs)
		callGraph.EdgeSetHash = hashStrings(edgeKeys)
		digest.CallGraph = callGraph
	}

	if df := report.DataFlow; df != nil {
		connectivity, _ := corpus.Connectivity(df)
		connected := corpus.ConnectedSlices(df)
		dataFlow := &DataFlowDigest{
			Mode: df.Mode, NodeCount: len(df.Nodes), EdgeCount: len(df.Edges), SliceCount: len(df.Slices),
			UniqueFlowCount: df.Stats.UniqueFlowCount, SummaryCount: len(df.Summaries),
			FlowsByCategoryPair: map[string]int{}, FlowsBySeverity: map[string]int{},
			EdgeConnectivity: round(connectivity), IntegrityViolations: countIntegrityViolations(report),
			DepCrossingSlices: countDependencyCrossingSlices(report),
			TruncationReasons: append([]string{}, df.Stats.TruncationReasons...),
		}
		nodes := map[string]model.DataFlowNode{}
		for _, node := range df.Nodes {
			nodes[node.ID] = node
		}
		flowKeys := make([]string, 0, len(df.Slices))
		samples := make([]SampleFlow, 0, len(df.Slices))
		for _, slice := range df.Slices {
			dataFlow.FlowsByCategoryPair[slice.SourceCategory+"->"+slice.SinkCategory]++
			dataFlow.FlowsBySeverity[nonEmpty(slice.Severity, "unset")]++
			flowKeys = append(flowKeys, slice.FlowKey)
			samples = append(samples, SampleFlow{
				FlowKey: slice.FlowKey, Source: nonEmpty(slice.SourceSymbol, slice.SourceName), Sink: nonEmpty(slice.SinkSymbol, slice.SinkName),
				SourceAt: relativePosition(root, nodes[slice.SourceID].Position), SinkAt: relativePosition(root, nodes[slice.SinkID].Position),
				Severity: slice.Severity, PathLength: slice.PathLength, Connected: connected[slice.ID],
				TaintKinds: strings.Join(slice.TaintKinds, ","),
			})
		}
		dataFlow.FlowKeySetHash = hashStrings(flowKeys)
		sort.Slice(samples, func(i, j int) bool {
			if samples[i].FlowKey != samples[j].FlowKey {
				return samples[i].FlowKey < samples[j].FlowKey
			}
			return samples[i].SinkAt < samples[j].SinkAt
		})
		if len(samples) > digestSampleFlows {
			samples = samples[:digestSampleFlows]
		}
		dataFlow.SampleFlows = samples
		digest.DataFlow = dataFlow
	}
	return digest
}

// Diff returns the field paths where two digests disagree.
func (d *Digest) Diff(other *Digest) []string {
	current, err := json.Marshal(d)
	if err != nil {
		return []string{"marshal current: " + err.Error()}
	}
	baseline, err := json.Marshal(other)
	if err != nil {
		return []string{"marshal golden: " + err.Error()}
	}
	var currentMap, baselineMap map[string]any
	_ = json.Unmarshal(current, &currentMap)
	_ = json.Unmarshal(baseline, &baselineMap)
	var out []string
	diffMaps("", baselineMap, currentMap, &out)
	sort.Strings(out)
	return out
}

func diffMaps(prefix string, golden, current map[string]any, out *[]string) {
	keys := map[string]bool{}
	for key := range golden {
		keys[key] = true
	}
	for key := range current {
		keys[key] = true
	}
	names := make([]string, 0, len(keys))
	for key := range keys {
		names = append(names, key)
	}
	sort.Strings(names)
	for _, name := range names {
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		goldenValue, inGolden := golden[name]
		currentValue, inCurrent := current[name]
		switch {
		case !inGolden:
			*out = append(*out, fmt.Sprintf("%s: added (%v)", path, format(currentValue)))
		case !inCurrent:
			*out = append(*out, fmt.Sprintf("%s: removed (was %v)", path, format(goldenValue)))
		default:
			goldenNested, goldenIsMap := goldenValue.(map[string]any)
			currentNested, currentIsMap := currentValue.(map[string]any)
			if goldenIsMap && currentIsMap {
				diffMaps(path, goldenNested, currentNested, out)
				continue
			}
			if format(goldenValue) != format(currentValue) {
				*out = append(*out, fmt.Sprintf("%s: %v -> %v", path, format(goldenValue), format(currentValue)))
			}
		}
	}
}

func format(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	text := string(data)
	if len(text) > 200 {
		return text[:200] + "…"
	}
	return text
}

// SaveDigest writes a digest as indented JSON.
func SaveDigest(path string, digest *Digest) error {
	data, err := json.MarshalIndent(digest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// LoadDigest reads a digest.
func LoadDigest(path string) (*Digest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var digest Digest
	if err := json.Unmarshal(data, &digest); err != nil {
		return nil, fmt.Errorf("parsing digest %s: %w", path, err)
	}
	return &digest, nil
}

func relativePosition(root string, position model.Position) string {
	if position.Filename == "" {
		return ""
	}
	name := filepath.ToSlash(position.Filename)
	if root != "" {
		if rel, err := filepath.Rel(root, position.Filename); err == nil && !strings.HasPrefix(rel, "..") {
			name = filepath.ToSlash(rel)
		}
	}
	// Anything still absolute is outside the fixture (module cache or GOROOT);
	// keep the tail so the digest stays machine-independent.
	if filepath.IsAbs(name) {
		parts := strings.Split(name, "/")
		if len(parts) > 3 {
			name = ".../" + strings.Join(parts[len(parts)-3:], "/")
		}
	}
	return fmt.Sprintf("%s:%d", name, position.Line)
}

func hashStrings(values []string) string {
	sorted := append([]string{}, values...)
	sort.Strings(sorted)
	hash := sha256.New()
	for _, value := range sorted {
		hash.Write([]byte(value))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))[:16]
}

func nonEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
