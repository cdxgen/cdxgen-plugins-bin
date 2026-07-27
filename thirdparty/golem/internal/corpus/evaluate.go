package corpus

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// Outcome is the result of evaluating one annotation against one report.
type Outcome struct {
	Annotation Annotation
	Satisfied  bool
	Matches    int
	Detail     string
	// Engine names the taint engine that produced the report, so an
	// expectation scoped to one engine is judged against that engine only.
	Engine string
}

// KnownFail returns the defect number this outcome's expectation is known to
// fail on, under the engine that produced the report.
func (o Outcome) KnownFail() int {
	return o.Annotation.KnownFailFor(o.Engine)
}

// Status classifies an outcome against its known-fail marker, giving the corpus
// a ratchet: a known failure that starts passing is reported as XPASS so it gets
// promoted instead of quietly staying on the exception list.
func (o Outcome) Status() string {
	switch {
	case o.Satisfied && o.KnownFail() != 0:
		return "XPASS"
	case o.Satisfied:
		return "PASS"
	case o.KnownFail() != 0:
		return "XFAIL"
	default:
		return "FAIL"
	}
}

// Evaluation aggregates the outcomes for one fixture in one configuration,
// along with the confusion-matrix counts derived from them.
type Evaluation struct {
	Outcomes []Outcome

	// TruePositives counts want annotations that were satisfied.
	TruePositives int
	// FalseNegatives counts want annotations that were not satisfied.
	FalseNegatives int
	// FalsePositives counts reported flows that no annotation sanctions,
	// plus want-not annotations that were violated.
	FalsePositives int

	// Unexpected holds FAIL and XPASS outcomes: the two states that require a
	// human to either fix the engine or update the corpus.
	Unexpected []Outcome
}

// Precision returns TP/(TP+FP), or 1 when nothing was reported.
func (e Evaluation) Precision() float64 {
	if e.TruePositives+e.FalsePositives == 0 {
		return 1
	}
	return float64(e.TruePositives) / float64(e.TruePositives+e.FalsePositives)
}

// Recall returns TP/(TP+FN), or 1 when nothing was expected.
func (e Evaluation) Recall() float64 {
	if e.TruePositives+e.FalseNegatives == 0 {
		return 1
	}
	return float64(e.TruePositives) / float64(e.TruePositives+e.FalseNegatives)
}

// F1 returns the harmonic mean of precision and recall.
func (e Evaluation) F1() float64 {
	p, r := e.Precision(), e.Recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

// Evaluate checks every annotation that applies to mode against the report.
//
// False positives are counted per reported flow rather than per category pair:
// an unannotated flow is a false positive, and every extra copy of it counts,
// because a tool that reports one true finding alongside two hundred spurious
// ones does not have perfect precision.
func Evaluate(report *model.Report, annotations []Annotation, mode string) Evaluation {
	return EvaluateWithGroundTruth(report, annotations, mode, true)
}

// EvaluateWithGroundTruth is Evaluate with control over whether the annotation
// set is exhaustive.
//
// Corpus fixtures are twenty lines long and annotated completely, so any flow
// they do not sanction is a false positive. A real repository cannot be
// annotated that way: go-test-bench declares nine vulnerable routes and also
// contains a great deal of ordinary code that legitimately moves request data
// around. Counting every unannotated flow there as a false positive produced a
// precision of 0.03 for an engine that was not obviously wrong — the number
// measured the gap in the annotations, not the noise in the output.
//
// With exhaustive=false, recall is still measured (the declared vulnerabilities
// either are found or are not) and violated want-nots still count, but
// unannotated flows are left alone.
func EvaluateWithGroundTruth(report *model.Report, annotations []Annotation, mode string, exhaustive bool) Evaluation {
	var eval Evaluation
	sanctioned := map[string]bool{}
	engine := DefaultEngine
	if report != nil && report.DataFlow != nil && report.DataFlow.Engine != "" {
		engine = report.DataFlow.Engine
	}

	for _, ann := range annotations {
		if !ann.AppliesTo(mode) {
			continue
		}
		outcome := evaluateAnnotation(report, ann)
		outcome.Engine = engine
		eval.Outcomes = append(eval.Outcomes, outcome)

		if ann.Kind == KindFlow && ann.Want {
			sanctioned[flowKey(ann.Source, ann.Sink)] = true
		}
		// A violated want-not is a false positive whether or not a known-fail
		// marker records it. The marker keeps the *build* green while a defect
		// is open; precision measures how noisy the output is, and an
		// acknowledged spurious finding is still a spurious finding. Excluding
		// marked violations here would let an engine buy precision by adding
		// markers, and would silently exempt the promotion gate's precision
		// criterion from exactly the regressions it exists to catch.
		switch {
		case ann.Want && outcome.Satisfied:
			eval.TruePositives++
		case ann.Want:
			eval.FalseNegatives++
		case !ann.Want && !outcome.Satisfied:
			eval.FalsePositives++
		}
		if status := outcome.Status(); status == "FAIL" || status == "XPASS" {
			eval.Unexpected = append(eval.Unexpected, outcome)
		}
	}

	if exhaustive && report != nil && report.DataFlow != nil {
		for _, slice := range report.DataFlow.Slices {
			if !sanctioned[flowKey(slice.SourceCategory, slice.SinkCategory)] {
				eval.FalsePositives++
			}
		}
	}
	return eval
}

func flowKey(source, sink string) string {
	return strings.ToLower(source) + "->" + strings.ToLower(sink)
}

func evaluateAnnotation(report *model.Report, ann Annotation) Outcome {
	switch ann.Kind {
	case KindFlow:
		return evaluateFlow(report, ann)
	case KindEdge:
		return evaluateEdge(report, ann)
	case KindReachable:
		return evaluateReachable(report, ann)
	default:
		return Outcome{Annotation: ann, Detail: "unsupported annotation kind " + ann.Kind}
	}
}

func evaluateFlow(report *model.Report, ann Annotation) Outcome {
	if report == nil || report.DataFlow == nil {
		return finish(ann, 0, "report carries no dataFlow section")
	}
	nodes := indexNodes(report.DataFlow.Nodes)
	edges := indexEdges(report.DataFlow.Edges)

	matches := 0
	var rejected []string
	var observed []string
	for _, slice := range report.DataFlow.Slices {
		observed = append(observed, slice.SourceCategory+"->"+slice.SinkCategory)
		if !Matches(ann.Source, slice.SourceCategory) || !Matches(ann.Sink, slice.SinkCategory) {
			continue
		}
		if !Matches(ann.Severity, slice.Severity) {
			continue
		}
		if ann.SinkFn != "" && !Matches(ann.SinkFn, slice.SinkSymbol) && !Matches(ann.SinkFn, slice.SinkFunction) {
			continue
		}
		if ann.SourceFn != "" && !Matches(ann.SourceFn, slice.SourceSymbol) && !Matches(ann.SourceFn, slice.SourceFunction) {
			continue
		}
		if ann.Connected {
			if reason := pathDefect(slice, nodes, edges); reason != "" {
				rejected = append(rejected, fmt.Sprintf("%s: %s", slice.ID, reason))
				continue
			}
		}
		matches++
	}
	detail := fmt.Sprintf("matched %d of %d reported flows %v", matches, len(report.DataFlow.Slices), dedupe(observed))
	if len(rejected) > 0 {
		detail += fmt.Sprintf("; rejected as disconnected: %v", dedupe(rejected))
	}
	return finish(ann, matches, detail)
}

func evaluateEdge(report *model.Report, ann Annotation) Outcome {
	if report == nil || report.CallGraph == nil {
		return finish(ann, 0, "report carries no callGraph section")
	}
	matches := 0
	for _, edge := range report.CallGraph.Edges {
		if !symbolMatches(ann.Source, edge.SourceName, edge.SourceID) {
			continue
		}
		if !symbolMatches(ann.Sink, edge.TargetName, edge.TargetID) {
			continue
		}
		if !Matches(ann.CallType, edge.CallType) {
			continue
		}
		matches++
	}
	return finish(ann, matches, fmt.Sprintf("matched %d of %d call-graph edges", matches, len(report.CallGraph.Edges)))
}

func evaluateReachable(report *model.Report, ann Annotation) Outcome {
	if report == nil || report.CallGraph == nil {
		return finish(ann, 0, "report carries no callGraph section")
	}
	adjacency := map[string][]string{}
	for _, edge := range report.CallGraph.Edges {
		adjacency[edge.SourceID] = append(adjacency[edge.SourceID], edge.TargetID)
	}
	var roots []string
	for _, node := range report.CallGraph.Nodes {
		if ann.Source == "" {
			if strings.HasSuffix(node.ID, ".main") || strings.HasSuffix(node.ID, ".init") {
				roots = append(roots, node.ID)
			}
			continue
		}
		if symbolMatches(ann.Source, node.Label, node.ID) {
			roots = append(roots, node.ID)
		}
	}
	if len(roots) == 0 {
		return finish(ann, 0, fmt.Sprintf("no root matching %q in %d call-graph nodes", ann.Source, len(report.CallGraph.Nodes)))
	}

	depth := map[string]int{}
	queue := make([]string, 0, len(roots))
	for _, root := range roots {
		if _, seen := depth[root]; !seen {
			depth[root] = 0
			queue = append(queue, root)
		}
	}
	best := -1
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, next := range adjacency[current] {
			if _, seen := depth[next]; seen {
				continue
			}
			depth[next] = depth[current] + 1
			queue = append(queue, next)
		}
	}
	for _, node := range report.CallGraph.Nodes {
		if !symbolMatches(ann.Symbol, node.Label, node.ID) {
			continue
		}
		d, ok := depth[node.ID]
		if !ok {
			continue
		}
		if best < 0 || d < best {
			best = d
		}
	}
	if best < 0 {
		return finish(ann, 0, fmt.Sprintf("%q not reachable from %d root(s)", ann.Symbol, len(roots)))
	}
	if ann.MaxDepth > 0 && best > ann.MaxDepth {
		return finish(ann, 0, fmt.Sprintf("%q reachable at depth %d, deeper than maxdepth=%d", ann.Symbol, best, ann.MaxDepth))
	}
	return finish(ann, 1, fmt.Sprintf("%q reachable at depth %d", ann.Symbol, best))
}

func finish(ann Annotation, matches int, detail string) Outcome {
	satisfied := matches == 0
	if ann.Want {
		satisfied = matches >= ann.Required()
	}
	return Outcome{Annotation: ann, Satisfied: satisfied, Matches: matches, Detail: detail}
}

func symbolMatches(expected, name, id string) bool {
	if expected == "" {
		return true
	}
	return Matches(expected, name) || Matches(expected, id)
}

// pathDefect returns a human-readable reason when a slice's node and edge lists
// do not describe a connected path from its source to its sink. This is the
// property that silently breaks when a trace accumulator evicts entries.
func pathDefect(slice model.DataFlowSlice, nodes map[string]model.DataFlowNode, edges map[string]model.DataFlowEdge) string {
	if slice.SourceID == "" || slice.SinkID == "" {
		return "slice is missing a source or sink id"
	}
	listed := map[string]bool{}
	for _, id := range slice.NodeIDs {
		listed[id] = true
		if _, ok := nodes[id]; !ok {
			return "references unknown node " + id
		}
	}
	if !listed[slice.SourceID] {
		return "nodeIds omit the source node"
	}
	if !listed[slice.SinkID] {
		return "nodeIds omit the sink node"
	}
	if slice.SourceID == slice.SinkID {
		return ""
	}
	adjacency := map[string][]string{}
	for _, id := range slice.EdgeIDs {
		edge, ok := edges[id]
		if !ok {
			return "references unknown edge " + id
		}
		adjacency[edge.SourceID] = append(adjacency[edge.SourceID], edge.TargetID)
	}
	if len(adjacency) == 0 {
		return "carries no edges between distinct source and sink"
	}
	seen := map[string]bool{slice.SourceID: true}
	queue := []string{slice.SourceID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current == slice.SinkID {
			return ""
		}
		for _, next := range adjacency[current] {
			if seen[next] {
				continue
			}
			seen[next] = true
			queue = append(queue, next)
		}
	}
	return fmt.Sprintf("edges do not connect source to sink (%d edges, %d nodes reached)", len(slice.EdgeIDs), len(seen))
}

// Connectivity reports the fraction of slices whose node and edge lists form a
// connected source-to-sink path, and the reasons the rest failed.
func Connectivity(df *model.DataFlowEvidence) (float64, []string) {
	if df == nil || len(df.Slices) == 0 {
		return 1, nil
	}
	nodes := indexNodes(df.Nodes)
	edges := indexEdges(df.Edges)
	connected := 0
	reasons := map[string]int{}
	for _, slice := range df.Slices {
		reason := pathDefect(slice, nodes, edges)
		if reason == "" {
			connected++
			continue
		}
		reasons[generalizeReason(reason)]++
	}
	summary := make([]string, 0, len(reasons))
	for reason, count := range reasons {
		summary = append(summary, fmt.Sprintf("%s (%d)", reason, count))
	}
	sort.Strings(summary)
	return float64(connected) / float64(len(df.Slices)), summary
}

// ConnectedSlices maps slice IDs to whether their node and edge lists form a
// connected source-to-sink path.
func ConnectedSlices(df *model.DataFlowEvidence) map[string]bool {
	out := map[string]bool{}
	if df == nil {
		return out
	}
	nodes := indexNodes(df.Nodes)
	edges := indexEdges(df.Edges)
	for _, slice := range df.Slices {
		out[slice.ID] = pathDefect(slice, nodes, edges) == ""
	}
	return out
}

func generalizeReason(reason string) string {
	for _, prefix := range []string{"references unknown node", "references unknown edge", "edges do not connect source to sink"} {
		if strings.HasPrefix(reason, prefix) {
			return prefix
		}
	}
	return reason
}

func indexNodes(in []model.DataFlowNode) map[string]model.DataFlowNode {
	out := make(map[string]model.DataFlowNode, len(in))
	for _, node := range in {
		out[node.ID] = node
	}
	return out
}

func indexEdges(in []model.DataFlowEdge) map[string]model.DataFlowEdge {
	out := make(map[string]model.DataFlowEdge, len(in))
	for _, edge := range in {
		out[edge.ID] = edge
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, value := range in {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
