package exporter

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

// SARIFSchema is the schema URL emitted in SARIF output.
const SARIFSchema = "https://json.schemastore.org/sarif-2.1.0.json"

// SARIFOptions configures SARIF rendering.
type SARIFOptions struct {
	// BaseURI is stripped from result locations so they are repository-relative,
	// which is what code-scanning consumers expect.
	BaseURI string
	// ToolName and ToolVersion identify the producing tool.
	ToolName    string
	ToolVersion string
}

// WriteSARIF renders a report's data-flow slices as SARIF 2.1.0 results, one
// result per flow, with the flow path attached as a code-flow so a reviewer can
// step through it.
func WriteSARIF(w io.Writer, report *model.Report, options SARIFOptions) error {
	document, err := buildSARIF(report, options)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func buildSARIF(report *model.Report, options SARIFOptions) (map[string]any, error) {
	if report == nil {
		return nil, fmt.Errorf("nil report")
	}
	toolName := options.ToolName
	if toolName == "" {
		toolName = "golem"
	}

	nodes := map[string]model.DataFlowNode{}
	var slices []model.DataFlowSlice
	if report.DataFlow != nil {
		for _, node := range report.DataFlow.Nodes {
			nodes[node.ID] = node
		}
		slices = report.DataFlow.Slices
	}

	rules := map[string]map[string]any{}
	results := make([]map[string]any, 0, len(slices))
	for _, slice := range slices {
		ruleID := slice.RuleID
		if ruleID == "" {
			ruleID = "GOLEM-DATAFLOW-GENERIC"
		}
		if _, ok := rules[ruleID]; !ok {
			rules[ruleID] = map[string]any{
				"id":                   ruleID,
				"name":                 nonEmptyString(slice.RuleName, ruleID),
				"shortDescription":     map[string]any{"text": nonEmptyString(slice.RuleName, ruleID)},
				"defaultConfiguration": map[string]any{"level": sarifLevel(slice.Severity)},
				"properties": map[string]any{
					"security-severity": fmt.Sprintf("%.1f", securitySeverity(slice.RiskScore, slice.Severity)),
					"tags":              []string{"security", "taint", nonEmptyString(slice.SinkCategory, "flow")},
				},
			}
		}
		sinkNode := nodes[slice.SinkID]
		result := map[string]any{
			"ruleId": ruleID,
			"level":  sarifLevel(slice.Severity),
			"message": map[string]any{
				"text": sarifMessage(slice),
			},
			"locations": []map[string]any{sarifLocation(sinkNode.Position, options.BaseURI)},
			"partialFingerprints": map[string]any{
				"golemFlowKey": slice.FlowKey,
			},
			"properties": map[string]any{
				"sourceCategory": slice.SourceCategory,
				"sinkCategory":   slice.SinkCategory,
				"taintKinds":     slice.TaintKinds,
				"confidence":     slice.Confidence,
				"pathLength":     slice.PathLength,
				"riskScore":      slice.RiskScore,
				"purls":          slice.PURLs,
			},
		}
		if flow := sarifCodeFlow(slice, nodes, options.BaseURI); flow != nil {
			result["codeFlows"] = []map[string]any{flow}
		}
		results = append(results, result)
	}

	ruleList := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	sort.Slice(ruleList, func(i, j int) bool {
		return ruleList[i]["id"].(string) < ruleList[j]["id"].(string)
	})
	sort.Slice(results, func(i, j int) bool {
		left := results[i]["partialFingerprints"].(map[string]any)["golemFlowKey"].(string)
		right := results[j]["partialFingerprints"].(map[string]any)["golemFlowKey"].(string)
		if left != right {
			return left < right
		}
		return results[i]["ruleId"].(string) < results[j]["ruleId"].(string)
	})

	return map[string]any{
		"$schema": SARIFSchema,
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{"driver": map[string]any{
				"name":           toolName,
				"version":        nonEmptyString(options.ToolVersion, report.Tool.Version),
				"informationUri": "https://github.com/cdxgen/cdxgen-plugins-bin",
				"rules":          ruleList,
			}},
			"results": results,
		}},
	}, nil
}

func sarifMessage(slice model.DataFlowSlice) string {
	source := nonEmptyString(slice.SourceSymbol, slice.SourceName)
	sink := nonEmptyString(slice.SinkSymbol, slice.SinkName)
	message := fmt.Sprintf("%s flows from %s to %s", nonEmptyString(slice.SourceCategory, "tainted value"), source, sink)
	if len(slice.SanitizerNodeIDs) > 0 {
		message += fmt.Sprintf(" (passes %d sanitizer node(s))", len(slice.SanitizerNodeIDs))
	}
	return message
}

func sarifCodeFlow(slice model.DataFlowSlice, nodes map[string]model.DataFlowNode, baseURI string) map[string]any {
	locations := make([]map[string]any, 0, len(slice.NodeIDs))
	for _, id := range slice.NodeIDs {
		node, ok := nodes[id]
		if !ok {
			continue
		}
		locations = append(locations, map[string]any{
			"location": mergeMaps(sarifLocation(node.Position, baseURI), map[string]any{
				"message": map[string]any{"text": fmt.Sprintf("%s: %s", node.Kind, nonEmptyString(node.Symbol, node.Name))},
			}),
		})
	}
	if len(locations) == 0 {
		return nil
	}
	return map[string]any{"threadFlows": []map[string]any{{"locations": locations}}}
}

func sarifLocation(position model.Position, baseURI string) map[string]any {
	uri := filepath.ToSlash(position.Filename)
	if baseURI != "" {
		if rel, err := filepath.Rel(baseURI, position.Filename); err == nil && !strings.HasPrefix(rel, "..") {
			uri = filepath.ToSlash(rel)
		}
	}
	region := map[string]any{"startLine": maxInt(position.Line, 1)}
	if position.Column > 0 {
		region["startColumn"] = position.Column
	}
	return map[string]any{
		"physicalLocation": map[string]any{
			"artifactLocation": map[string]any{"uri": uri},
			"region":           region,
		},
	}
}

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info", "informational":
		return "note"
	default:
		return "warning"
	}
}

func securitySeverity(riskScore int, severity string) float64 {
	if riskScore > 0 {
		return float64(riskScore) / 10
	}
	switch strings.ToLower(severity) {
	case "critical":
		return 9.5
	case "high":
		return 8
	case "medium":
		return 5.5
	case "low":
		return 3
	default:
		return 5
	}
}

func mergeMaps(base, extra map[string]any) map[string]any {
	for key, value := range extra {
		base[key] = value
	}
	return base
}

func nonEmptyString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
