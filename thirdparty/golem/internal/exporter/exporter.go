package exporter

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

type Format string
type DataFlowGraphFormat string

const (
	FormatJSON      Format              = "json"
	FormatGraphML   Format              = "graphml"
	FormatGEXF      Format              = "gexf"
	DataFlowGraphML DataFlowGraphFormat = "graphml"
	DataFlowGEXF    DataFlowGraphFormat = "gexf"
)

func ParseFormat(value string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "json":
		return FormatJSON, nil
	case "graphml", "graph-ml":
		return FormatGraphML, nil
	case "gexf":
		return FormatGEXF, nil
	default:
		return "", fmt.Errorf("unsupported format %q: expected json, graphml, or gexf", value)
	}
}

func ParseDataFlowGraphFormat(value string) (DataFlowGraphFormat, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "graphml", "graph-ml":
		return DataFlowGraphML, nil
	case "gexf":
		return DataFlowGEXF, nil
	default:
		return "", fmt.Errorf("unsupported data-flow graph format %q: expected graphml or gexf", value)
	}
}

func DataFlowGraph(df *model.DataFlowEvidence, format DataFlowGraphFormat) string {
	switch format {
	case DataFlowGEXF:
		return DataFlowGEXFGraph(df)
	default:
		return DataFlowGraphMLGraph(df)
	}
}

func Write(w io.Writer, report *model.Report, format Format) error {
	switch format {
	case FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		return enc.Encode(report)
	case FormatGraphML:
		_, err := io.WriteString(w, GraphML(report.CallGraph))
		return err
	case FormatGEXF:
		_, err := io.WriteString(w, GEXF(report.CallGraph))
		return err
	default:
		return fmt.Errorf("unsupported export format %q", format)
	}
}

func GraphML(graph *model.CallGraph) string {
	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n")
	keys := []string{"label", "kind", "packagePath", "packageName", "purl", "standard", "local", "external", "signature", "receiver"}
	for _, key := range keys {
		writef(&b, "  <key id=\"%s\" for=\"node\" attr.name=\"%s\" attr.type=\"string\" />\n", xmlEscape(key), xmlEscape(key))
	}
	edgeKeys := []string{"callType", "static", "location", "sourceName", "targetName", "sourcePurl", "sinkPurl", "purls"}
	for _, key := range edgeKeys {
		writef(&b, "  <key id=\"%s\" for=\"edge\" attr.name=\"%s\" attr.type=\"string\" />\n", xmlEscape(key), xmlEscape(key))
	}
	b.WriteString("  <graph id=\"callgraph\" edgedefault=\"directed\">\n")
	if graph != nil {
		nodes := append([]model.CallGraphNode{}, graph.Nodes...)
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
		for _, node := range nodes {
			writef(&b, "    <node id=\"%s\">\n", xmlEscape(node.ID))
			graphMLData(&b, "label", firstNonEmpty(node.Label, node.Name))
			graphMLData(&b, "kind", node.Kind)
			graphMLData(&b, "packagePath", node.PackagePath)
			graphMLData(&b, "packageName", node.PackageName)
			graphMLData(&b, "purl", node.PURL)
			graphMLData(&b, "standard", fmt.Sprint(node.Standard))
			graphMLData(&b, "local", fmt.Sprint(node.Local))
			graphMLData(&b, "external", fmt.Sprint(node.External))
			graphMLData(&b, "signature", node.Signature)
			graphMLData(&b, "receiver", node.Receiver)
			b.WriteString("    </node>\n")
		}
		edges := append([]model.CallGraphEdge{}, graph.Edges...)
		sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
		for _, edge := range edges {
			writef(&b, "    <edge id=\"%s\" source=\"%s\" target=\"%s\">\n", xmlEscape(edge.ID), xmlEscape(edge.SourceID), xmlEscape(edge.TargetID))
			graphMLData(&b, "callType", edge.CallType)
			graphMLData(&b, "static", fmt.Sprint(edge.Static))
			graphMLData(&b, "location", formatLocation(edge.Position))
			graphMLData(&b, "sourceName", edge.SourceName)
			graphMLData(&b, "targetName", edge.TargetName)
			graphMLData(&b, "sourcePurl", edge.SourcePURL)
			graphMLData(&b, "sinkPurl", edge.SinkPURL)
			graphMLData(&b, "purls", strings.Join(edge.PURLs, ","))
			b.WriteString("    </edge>\n")
		}
	}
	b.WriteString("  </graph>\n")
	b.WriteString("</graphml>\n")
	return b.String()
}

func GEXF(graph *model.CallGraph) string {
	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<gexf xmlns=\"http://www.gexf.net/1.3\" version=\"1.3\">\n")
	b.WriteString("  <graph mode=\"static\" defaultedgetype=\"directed\">\n")
	b.WriteString("    <attributes class=\"node\">\n")
	for _, key := range []string{"kind", "packagePath", "packageName", "purl", "standard", "local", "external", "signature", "receiver"} {
		writef(&b, "      <attribute id=\"%s\" title=\"%s\" type=\"string\" />\n", xmlEscape(key), xmlEscape(key))
	}
	b.WriteString("    </attributes>\n")
	b.WriteString("    <attributes class=\"edge\">\n")
	for _, key := range []string{"callType", "static", "location", "sourceName", "targetName", "sourcePurl", "sinkPurl", "purls"} {
		writef(&b, "      <attribute id=\"%s\" title=\"%s\" type=\"string\" />\n", xmlEscape(key), xmlEscape(key))
	}
	b.WriteString("    </attributes>\n")
	b.WriteString("    <nodes>\n")
	if graph != nil {
		nodes := append([]model.CallGraphNode{}, graph.Nodes...)
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
		for _, node := range nodes {
			writef(&b, "      <node id=\"%s\" label=\"%s\">\n", xmlEscape(node.ID), xmlEscape(firstNonEmpty(node.Label, node.Name)))
			b.WriteString("        <attvalues>\n")
			gexfValue(&b, "kind", node.Kind)
			gexfValue(&b, "packagePath", node.PackagePath)
			gexfValue(&b, "packageName", node.PackageName)
			gexfValue(&b, "purl", node.PURL)
			gexfValue(&b, "standard", fmt.Sprint(node.Standard))
			gexfValue(&b, "local", fmt.Sprint(node.Local))
			gexfValue(&b, "external", fmt.Sprint(node.External))
			gexfValue(&b, "signature", node.Signature)
			gexfValue(&b, "receiver", node.Receiver)
			b.WriteString("        </attvalues>\n")
			b.WriteString("      </node>\n")
		}
		b.WriteString("    </nodes>\n")
		b.WriteString("    <edges>\n")
		edges := append([]model.CallGraphEdge{}, graph.Edges...)
		sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
		for _, edge := range edges {
			writef(&b, "      <edge id=\"%s\" source=\"%s\" target=\"%s\">\n", xmlEscape(edge.ID), xmlEscape(edge.SourceID), xmlEscape(edge.TargetID))
			b.WriteString("        <attvalues>\n")
			gexfValue(&b, "callType", edge.CallType)
			gexfValue(&b, "static", fmt.Sprint(edge.Static))
			gexfValue(&b, "location", formatLocation(edge.Position))
			gexfValue(&b, "sourceName", edge.SourceName)
			gexfValue(&b, "targetName", edge.TargetName)
			gexfValue(&b, "sourcePurl", edge.SourcePURL)
			gexfValue(&b, "sinkPurl", edge.SinkPURL)
			gexfValue(&b, "purls", strings.Join(edge.PURLs, ","))
			b.WriteString("        </attvalues>\n")
			b.WriteString("      </edge>\n")
		}
	}
	b.WriteString("    </edges>\n")
	b.WriteString("  </graph>\n")
	b.WriteString("</gexf>\n")
	return b.String()
}

func DataFlowGraphMLGraph(df *model.DataFlowEvidence) string {
	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n")
	for _, key := range []string{"label", "kind", "symbol", "type", "packagePath", "purl", "function", "source", "sink", "category", "taintKinds", "fieldPath", "confidence", "location"} {
		writef(&b, "  <key id=\"%s\" for=\"node\" attr.name=\"%s\" attr.type=\"string\" />\n", xmlEscape(key), xmlEscape(key))
	}
	for _, key := range []string{"kind", "label", "location"} {
		writef(&b, "  <key id=\"edge_%s\" for=\"edge\" attr.name=\"%s\" attr.type=\"string\" />\n", xmlEscape(key), xmlEscape(key))
	}
	b.WriteString("  <graph id=\"dataflows\" edgedefault=\"directed\">\n")
	if df != nil {
		nodes := append([]model.DataFlowNode{}, df.Nodes...)
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
		for _, node := range nodes {
			writef(&b, "    <node id=\"%s\">\n", xmlEscape(node.ID))
			graphMLData(&b, "label", firstNonEmpty(node.Name, node.Symbol, node.ID))
			graphMLData(&b, "kind", node.Kind)
			graphMLData(&b, "symbol", node.Symbol)
			graphMLData(&b, "type", node.Type)
			graphMLData(&b, "packagePath", node.PackagePath)
			graphMLData(&b, "purl", node.PURL)
			graphMLData(&b, "function", node.Function)
			graphMLData(&b, "source", fmt.Sprint(node.Source))
			graphMLData(&b, "sink", fmt.Sprint(node.Sink))
			graphMLData(&b, "category", node.Category)
			graphMLData(&b, "taintKinds", strings.Join(node.TaintKinds, ","))
			graphMLData(&b, "fieldPath", node.FieldPath)
			graphMLData(&b, "confidence", node.Confidence)
			graphMLData(&b, "location", formatLocation(node.Position))
			b.WriteString("    </node>\n")
		}
		edges := append([]model.DataFlowEdge{}, df.Edges...)
		sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
		for _, edge := range edges {
			writef(&b, "    <edge id=\"%s\" source=\"%s\" target=\"%s\">\n", xmlEscape(edge.ID), xmlEscape(edge.SourceID), xmlEscape(edge.TargetID))
			graphMLData(&b, "edge_kind", edge.Kind)
			graphMLData(&b, "edge_label", edge.Label)
			graphMLData(&b, "edge_location", formatLocation(edge.Position))
			b.WriteString("    </edge>\n")
		}
	}
	b.WriteString("  </graph>\n")
	b.WriteString("</graphml>\n")
	return b.String()
}

func DataFlowGEXFGraph(df *model.DataFlowEvidence) string {
	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<gexf xmlns=\"http://www.gexf.net/1.3\" version=\"1.3\">\n")
	b.WriteString("  <graph mode=\"static\" defaultedgetype=\"directed\">\n")
	b.WriteString("    <attributes class=\"node\">\n")
	for _, key := range []string{"kind", "symbol", "type", "packagePath", "purl", "function", "source", "sink", "category", "taintKinds", "fieldPath", "confidence", "location"} {
		writef(&b, "      <attribute id=\"%s\" title=\"%s\" type=\"string\" />\n", xmlEscape(key), xmlEscape(key))
	}
	b.WriteString("    </attributes>\n")
	b.WriteString("    <attributes class=\"edge\">\n")
	for _, key := range []string{"kind", "label", "location"} {
		writef(&b, "      <attribute id=\"%s\" title=\"%s\" type=\"string\" />\n", xmlEscape(key), xmlEscape(key))
	}
	b.WriteString("    </attributes>\n")
	b.WriteString("    <nodes>\n")
	if df != nil {
		nodes := append([]model.DataFlowNode{}, df.Nodes...)
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
		for _, node := range nodes {
			writef(&b, "      <node id=\"%s\" label=\"%s\">\n", xmlEscape(node.ID), xmlEscape(firstNonEmpty(node.Name, node.Symbol, node.ID)))
			b.WriteString("        <attvalues>\n")
			gexfValue(&b, "kind", node.Kind)
			gexfValue(&b, "symbol", node.Symbol)
			gexfValue(&b, "type", node.Type)
			gexfValue(&b, "packagePath", node.PackagePath)
			gexfValue(&b, "purl", node.PURL)
			gexfValue(&b, "function", node.Function)
			gexfValue(&b, "source", fmt.Sprint(node.Source))
			gexfValue(&b, "sink", fmt.Sprint(node.Sink))
			gexfValue(&b, "category", node.Category)
			gexfValue(&b, "taintKinds", strings.Join(node.TaintKinds, ","))
			gexfValue(&b, "fieldPath", node.FieldPath)
			gexfValue(&b, "confidence", node.Confidence)
			gexfValue(&b, "location", formatLocation(node.Position))
			b.WriteString("        </attvalues>\n")
			b.WriteString("      </node>\n")
		}
	}
	b.WriteString("    </nodes>\n")
	b.WriteString("    <edges>\n")
	if df != nil {
		edges := append([]model.DataFlowEdge{}, df.Edges...)
		sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
		for _, edge := range edges {
			writef(&b, "      <edge id=\"%s\" source=\"%s\" target=\"%s\">\n", xmlEscape(edge.ID), xmlEscape(edge.SourceID), xmlEscape(edge.TargetID))
			b.WriteString("        <attvalues>\n")
			gexfValue(&b, "kind", edge.Kind)
			gexfValue(&b, "label", edge.Label)
			gexfValue(&b, "location", formatLocation(edge.Position))
			b.WriteString("        </attvalues>\n")
			b.WriteString("      </edge>\n")
		}
	}
	b.WriteString("    </edges>\n")
	b.WriteString("  </graph>\n")
	b.WriteString("</gexf>\n")
	return b.String()
}

func writef(b *bytes.Buffer, format string, args ...any) {
	_, _ = fmt.Fprintf(b, format, args...)
}

func graphMLData(b *bytes.Buffer, key string, value string) {
	writef(b, "      <data key=\"%s\">%s</data>\n", xmlEscape(key), xmlEscape(value))
}

func gexfValue(b *bytes.Buffer, key string, value string) {
	writef(b, "          <attvalue for=\"%s\" value=\"%s\" />\n", xmlEscape(key), xmlEscape(value))
}

func xmlEscape(value string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(value))
	return b.String()
}

func formatLocation(pos model.Position) string {
	if pos.Filename == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d:%d", pos.Filename, pos.Line, pos.Column)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
