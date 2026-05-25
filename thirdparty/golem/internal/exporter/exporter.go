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

const (
	FormatJSON    Format = "json"
	FormatGraphML Format = "graphml"
	FormatGEXF    Format = "gexf"
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

func Write(w io.Writer, report *model.Report, format Format) error {
	switch format {
	case FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
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
		fmt.Fprintf(&b, "  <key id=\"%s\" for=\"node\" attr.name=\"%s\" attr.type=\"string\" />\n", xmlEscape(key), xmlEscape(key))
	}
	edgeKeys := []string{"callType", "static", "location", "sourceName", "targetName"}
	for _, key := range edgeKeys {
		fmt.Fprintf(&b, "  <key id=\"%s\" for=\"edge\" attr.name=\"%s\" attr.type=\"string\" />\n", xmlEscape(key), xmlEscape(key))
	}
	b.WriteString("  <graph id=\"callgraph\" edgedefault=\"directed\">\n")
	if graph != nil {
		nodes := append([]model.CallGraphNode{}, graph.Nodes...)
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
		for _, node := range nodes {
			fmt.Fprintf(&b, "    <node id=\"%s\">\n", xmlEscape(node.ID))
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
			fmt.Fprintf(&b, "    <edge id=\"%s\" source=\"%s\" target=\"%s\">\n", xmlEscape(edge.ID), xmlEscape(edge.SourceID), xmlEscape(edge.TargetID))
			graphMLData(&b, "callType", edge.CallType)
			graphMLData(&b, "static", fmt.Sprint(edge.Static))
			graphMLData(&b, "location", formatLocation(edge.Position))
			graphMLData(&b, "sourceName", edge.SourceName)
			graphMLData(&b, "targetName", edge.TargetName)
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
		fmt.Fprintf(&b, "      <attribute id=\"%s\" title=\"%s\" type=\"string\" />\n", xmlEscape(key), xmlEscape(key))
	}
	b.WriteString("    </attributes>\n")
	b.WriteString("    <attributes class=\"edge\">\n")
	for _, key := range []string{"callType", "static", "location", "sourceName", "targetName"} {
		fmt.Fprintf(&b, "      <attribute id=\"%s\" title=\"%s\" type=\"string\" />\n", xmlEscape(key), xmlEscape(key))
	}
	b.WriteString("    </attributes>\n")
	b.WriteString("    <nodes>\n")
	if graph != nil {
		nodes := append([]model.CallGraphNode{}, graph.Nodes...)
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
		for _, node := range nodes {
			fmt.Fprintf(&b, "      <node id=\"%s\" label=\"%s\">\n", xmlEscape(node.ID), xmlEscape(firstNonEmpty(node.Label, node.Name)))
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
			fmt.Fprintf(&b, "      <edge id=\"%s\" source=\"%s\" target=\"%s\">\n", xmlEscape(edge.ID), xmlEscape(edge.SourceID), xmlEscape(edge.TargetID))
			b.WriteString("        <attvalues>\n")
			gexfValue(&b, "callType", edge.CallType)
			gexfValue(&b, "static", fmt.Sprint(edge.Static))
			gexfValue(&b, "location", formatLocation(edge.Position))
			gexfValue(&b, "sourceName", edge.SourceName)
			gexfValue(&b, "targetName", edge.TargetName)
			b.WriteString("        </attvalues>\n")
			b.WriteString("      </edge>\n")
		}
	}
	b.WriteString("    </edges>\n")
	b.WriteString("  </graph>\n")
	b.WriteString("</gexf>\n")
	return b.String()
}

func graphMLData(b *bytes.Buffer, key string, value string) {
	fmt.Fprintf(b, "      <data key=\"%s\">%s</data>\n", xmlEscape(key), xmlEscape(value))
}

func gexfValue(b *bytes.Buffer, key string, value string) {
	fmt.Fprintf(b, "          <attvalue for=\"%s\" value=\"%s\" />\n", xmlEscape(key), xmlEscape(value))
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
