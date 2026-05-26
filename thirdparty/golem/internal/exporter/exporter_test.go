package exporter

import (
	"strings"
	"testing"

	"github.com/cdxgen/cdxgen-plugins-bin/thirdparty/golem/internal/model"
)

func TestGraphExportsEscapeXML(t *testing.T) {
	graph := &model.CallGraph{Nodes: []model.CallGraphNode{{ID: "a&b", Name: "A<B", Label: "A<B", Kind: "function"}}, Edges: []model.CallGraphEdge{{ID: "e&1", SourceID: "a&b", TargetID: "a&b", CallType: "static", Static: true}}}
	graphml := GraphML(graph)
	if strings.Contains(graphml, "A<B") || !strings.Contains(graphml, "A&lt;B") {
		t.Fatalf("graphml did not escape label: %s", graphml)
	}
	gexf := GEXF(graph)
	if strings.Contains(gexf, "a&b") || !strings.Contains(gexf, "a&amp;b") {
		t.Fatalf("gexf did not escape id: %s", gexf)
	}
}
