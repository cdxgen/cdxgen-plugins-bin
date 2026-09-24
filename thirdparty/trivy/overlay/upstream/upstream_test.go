package upstream

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/result"
	corev1 "k8s.io/api/core/v1"
)

func readPatch(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "patches", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestInlinedAnalyzerTypesMatchDetection checks the analyzer types
// 01-analyzer-without-iac.patch spells out against pkg/iac/detection.
func TestInlinedAnalyzerTypesMatchDetection(t *testing.T) {
	upstream := map[string]detection.FileType{
		"AzureARM":              detection.FileTypeAzureARM,
		"CloudFormation":        detection.FileTypeCloudFormation,
		"Dockerfile":            detection.FileTypeDockerfile,
		"Helm":                  detection.FileTypeHelm,
		"Kubernetes":            detection.FileTypeKubernetes,
		"Terraform":             detection.FileTypeTerraform,
		"TerraformPlanJSON":     detection.FileTypeTerraformPlanJSON,
		"TerraformPlanSnapshot": detection.FileTypeTerraformPlanSnapshot,
		"YAML":                  detection.FileTypeYAML,
		"JSON":                  detection.FileTypeJSON,
		"Ansible":               detection.FileTypeAnsible,
	}
	inlined := regexp.MustCompile(`(?m)^\+\tType(\w+)\s+Type = "([^"]*)"$`).
		FindAllStringSubmatch(readPatch(t, "01-analyzer-without-iac.patch"), -1)
	if len(inlined) != len(upstream) {
		t.Fatalf("the patch inlines %d analyzer types, upstream derives %d from detection", len(inlined), len(upstream))
	}
	for _, m := range inlined {
		if want, ok := upstream[m[1]]; !ok || string(want) != m[2] {
			t.Errorf("Type%s is inlined as %q, upstream detection.FileType%s is %q", m[1], m[2], m[1], want)
		}
	}
}

// TestInlinedValuesMatchUpstream checks every other value a patch inlines,
// by rendering the patched line from the upstream value.
func TestInlinedValuesMatchUpstream(t *testing.T) {
	namespaces := rego.BuiltinNamespaces()
	slices.Sort(namespaces)
	for _, c := range []struct {
		patch string
		line  string
	}{
		{"03-flag-without-scanners.patch", fmt.Sprintf("+\t\tDefault:       %d, // trivy-cdxgen: rego.DefaultAllowedRegoErrors", rego.DefaultAllowedRegoErrors)},
		{"03-flag-without-scanners.patch", fmt.Sprintf("+\t\tDefault:    \"%s:%d\", // trivy-cdxgen: policy.BundleRepository:policy.BundleVersion", policy.BundleRepository, policy.BundleVersion)},
		{"03-flag-without-scanners.patch", fmt.Sprintf("+\t\tDefault:    %q, // trivy-cdxgen: result.DefaultIgnoreFile", result.DefaultIgnoreFile)},
		{"03-flag-without-scanners.patch", fmt.Sprintf("+}{%q, %q, %q, %q, %q}", corev1.TaintEffectNoSchedule, corev1.TaintEffectPreferNoSchedule,
			corev1.TaintEffectNoExecute, corev1.TolerationOpEqual, corev1.TolerationOpExists)},
		{"05-scan-without-report-writers.patch", fmt.Sprintf("+\t\tSchemaVersion: %d, // trivy-cdxgen: report.SchemaVersion", report.SchemaVersion)},
		{"02-scan-local-without-registration.patch", fmt.Sprintf("+\treturn lo.ContainsBy([]string{%q, %q, %q}, func(ns string) bool {", "builtin", "defsec", "appshield")},
	} {
		if !strings.Contains(readPatch(t, c.patch), c.line) {
			t.Errorf("%s no longer carries the upstream value:\n%s", c.patch, c.line)
		}
	}
	if want := []string{"appshield", "builtin", "defsec"}; !slices.Equal(namespaces, want) {
		t.Errorf("rego.BuiltinNamespaces() = %v, 02-scan-local-without-registration.patch inlines %v", namespaces, want)
	}

	// 03-flag-without-scanners.patch derives the DB repositories from
	// trivy-db's schema version the same way pkg/db does.
	if got := fmt.Sprintf("%s:%d", "mirror.gcr.io/aquasec/trivy-db", trivydb.SchemaVersion); got != db.DefaultGCRRepository {
		t.Errorf("patched GCR repository %q, upstream %q", got, db.DefaultGCRRepository)
	}
	if got := fmt.Sprintf("%s:%d", "ghcr.io/aquasecurity/trivy-db", trivydb.SchemaVersion); got != db.DefaultGHCRRepository {
		t.Errorf("patched GHCR repository %q, upstream %q", got, db.DefaultGHCRRepository)
	}
}
