// Package native: cgo build-input classification.
//
// The classifier mirrors the flags Go 1.26.11 and 1.27.4 refuse before they
// reach the C compiler or linker (CVE-2026-97033 through CVE-2026-97043), and
// the inputs that remain allowed but carry build-host paths or escape the
// module. It works on names and categories only: a caller that emitted the
// values would put the very paths and tokens under classification into a
// report that travels further than the analyst's terminal.
//
// The checks are small and anchored, matching the way the go command itself
// tokenises and compares flags, rather than one pattern that tries to describe
// every form at once.
package native

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// Risk categories a cgo build input can fall in.
const (
	// CategoryRefused marks inputs the patched toolchain refuses outright.
	CategoryRefused = "refused-by-go1.27.4"
	// CategoryPathEscape marks a path argument that is absolute or climbs
	// with "..", so it names a location outside the package.
	CategoryPathEscape = "path-escape"
	// CategoryModulePath marks a path argument that stays inside the analysed
	// module. Informational: the flag is ordinary, its target is just local.
	CategoryModulePath = "module-path"
	// CategoryDirectiveInSource marks a //go:cgo_* directive found in a file a
	// human wrote. The compiler only accepts them in cgo-generated files, so
	// their presence in source is a signal by itself.
	CategoryDirectiveInSource = "cgo-directive-in-source"
	// CategoryInvalidObject marks a .syso input whose header is not an object
	// file or archive the linker would accept.
	CategoryInvalidObject = "invalid-object"
)

// CgoFlagRisk names one risky input: a flag (or directive, or file) name and
// the categories it falls in.
type CgoFlagRisk struct {
	Name       string
	Categories []string
}

// SplitCgoFields splits a #cgo value the way the go command tokenises it:
// on spaces, with runs inside single or double quotes kept together and a
// backslash escaping a quote or a backslash inside a double-quoted run. An
// unterminated quote ends the token rather than consuming the rest of the
// line, so a malformed directive cannot hide what follows it.
func SplitCgoFields(s string) []string {
	var out []string
	var current strings.Builder
	inSingle, inDouble, haveToken := false, false, false
	flush := func() {
		if haveToken {
			out = append(out, current.String())
			current.Reset()
			haveToken = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			} else {
				current.WriteByte(c)
			}
		case inDouble:
			if c == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
				i++
				current.WriteByte(s[i])
			} else if c == '"' {
				inDouble = false
			} else {
				current.WriteByte(c)
			}
		case c == '\'':
			inSingle = true
			haveToken = true
		case c == '"':
			inDouble = true
			haveToken = true
		case c == ' ' || c == '\t':
			flush()
		default:
			current.WriteByte(c)
			haveToken = true
		}
	}
	flush()
	return out
}

// CgoValuesInput carries what classifyCgoValues needs to resolve a flag's
// path argument: the analysed module's absolute root (empty disables the
// module-path category) and the directory of the file the directive lives in,
// which is what ${SRCDIR} expands to and what a relative path is taken
// against.
type CgoValuesInput struct {
	ModuleRoot string
	SrcDir     string
}

// ClassifyCgoValues classifies the value tokens of one #cgo directive against
// what Go 1.26.11 and 1.27.4 refuse and what still carries host paths.
func ClassifyCgoValues(variable string, values []string, in CgoValuesInput) []CgoFlagRisk {
	if variable == "pkg-config" {
		return classifyPkgConfigValues(values)
	}
	switch variable {
	case "CFLAGS", "CPPFLAGS", "CXXFLAGS", "FFLAGS", "LDFLAGS":
	default:
		return nil
	}
	var risks []CgoFlagRisk
	add := func(name string, categories ...string) {
		if name == "" || len(categories) == 0 {
			return
		}
		risks = append(risks, CgoFlagRisk{Name: name, Categories: categories})
	}
	// pathClass reports the categories for one path-carrying flag: the
	// refused set first (a sysroot that names a regular file, a search
	// directory holding a GCC spec file), then where the path points.
	pathClass := func(name, rawPath string, wantFile, wantSpecDir bool) {
		path := resolveCgoPath(rawPath, in.SrcDir)
		var categories []string
		if wantFile && statIsRegular(path) {
			categories = append(categories, CategoryRefused)
		}
		if wantSpecDir && dirHoldsSpecFile(path) {
			categories = append(categories, CategoryRefused)
		}
		categories = append(categories, pathCategories(rawPath, path, in.ModuleRoot)...)
		add(name, categories...)
	}
	for i := 0; i < len(values); i++ {
		token := values[i]
		next := ""
		if i+1 < len(values) {
			next = values[i+1]
		}
		switch {
		case token == "--sysroot" || strings.HasPrefix(token, "--sysroot="):
			add("--sysroot", CategoryRefused)
		case token == "-target" || strings.HasPrefix(token, "-target="):
			add("-target", CategoryRefused)
		case strings.HasPrefix(token, "-gen-"):
			add(flagName(token), CategoryRefused)
		case strings.HasPrefix(token, "-gnat"):
			add(flagName(token), CategoryRefused)
		case token == "-isysroot" || strings.HasPrefix(token, "-isysroot="):
			// A regular file here is a linker script GNU ld would execute.
			if path, ok := strings.CutPrefix(token, "-isysroot="); ok {
				pathClass("-isysroot", path, true, true)
			} else if next != "" {
				pathClass("-isysroot", next, true, true)
			} else {
				add("-isysroot", CategoryRefused)
			}
		case strings.HasPrefix(token, "-Wl,-syslibroot,") || strings.HasPrefix(token, "-Wl,-syslibroot="):
			sep := len("-Wl,-syslibroot")
			pathClass("-Wl,-syslibroot", token[sep+1:], true, true)
		case strings.HasPrefix(token, "-Wl,-rpath,") || strings.HasPrefix(token, "-Wl,-rpath="):
			pathClass("-Wl,-rpath", token[len("-Wl,-rpath")+1:], false, false)
		case token == "-Wl,-rpath":
			if arg, ok := strings.CutPrefix(next, "-Wl,"); ok {
				pathClass("-Wl,-rpath", arg, false, false)
			} else if next != "" {
				pathClass("-Wl,-rpath", next, false, false)
			}
		case token == "-Wl,--warn-backrefs-exclude":
			add("-Wl,--warn-backrefs-exclude", CategoryRefused)
		case token == "-x":
			// -x hands the following files to another compiler front end;
			// only the languages cgo compiles are ordinary here.
			if !validCompilerLanguage(next) {
				add("-x", CategoryRefused)
			}
		case token == "-I" || strings.HasPrefix(token, "-I=") || joinedPathFlag(token, "-I"):
			if path, ok := strings.CutPrefix(token, "-I"); ok && path != "" {
				pathClass("-I", path, false, false)
			} else if path, ok := strings.CutPrefix(next, "="); ok && token == "-I" {
				pathClass("-I", path, false, false)
			} else if next != "" {
				pathClass("-I", next, false, false)
			}
		case token == "-L" || strings.HasPrefix(token, "-L=") || joinedPathFlag(token, "-L"):
			if path, ok := strings.CutPrefix(token, "-L"); ok && path != "" {
				pathClass("-L", path, false, true)
			} else if next != "" {
				pathClass("-L", next, false, true)
			}
		case isRefusedLoaderFlag(token):
			add(flagName(token), CategoryRefused)
		case isSplitWlPair(token, next):
			add(flagName(token), CategoryRefused)
		}
	}
	return risks
}

// joinedPathFlag reports whether token is a short flag glued to its path
// argument, such as -I/usr/include or -L/opt/lib, as opposed to the bare flag.
func joinedPathFlag(token, flag string) bool {
	return strings.HasPrefix(token, flag) && len(token) > len(flag) && !strings.HasPrefix(token, flag+"-")
}

// isRefusedLoaderFlag reports whether token is one of the macOS and gold/LLD
// loader forms Go refuses: flags whose argument the loader opens and executes.
// The release notes name the family as "-l to_library", -lazy_library,
// -lazy_framework, -load_hidden, -library and -library-path.
func isRefusedLoaderFlag(token string) bool {
	switch {
	case token == "-lto_library", token == "-lazy_library", token == "-lazy_framework", token == "-load_hidden":
		return true
	case token == "-library" || token == "-library-path":
		return true
	case strings.HasPrefix(token, "-library=") || strings.HasPrefix(token, "-library-path="):
		return true
	}
	return false
}

// isSplitWlPair reports whether a two-token -Wl, form is one Go refuses: the
// flag expects its continuation to carry the -Wl, prefix itself, and a bare
// second token smuggles an unchecked argument to the linker. -Wl,-R is the
// one form that may take a plain path, so it is exempt.
func isSplitWlPair(token, next string) bool {
	switch token {
	case "-Wl,-framework", "-Wl,-rpath", "-Wl,--just-symbols", "-Wl,-undefined":
		return next != "" && !strings.HasPrefix(next, "-Wl,")
	}
	return false
}

// validCompilerLanguage reports whether lang is one of the languages cgo
// compiles. Anything else turns -x into a way to hand another compiler
// front end a file it was never meant to see.
func validCompilerLanguage(lang string) bool {
	switch lang {
	case "c", "c-header", "cpp-output", "c++", "c++-header", "c++-cpp-output",
		"objective-c", "objective-c-header", "objective-c-cpp-output",
		"objective-c++", "objective-c++-header", "objective-c++-cpp-output",
		"assembler", "assembler-with-cpp":
		return true
	}
	return false
}

// classifyPkgConfigValues classifies a #cgo pkg-config: value. The refused
// options redirect where pkg-config loads its description files from, which
// turns a package name into a file the analyst's toolchain reads.
func classifyPkgConfigValues(values []string) []CgoFlagRisk {
	var risks []CgoFlagRisk
	add := func(name string, categories ...string) {
		if name != "" {
			risks = append(risks, CgoFlagRisk{Name: name, Categories: categories})
		}
	}
	for _, token := range values {
		switch {
		case strings.HasPrefix(token, "--with-path="):
			add("--with-path", CategoryRefused)
		case strings.HasPrefix(token, "--personality="):
			add("--personality", CategoryRefused)
		case strings.HasPrefix(token, "--define-variable="):
			if !validPkgConfigDefine(token[len("--define-variable="):]) {
				add("--define-variable", CategoryRefused)
			}
		case strings.HasPrefix(token, "--"):
			// Other pkg-config options are out of scope here.
		default:
			// A package name that names a file or a path is a local .pc file
			// and is refused; a plain name is ordinary and never reported.
			if !validPkgConfigName(token) {
				add(".pc-path", CategoryRefused)
			}
		}
	}
	return risks
}

// validPkgConfigDefine mirrors Go's rule for --define-variable=NAME=VALUE:
// a plain identifier, then a value that starts with none of @ - = $ and
// contains none of @ - $.
func validPkgConfigDefine(define string) bool {
	name, value, ok := strings.Cut(define, "=")
	if !ok || name == "" || value == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return !strings.ContainsAny(value[:1], "@-=$") && !strings.ContainsAny(value, "@-$")
}

// validPkgConfigName reports whether a pkg-config package name is a name and
// not a path: no separators, no climb, no .pc suffix, no comparison operators
// glued to a .pc fragment.
func validPkgConfigName(pkg string) bool {
	if pkg == "" {
		return false
	}
	if strings.ContainsAny(pkg, `/\:`) || strings.Contains(pkg, "..") {
		return false
	}
	lower := strings.ToLower(pkg)
	if strings.HasSuffix(lower, ".pc") {
		return false
	}
	for i := 0; i < len(lower); i++ {
		if strings.IndexByte("<>=!", lower[i]) >= 0 && strings.HasSuffix(lower[:i], ".pc") {
			return false
		}
	}
	return true
}

// ClassifyCompilerDirective reads a //go:cgo_* comment line found in a file a
// human wrote. Such directives are only meaningful in the files cgo itself
// generates, so the name alone is the finding; commas, escaped quotes and
// path-like DLL names additionally hit what the patched toolchain refuses.
// The text is the trimmed comment without its leading slashes.
func ClassifyCompilerDirective(text string) (name string, categories []string, ok bool) {
	rest, found := strings.CutPrefix(text, "go:cgo_")
	if !found {
		return "", nil, false
	}
	fields := strings.SplitN(rest, " ", 2)
	if fields[0] == "" {
		return "", nil, false
	}
	name = "cgo_" + fields[0]
	categories = append(categories, CategoryDirectiveInSource)
	args := ""
	if len(fields) > 1 {
		args = strings.TrimSpace(fields[1])
	}
	if strings.Contains(args, ",") {
		categories = append(categories, CategoryRefused)
	}
	switch name {
	case "cgo_ldflag":
		// An escaped quote escapes the quoting the compiler applies to the
		// flag, letting a value break out as its own argument.
		if strings.Contains(args, `\"`) {
			categories = append(categories, CategoryRefused)
		}
	case "cgo_import_dynamic":
		// //go:cgo_import_dynamic local symbol "dll!function" ["library"]:
		// the second field names the Windows DLL and must be a bare name.
		parts := strings.Fields(args)
		if len(parts) >= 2 {
			dll := strings.Trim(parts[1], `"`)
			if strings.ContainsAny(dll, `/\:`) || strings.Contains(dll, "..") || strings.HasPrefix(dll, "-") || strings.HasPrefix(dll, "@") {
				categories = append(categories, CategoryRefused)
			}
		}
	}
	return name, categories, true
}

// SysoObjectValid reports whether path begins like an input the linker
// accepts: an ELF, Mach-O (either byte order, fat binaries included), PE/COFF
// object, or an ar archive. Only the first 64 bytes are read, and a file that
// cannot be opened counts as valid: unreadable is not the same as not an
// object, and the caller reports a classification, not a verdict.
func SysoObjectValid(path string) bool {
	// Only a regular file is opened: a FIFO or device committed as a .syso
	// would block the read, and the linker could not use it either.
	info, err := os.Lstat(path)
	if err != nil {
		return true
	}
	if !info.Mode().IsRegular() {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer func() { _ = f.Close() }()
	var header [64]byte
	n, _ := f.Read(header[:])
	return hasObjectMagic(header[:n])
}

func hasObjectMagic(header []byte) bool {
	for _, magic := range [][]byte{
		magicELF,
		magicMachO32BE, magicMachO32LE,
		magicMachO64BE, magicMachO64LE,
		magicMachOFatBE, magicMachOFatLE,
		magicMachOFat64BE, magicMachOFat64LE,
		magicPE,
		magicArchive,
	} {
		if bytes.HasPrefix(header, magic) {
			return true
		}
	}
	return false
}

var (
	magicELF          = []byte{0x7f, 'E', 'L', 'F'}
	magicMachO32BE    = []byte{0xfe, 0xed, 0xfa, 0xce}
	magicMachO32LE    = []byte{0xce, 0xfa, 0xed, 0xfe}
	magicMachO64BE    = []byte{0xfe, 0xed, 0xfa, 0xcf}
	magicMachO64LE    = []byte{0xcf, 0xfa, 0xed, 0xfe}
	magicMachOFatBE   = []byte{0xca, 0xfe, 0xba, 0xbe}
	magicMachOFatLE   = []byte{0xbe, 0xba, 0xfe, 0xca}
	magicMachOFat64BE = []byte{0xca, 0xfe, 0xba, 0xbf}
	magicMachOFat64LE = []byte{0xbf, 0xba, 0xfe, 0xca}
	magicPE           = []byte{'M', 'Z'}
	magicArchive      = []byte("!<arch>\n")
)

// resolveCgoPath expands ${SRCDIR} to the directive file's directory and
// resolves a relative path against it, the way the compiler sees the flag.
// Sysroot decorations Go strips ("=", "$SYSROOT") go first.
func resolveCgoPath(path, srcDir string) string {
	path = strings.TrimPrefix(path, "=")
	path = strings.TrimPrefix(path, "$SYSROOT")
	path = strings.ReplaceAll(path, "${SRCDIR}", srcDir)
	if !filepath.IsAbs(path) {
		path = filepath.Join(srcDir, path)
	}
	return filepath.Clean(path)
}

// pathCategories classifies where a flag's path argument points: outside the
// package when it is absolute or climbs with "..", and inside the analysed
// module when the resolved path falls under moduleRoot. Both can hold at once.
func pathCategories(rawPath, resolvedPath, moduleRoot string) []string {
	if rawPath == "" {
		return nil
	}
	var categories []string
	if filepath.IsAbs(rawPath) || strings.Contains(rawPath, "..") {
		categories = append(categories, CategoryPathEscape)
	}
	if moduleRoot != "" && underDir(resolvedPath, moduleRoot) {
		categories = append(categories, CategoryModulePath)
	}
	return categories
}

// underDir reports whether path names something inside root. Both must be
// absolute and cleaned.
func underDir(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

func statIsRegular(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// dirHoldsSpecFile reports whether dir, the target of -L or -isysroot, holds a
// GCC spec file. GCC reads spec files from search directories and executes
// what they describe, which is why the patched toolchain refuses such
// directories. Only the conventional names at the top of the directory are
// checked, which keeps the classifier a classifier rather than a walk of the
// analyst's disk.
func dirHoldsSpecFile(dir string) bool {
	if dir == "" {
		return false
	}
	// Opening a FIFO named by a flag would block, so only a directory is read.
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		if name == "specs" || strings.HasSuffix(name, ".spec") {
			return true
		}
	}
	return false
}

// flagName reduces a flag token to the name a report may carry: the part
// before "=", short joined path flags ("-I/usr/include") to the flag itself,
// and a comma-joined -Wl form to its first two segments. The remainder is a
// value or a path and never belongs in a name.
func flagName(token string) string {
	if name, _, ok := strings.Cut(token, "="); ok {
		token = name
	}
	if rest, ok := strings.CutPrefix(token, "-Wl,"); ok {
		if i := strings.Index(rest, ","); i >= 0 {
			return "-Wl," + rest[:i]
		}
		return token
	}
	for _, prefix := range []string{"-I", "-L", "-F", "-B"} {
		if strings.HasPrefix(token, prefix) && len(token) > len(prefix) {
			return prefix
		}
	}
	return token
}
