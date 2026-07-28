package seam

import (
	"go/types"
	"sort"

	"golang.org/x/tools/go/ssa"
)

// InterfaceIndex maps interface types to their known implementations.
// It replaces the O(methods × summaries) name+string-signature scan with
// a single pre-built lookup using types.Implements.
type InterfaceIndex struct {
	// methods maps (package path, interface name, method name) → implementing functions.
	methods map[ifaceKey][]*ssa.Function

	// byInterface maps *types.Interface → list of implementing *types.Named types.
	byInterface map[*types.Interface][]*types.Named

	// namedToFunc maps *types.Named → implementing *ssa.Function (for methods).
	namedToFunc map[*types.Named]map[string]*ssa.Function
}

type ifaceKey struct {
	pkgPath    string
	ifaceName  string
	methodName string
}

// NewInterfaceIndex builds an implements-index from the set of analyzed functions.
func NewInterfaceIndex(funcs []*ssa.Function, programTypes []*types.Package) *InterfaceIndex {
	idx := &InterfaceIndex{
		methods:     make(map[ifaceKey][]*ssa.Function),
		byInterface: make(map[*types.Interface][]*types.Named),
		namedToFunc: make(map[*types.Named]map[string]*ssa.Function),
	}

	// Index all functions by their receiver named type.
	for _, fn := range funcs {
		if fn == nil || fn.Signature == nil || fn.Signature.Recv() == nil {
			continue
		}
		recvType := fn.Signature.Recv().Type()
		if ptr, ok := recvType.(*types.Pointer); ok {
			recvType = ptr.Elem()
		}
		recvType = types.Unalias(recvType)
		named, ok := recvType.(*types.Named)
		if !ok {
			continue
		}
		if idx.namedToFunc[named] == nil {
			idx.namedToFunc[named] = make(map[string]*ssa.Function)
		}
		idx.namedToFunc[named][fn.Name()] = fn
	}

	// For each known named type, check which interfaces it implements.
	for named, methods := range idx.namedToFunc {
		_ = methods
		// Find all interfaces in the program.
		for _, pkg := range programTypes {
			if pkg == nil {
				continue
			}
			for _, name := range pkg.Scope().Names() {
				obj := pkg.Scope().Lookup(name)
				if obj == nil {
					continue
				}
				typeName, ok := obj.(*types.TypeName)
				if !ok {
					continue
				}
				iface, ok := typeName.Type().Underlying().(*types.Interface)
				if !ok {
					continue
				}
				if types.Implements(named, iface) {
					idx.byInterface[iface] = append(idx.byInterface[iface], named)
					// Index each interface method → implementing functions.
					for i := 0; i < iface.NumMethods(); i++ {
						method := iface.Method(i)
						if fn, ok := idx.namedToFunc[named][method.Name()]; ok {
							key := ifaceKey{
								pkgPath:    obj.Pkg().Path(),
								ifaceName:  typeName.Name(),
								methodName: method.Name(),
							}
							idx.methods[key] = append(idx.methods[key], fn)
						}
					}
				}
			}
		}
	}

	return idx
}

// LookupInterfaceCall returns the functions that could be called at an
// interface dispatch site.
func (idx *InterfaceIndex) LookupInterfaceCall(common *ssa.CallCommon) []*ssa.Function {
	if common == nil || common.Method == nil {
		return nil
	}
	method := common.Method

	// Resolve through the interface type's receiver, which tells us which
	// interface is being dispatched. This is the O(1) primary path.
	if sig, ok := method.Type().(*types.Signature); ok {
		if sig.Recv() != nil {
			recvType := sig.Recv().Type()
			if iface, ok := recvType.Underlying().(*types.Interface); ok {
				var results []*ssa.Function
				seen := make(map[*ssa.Function]bool)
				for _, named := range idx.byInterface[iface] {
					if fn, ok := idx.namedToFunc[named][method.Name()]; ok && !seen[fn] {
						seen[fn] = true
						results = append(results, fn)
					}
				}
				if len(results) > 0 {
					sort.Slice(results, func(i, j int) bool { return results[i].String() < results[j].String() })
					return results
				}
			}
		}
	}

	// Fallback: look up by interface key (package, interface name, method name).
	// This handles cases where the interface type isn't directly available.
	if method.Pkg() != nil {
		key := ifaceKey{
			pkgPath:    method.Pkg().Path(),
			methodName: method.Name(),
		}
		var results []*ssa.Function
		seen := make(map[*ssa.Function]bool)
		for k, fns := range idx.methods {
			if k.methodName == key.methodName && k.pkgPath == key.pkgPath {
				for _, fn := range fns {
					if !seen[fn] {
						seen[fn] = true
						results = append(results, fn)
					}
				}
			}
		}
		sort.Slice(results, func(i, j int) bool { return results[i].String() < results[j].String() })
		return results
	}

	return nil
}

// ImplementorsOf returns all function implementations of an interface method.
func (idx *InterfaceIndex) ImplementorsOf(iface *types.Interface, methodName string) []*ssa.Function {
	if iface == nil {
		return nil
	}
	var results []*ssa.Function
	seen := make(map[*ssa.Function]bool)
	for _, named := range idx.byInterface[iface] {
		if fn, ok := idx.namedToFunc[named][methodName]; ok && !seen[fn] {
			seen[fn] = true
			results = append(results, fn)
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].String() < results[j].String() })
	return results
}
