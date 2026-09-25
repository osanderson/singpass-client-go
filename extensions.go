package singpass

import "github.com/idfoundry/fapigo/extension"

// authContextTypeExt is the Singpass/Corppass-proprietary
// "authentication_context_type" PAR parameter (mandatory for Login apps). It is
// a single bare string, so FAPIgo emits it as a plain top-level PAR parameter on
// the FAPI 2.0 baseline profile — no signed request object required. The value
// itself is the caller's responsibility (see Options.AuthContextType).
var authContextTypeExt = extension.Definition[string]{
	Name:           "authentication_context_type",
	Cardinality:    extension.Single,
	AllowedSources: extension.SourcePlainParameter,
	MaxBytes:       128,
}
