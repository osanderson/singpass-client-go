module github.com/osanderson/singpass-client-go/examples/demo

go 1.26.6

require github.com/osanderson/singpass-client-go v0.0.0

require github.com/idfoundry/fapigo v0.32.1-0.20260926045710-901fd04d16c6 // indirect

// The library is developed alongside this example in the same repo and is not
// published; resolve it from the local tree. go.work at the repo root does the
// same for a workspace build — this replace keeps `go build`/CI working with
// -mod=mod outside the workspace too.
replace github.com/osanderson/singpass-client-go => ../..
