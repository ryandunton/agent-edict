package compiler

// NativeArtifact describes a generated file. Destinations are informational;
// the endpoint installs only its built-in targets, never arbitrary paths from a bundle.
type NativeArtifact struct {
	Extension   string `json:"extension"`
	Content     string `json:"-"`
	Delivery    string `json:"delivery"`
	Destination string `json:"destination"`
}

// NativeCapability describes the scope of a native control, including bypasses.
// It is not proof that a running application consumed the generated file.
type NativeCapability struct {
	Product string `json:"product"`
	Control string `json:"control"`
	Level   string `json:"level"`
	Details string `json:"details"`
}

type NativeOutput struct {
	Artifacts    []NativeArtifact   `json:"artifacts"`
	Capabilities []NativeCapability `json:"capabilities"`
}
