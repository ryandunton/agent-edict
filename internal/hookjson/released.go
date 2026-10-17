package hookjson

import "bytes"

// ReleasedPolicy replaces a per-user hook product's policy when the product
// leaves AgentEdict's managed scope. Hooks still registered in users' home
// folders then allow every action instead of denying on a missing policy.
var ReleasedPolicy = []byte("{\"agentedict\":\"released\"}\n")

// IsReleased reports whether data is exactly the released policy. Any other
// bytes, including near matches, are evaluated as an ordinary policy.
func IsReleased(data []byte) bool {
	return bytes.Equal(data, ReleasedPolicy)
}
