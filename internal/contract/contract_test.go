package contract

import "testing"

func sampleContract() Contract {
	return Contract{Fields: []Field{
		{Name: "timestamp", Type: TypeString, Target: "timestamp"},
		{Name: "Src_IP", Aliases: []string{"source-ip", "SRC_IP"}, Type: TypeString, Target: "network.src_ip", Optional: true},
		{Name: "src_port", Type: TypeInteger, Target: "network.src_port", Optional: true},
	}}
}

func TestNormalizedIsDeterministic(t *testing.T) {
	c := sampleContract().Normalized()

	// Names are lower-cased and dashes folded to underscores.
	if c.Fields[0].Name != "src_ip" {
		t.Errorf("expected src_ip first after sorting, got %q", c.Fields[0].Name)
	}

	// Aliases are normalized and de-duplicated. "SRC_IP" normalizes to the
	// canonical name, so only the genuinely distinct alias survives.
	field, _, ok := c.Resolve("src_ip")
	if !ok {
		t.Fatal("expected src_ip to resolve")
	}
	if len(field.Aliases) != 1 || field.Aliases[0] != "source_ip" {
		t.Errorf("expected the single distinct alias source_ip, got %v", field.Aliases)
	}

	// Normalizing twice changes nothing.
	if c.Hash() != c.Normalized().Hash() {
		t.Error("expected Normalized to be idempotent")
	}
}

func TestResolveReachesAliases(t *testing.T) {
	c := sampleContract().Normalized()

	field, viaAlias, ok := c.Resolve("Source-IP")
	if !ok {
		t.Fatal("expected an alias to resolve")
	}
	if !viaAlias {
		t.Error("expected viaAlias=true for an alias lookup")
	}
	if field.Name != "src_ip" {
		t.Errorf("expected the canonical field src_ip, got %q", field.Name)
	}

	field, viaAlias, ok = c.Resolve("src_ip")
	if !ok || viaAlias {
		t.Error("expected the canonical name to resolve without the alias flag")
	}
	if field.Target != "network.src_ip" {
		t.Errorf("unexpected target %q", field.Target)
	}

	if _, _, ok := c.Resolve("nothing_like_this"); ok {
		t.Error("expected an undeclared name not to resolve")
	}
}

func TestHashTracksContent(t *testing.T) {
	base := sampleContract().Normalized()
	same := sampleContract().Normalized()

	if base.Hash() != same.Hash() {
		t.Error("expected equal contracts to hash equally")
	}

	added := base.WithField(Field{Name: "device_uuid", Type: TypeString, Optional: true})
	if added.Hash() == base.Hash() {
		t.Error("expected adding a field to change the hash")
	}

	retargeted := base.WithField(Field{Name: "src_port", Type: TypeInteger, Target: "network.dst_port", Optional: true})
	if retargeted.Hash() == base.Hash() {
		t.Error("expected changing a target to change the hash")
	}

	optionality := base.WithField(Field{Name: "timestamp", Type: TypeString, Target: "timestamp", Optional: true})
	if optionality.Hash() == base.Hash() {
		t.Error("expected changing optionality to change the hash")
	}
}

func TestWithFieldReplacesInPlace(t *testing.T) {
	c := sampleContract().Normalized()
	next := c.WithField(Field{Name: "SRC_PORT", Type: TypeString, Target: "network.src_port", Optional: true})

	if len(next.Fields) != len(c.Fields) {
		t.Errorf("expected the field to be replaced, not appended: %d -> %d", len(c.Fields), len(next.Fields))
	}
	field, _, _ := next.Resolve("src_port")
	if field.Type != TypeString {
		t.Errorf("expected the replacement type, got %q", field.Type)
	}
	// WithField must not mutate the receiver.
	original, _, _ := c.Resolve("src_port")
	if original.Type != TypeInteger {
		t.Error("WithField mutated the original contract")
	}
}

func TestHasNestedField(t *testing.T) {
	c := Contract{Fields: []Field{
		{Name: "network.src_ip", Type: TypeString, Optional: true},
		{Name: "action", Type: TypeString, Optional: true},
	}}

	if !c.HasNestedField("network") {
		t.Error("expected network to be recognised as declared structure")
	}
	if c.HasNestedField("firewall") {
		t.Error("expected firewall not to be recognised")
	}
	if c.HasNestedField("action") {
		t.Error("expected a scalar field not to be reported as nested structure")
	}
	if c.HasNestedField("") {
		t.Error("expected an empty prefix to report false")
	}
}

func TestRequiredAndTypes(t *testing.T) {
	c := sampleContract()
	required := c.Required()
	if len(required) != 1 || required[0].Name != "timestamp" {
		t.Errorf("expected only timestamp to be required, got %v", required)
	}

	if TypeObject.IsContainer() != true || TypeArray.IsContainer() != true {
		t.Error("expected object and array to be containers")
	}
	if TypeString.IsContainer() || TypeInteger.IsContainer() {
		t.Error("expected scalars not to be containers")
	}
	if Type("nonsense").Known() {
		t.Error("expected an unknown type to report Known()=false")
	}
}
