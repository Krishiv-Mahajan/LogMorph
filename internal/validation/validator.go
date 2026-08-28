package validation

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/Krishiv-Mahajan/LogMorph/internal/models"
)

//go:embed universal_event.schema.json
var embeddedUniversalSchema string

// ValidationError details a specific field violation.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationResult contains the outcome of schema validation.
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors"`
}

// Validator validates events against the Universal Event JSON schema.
type Validator interface {
	Validate(event *models.UniversalEvent) ValidationResult
	ValidateBytes(data []byte) ValidationResult
}

// JSONSchemaValidator uses compiled JSON schemas to validate events.
type JSONSchemaValidator struct {
	schema *jsonschema.Schema
	mu     sync.RWMutex
}

// NewValidator initializes a JSON schema validator from contracts or embedded fallback.
func NewValidator(schemaPath string) (*JSONSchemaValidator, error) {
	compiler := jsonschema.NewCompiler()

	var schemaData string
	if schemaPath != "" {
		if content, err := os.ReadFile(schemaPath); err == nil {
			schemaData = string(content)
		}
	}

	if schemaData == "" {
		schemaData = embeddedUniversalSchema
	}

	if schemaData == "" {
		return nil, fmt.Errorf("no schema content available")
	}

	schemaURL := "universal_event.schema.json"
	if err := compiler.AddResource(schemaURL, strings.NewReader(schemaData)); err != nil {
		return nil, fmt.Errorf("failed to add schema resource: %w", err)
	}

	compiled, err := compiler.Compile(schemaURL)
	if err != nil {
		return nil, fmt.Errorf("failed to compile schema: %w", err)
	}

	return &JSONSchemaValidator{
		schema: compiled,
	}, nil
}

// Validate converts UniversalEvent to JSON and validates it against the schema.
func (v *JSONSchemaValidator) Validate(event *models.UniversalEvent) ValidationResult {
	data, err := json.Marshal(event)
	if err != nil {
		return ValidationResult{
			Valid: false,
			Errors: []ValidationError{
				{Field: "root", Message: fmt.Sprintf("failed to serialize event: %v", err)},
			},
		}
	}
	return v.ValidateBytes(data)
}

// ValidateBytes validates raw JSON bytes against the schema.
func (v *JSONSchemaValidator) ValidateBytes(data []byte) ValidationResult {
	var vData any
	if err := json.Unmarshal(data, &vData); err != nil {
		return ValidationResult{
			Valid: false,
			Errors: []ValidationError{
				{Field: "root", Message: fmt.Sprintf("invalid JSON: %v", err)},
			},
		}
	}

	v.mu.RLock()
	err := v.schema.Validate(vData)
	v.mu.RUnlock()

	if err == nil {
		return ValidationResult{
			Valid:  true,
			Errors: []ValidationError{},
		}
	}

	var valErrors []ValidationError
	if valErr, ok := err.(*jsonschema.ValidationError); ok {
		for _, leaf := range valErr.Causes {
			valErrors = append(valErrors, ValidationError{
				Field:   leaf.InstanceLocation,
				Message: leaf.Message,
			})
		}
		if len(valErrors) == 0 {
			valErrors = append(valErrors, ValidationError{
				Field:   valErr.InstanceLocation,
				Message: valErr.Message,
			})
		}
	} else {
		valErrors = append(valErrors, ValidationError{
			Field:   "schema",
			Message: err.Error(),
		})
	}

	return ValidationResult{
		Valid:  false,
		Errors: valErrors,
	}
}
