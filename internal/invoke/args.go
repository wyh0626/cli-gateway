package invoke

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/wyh0626/cli-gateway/internal/httpx"
	"github.com/wyh0626/cli-gateway/internal/model"
)

func validateArguments(command *model.CompiledCommand, supplied map[string]any) (map[string]any, *httpx.APIError) {
	definitions := make(map[string]model.CompiledFlag, len(command.Flags))
	for _, flag := range command.Flags {
		definitions[flag.Name] = flag
	}
	for name := range supplied {
		if _, ok := definitions[name]; !ok {
			return nil, argumentError(name, "unknown argument")
		}
	}

	result := make(map[string]any, len(command.Flags))
	for _, flag := range command.Flags {
		value, present := supplied[flag.Name]
		if !present {
			if flag.Default != nil {
				result[flag.Name] = flag.Default
				continue
			}
			if flag.Required {
				return nil, argumentError(flag.Name, "required argument is missing")
			}
			continue
		}
		normalized, err := normalizeValue(flag.Type, value)
		if err != nil {
			return nil, argumentError(flag.Name, err.Error())
		}
		result[flag.Name] = normalized
	}
	return result, nil
}

func normalizeValue(flagType model.FlagType, value any) (any, error) {
	switch flagType {
	case model.FlagString:
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("must be a string")
		}
		return text, nil
	case model.FlagInt:
		switch typed := value.(type) {
		case int:
			return typed, nil
		case int64:
			return typed, nil
		case json.Number:
			parsed, err := typed.Int64()
			if err != nil {
				return nil, fmt.Errorf("must be an integer")
			}
			return parsed, nil
		case float64:
			text := strconv.FormatFloat(typed, 'f', -1, 64)
			parsed, err := strconv.ParseInt(text, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("must be an integer")
			}
			return parsed, nil
		default:
			return nil, fmt.Errorf("must be an integer")
		}
	case model.FlagBool:
		boolean, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("must be a boolean")
		}
		return boolean, nil
	case model.FlagStringArray:
		switch typed := value.(type) {
		case []string:
			return append([]string(nil), typed...), nil
		case []any:
			result := make([]string, 0, len(typed))
			for _, item := range typed {
				text, ok := item.(string)
				if !ok {
					return nil, fmt.Errorf("must be an array of strings")
				}
				result = append(result, text)
			}
			return result, nil
		default:
			return nil, fmt.Errorf("must be an array of strings")
		}
	default:
		return nil, fmt.Errorf("uses an unsupported type")
	}
}

func argumentError(name, message string) *httpx.APIError {
	return &httpx.APIError{Status: 400, Code: "E_ARG_INVALID", Message: "argument " + name + " " + message}
}
