package manifest

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadFile parses, validates, and compiles one manifest file.
func LoadFile(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	return Load(data, path)
}

// Load parses, validates, and compiles one manifest document.
func Load(data []byte, source string) (*Snapshot, error) {
	positions, err := decodePositions(data)
	if err != nil {
		return nil, fmt.Errorf("parse manifest positions: %w", err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var raw Manifest
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode manifest: multiple YAML documents are not allowed")
		}
		return nil, fmt.Errorf("decode trailing manifest document: %w", err)
	}

	if err := validate(raw, positions); err != nil {
		return nil, err
	}
	return compile(raw, data, source), nil
}

func decodePositions(data []byte) (map[string]Position, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	positions := make(map[string]Position)
	if len(document.Content) > 0 {
		collectPositions(document.Content[0], "", positions)
	}
	return positions, nil
}

func collectPositions(node *yaml.Node, path string, positions map[string]Position) {
	switch node.Kind {
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index]
			value := node.Content[index+1]
			childPath := key.Value
			if path != "" {
				childPath = path + "." + key.Value
			}
			positions[childPath] = Position{Line: value.Line, Column: value.Column}
			collectPositions(value, childPath, positions)
		}
	case yaml.SequenceNode:
		for index, child := range node.Content {
			childPath := fmt.Sprintf("%s[%d]", path, index)
			positions[childPath] = Position{Line: child.Line, Column: child.Column}
			collectPositions(child, childPath, positions)
		}
	}
}
