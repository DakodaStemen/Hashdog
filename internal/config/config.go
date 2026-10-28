// Package config loads the optional YAML or JSON rules file.
//
//	# hashdog.yaml
//	exclude:
//	  - "*.log"
//	  - var/cache/**
//	include:            # optional allow-list for files; empty = everything
//	  - etc/**
//
// The same keys work in JSON. Unknown keys are an error so typos don't
// silently disable a rule.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DakodaStemen/hashdog/internal/filter"
)

// File is the on-disk schema.
type File struct {
	Include []string `yaml:"include" json:"include"`
	Exclude []string `yaml:"exclude" json:"exclude"`
}

// Load reads path; the format is chosen by extension (.json, .yaml, .yml).
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&f); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	case ".yaml", ".yml":
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) { // empty file is fine
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	default:
		return nil, fmt.Errorf("%s: config must end in .json, .yaml or .yml", path)
	}
	if _, err := filter.New(f.Include, f.Exclude); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &f, nil
}
