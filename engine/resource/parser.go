// Copyright 2019 Drone.IO Inc. All rights reserved.
// Use of this source code is governed by the Polyform License
// that can be found in the LICENSE file.

package resource

import (
	"errors"

	"github.com/drone/runner-go/manifest"

	"github.com/buildkite/yaml"
)

func init() {
	manifest.Register(parse)
}

// parse parses the raw resource and returns an Exec pipeline.
func parse(r *manifest.RawResource) (manifest.Resource, bool, error) {
	if !match(r) {
		return nil, false, nil
	}
	out := new(Pipeline)
	err := yaml.Unmarshal(r.Data, out)
	if err != nil {
		return out, true, err
	}
	err = lint(out)
	return out, true, err
}

// match returns true if the resource matches the kind and type.
func match(r *manifest.RawResource) bool {
	return r.Kind == Kind && r.Type == Type
}

// lint returns an error if any pipeline values are invalid.
func lint(pipeline *Pipeline) error {
	// ensure configuration provided.
	if pipeline.Server.AMI == "" {
		return errors.New("Linter: invalid or missing AMI")
	}
	if pipeline.Server.Type == "" {
		return errors.New("Linter: invalid or missing type")
	}
	if pipeline.Server.SSHPublicKeyName != "" && pipeline.Server.SSHPrivateKey.Value == "" {
		return errors.New("Linter: invalid or missing ssh private key with named key")
	}

	// ensure pipeline steps are not unique.
	names := map[string]struct{}{}
	for _, step := range pipeline.Steps {
		if step.Detach {
			return errors.New("Linter: detached steps are not allowed")
		}
		if step.Name == "" {
			return errors.New("Linter: invalid or missing step name")
		}
		if _, ok := names[step.Name]; ok {
			return errors.New("Linter: duplicate step name")
		}
		names[step.Name] = struct{}{}
	}
	return nil
}
