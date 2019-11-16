// Copyright 2019 Drone.IO Inc. All rights reserved.
// Use of this source code is governed by the Polyform License
// that can be found in the LICENSE file.

package resource

import "github.com/drone/runner-go/manifest"

var (
	_ manifest.Resource          = (*Pipeline)(nil)
	_ manifest.TriggeredResource = (*Pipeline)(nil)
	_ manifest.DependantResource = (*Pipeline)(nil)
	_ manifest.PlatformResource  = (*Pipeline)(nil)
)

// Defines the Resource Kind and Type.
const (
	Kind = "pipeline"
	Type = "aws"
)

type (
	// Pipeline is a pipeline resource that executes pipelines
	// on the host machine without any virtualization.
	Pipeline struct {
		AWS    AWS    `json:"aws,omitempty"`
		Server Server `json:"server,omitempty"`

		Version   string              `json:"version,omitempty"`
		Kind      string              `json:"kind,omitempty"`
		Type      string              `json:"type,omitempty"`
		Name      string              `json:"name,omitempty"`
		Deps      []string            `json:"depends_on,omitempty"`
		Clone     manifest.Clone      `json:"clone,omitempty"`
		Platform  manifest.Platform   `json:"platform,omitempty"`
		Trigger   manifest.Conditions `json:"conditions,omitempty"`
		Workspace manifest.Workspace  `json:"workspace,omitempty"`

		Steps []*Step `json:"steps,omitempty"`
	}

	// AWS provides the endpoint configuration.
	AWS struct {
		Endpoint        string            `json:"endpoint,omitempty"`
		Region          string            `json:"region,omitempty"`
		AccessKeyID     manifest.Variable `json:"access_key_id,omitempty" yaml:"access_key_id"`
		SecretAccessKey manifest.Variable `json:"secret_access_key,omitempty" yaml:"secret_access_key"`
	}

	// Server defines a remote server.
	Server struct {
		// basics
		Name string `json:"name,omitempty"`
		AMI  string `json:"ami,omitempty"`
		Type string `json:"type,omitempty"`

		// spot
		SpotPrice manifest.Variable `json:"spot_price,omitempty" yaml:"spot_price"`

		// capacity
		DiskSize int64  `json:"disk_size,omitempty" yaml:"disk_size"` // in GB
		DiskName string `json:"disk_name,omitempty" yaml:"disk_name"`

		// credentials
		Username         string            `json:"username,omitempty"`
		Password         manifest.Variable `json:"password,omitempty"`
		SSHPrivateKey    manifest.Variable `json:"ssh_private_key,omitempty" yaml:"ssh_private_key"` // in PEM format
		SSHKeyType       string            `json:"ssh_key_type,omitempty" yaml:"ssh_key_type"`
		SSHPublicKeyName string            `json:"ssh_key_name,omitempty" yaml:"aws_ssh_key_name"`

		// network
		VPC                 string   `json:"vpc,omitempty"`
		SecurityGroupsNames []string `json:"security_groups,omitempty" yaml:"security_groups"`
	}

	// Step defines a Pipeline step.
	Step struct {
		Name        string                        `json:"name,omitempty"`
		Shell       string                        `json:"shell,omitempty"`
		DependsOn   []string                      `json:"depends_on,omitempty" yaml:"depends_on"`
		Detach      bool                          `json:"detach,omitempty"`
		Environment map[string]*manifest.Variable `json:"environment,omitempty"`
		Failure     string                        `json:"failure,omitempty"`
		Commands    []string                      `json:"commands,omitempty"`
		When        manifest.Conditions           `json:"when,omitempty"`
		WorkingDir  string                        `json:"working_dir,omitempty" yaml:"working_dir"`
	}
)

// GetVersion returns the resource version.
func (p *Pipeline) GetVersion() string { return p.Version }

// GetKind returns the resource kind.
func (p *Pipeline) GetKind() string { return p.Kind }

// GetType returns the resource type.
func (p *Pipeline) GetType() string { return p.Type }

// GetName returns the resource name.
func (p *Pipeline) GetName() string { return p.Name }

// GetDependsOn returns the resource dependencies.
func (p *Pipeline) GetDependsOn() []string { return p.Deps }

// GetTrigger returns the resource triggers.
func (p *Pipeline) GetTrigger() manifest.Conditions { return p.Trigger }

// GetPlatform returns the resource platform.
func (p *Pipeline) GetPlatform() manifest.Platform { return p.Platform }

// GetStep returns the named step. If no step exists with the
// given name, a nil value is returned.
func (p *Pipeline) GetStep(name string) *Step {
	for _, step := range p.Steps {
		if step.Name == name {
			return step
		}
	}
	return nil
}
