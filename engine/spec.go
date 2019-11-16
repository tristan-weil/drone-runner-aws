// Copyright 2019 Drone.IO Inc. All rights reserved.
// Use of this source code is governed by the Polyform License
// that can be found in the LICENSE file.

package engine

type (
	// Spec provides the pipeline spec. This provides the
	// required instructions for reproducable pipeline
	// execution.
	Spec struct {
		// AWS
		AWS    AWS    `json:"aws,omitempty"`
		Server Server `json:"server,omitempty"`

		// drone
		Platform Platform `json:"platform,omitempty"`
		Root     string   `json:"root,omitempty"`
		Files    []*File  `json:"files,omitempty"`
		Steps    []*Step  `json:"steps,omitempty"`

		// the engine sets these variables after having
		// successfully provisioned an instance using the API
		id                             string   // ID of the provisioned instance.
		ip                             string   // IP of the provisioned instance.
		sshPrivateKey                  string   // SSHPrivateKey of the provisioned instance.
		sshPublicKeyName               string   // the associated public key name
		securityGroupsIds              []string // the security groups ids
		alreadyCreatedSSHPublicKeyName bool     // true if this keyname already exists
		alreadyCreatedSecurityGroups   bool     // true if the security groups already exist
	}

	// AWS provides the aws configuration
	AWS struct {
		Endpoint        string `json:"endpoint,omitempty"`
		Region          string `json:"region,omitempty"`
		AccessKeyID     string `json:"access_key_id,omitempty"`
		SecretAccessKey string `json:"secret_access_key,omitempty"`
	}

	// Server provides the server configuration.
	Server struct {
		// basics
		Name string `json:"name,omitempty"`
		AMI  string `json:"ami,omitempty"`
		Type string `json:"type,omitempty"`

		// spot
		SpotPrice string `json:"spot_price,omitempty"`

		// capacity
		DiskSize int64  `json:"disk_size,omitempty"` // in GB
		DiskName string `json:"disk_name,omitempty"`

		// credentials
		Username         string `json:"username,omitempty"`
		Password         string `json:"password,omitempty"`
		SSHPrivateKey    string `json:"ssh_private_key,omitempty"` // in PEM format
		SSHKeyType       string `json:"ssh_key_type,omitempty"`
		SSHPublicKeyName string `json:"ssh_key_name,omitempty"`

		// network
		VPC                 string   `json:"vpc,omitempty"`
		SecurityGroupsNames []string `json:"security_groups,omitempty"`
	}

	// Step defines a pipeline step.
	Step struct {
		Args         []string          `json:"args,omitempty"`
		Command      string            `json:"command,omitempty"`
		Detach       bool              `json:"detach,omitempty"`
		DependsOn    []string          `json:"depends_on,omitempty"`
		Envs         map[string]string `json:"environment,omitempty"`
		Files        []*File           `json:"files,omitempty"`
		IgnoreErr    bool              `json:"ignore_err,omitempty"`
		IgnoreStdout bool              `json:"ignore_stderr,omitempty"`
		IgnoreStderr bool              `json:"ignore_stdout,omitempty"`
		Name         string            `json:"name,omitempt"`
		RunPolicy    RunPolicy         `json:"run_policy,omitempty"`
		Secrets      []*Secret         `json:"secrets,omitempty"`
		WorkingDir   string            `json:"working_dir,omitempty"`
	}

	// File defines a file that should be uploaded or
	// mounted somewhere in the step container or virtual
	// machine prior to command execution.
	File struct {
		Path  string `json:"path,omitempty"`
		Mode  uint32 `json:"mode,omitempty"`
		Data  []byte `json:"data,omitempty"`
		IsDir bool   `json:"is_dir,omitempty"`
	}

	// Platform defines the target platform.
	Platform struct {
		OS      string `json:"os,omitempty"`
		Arch    string `json:"arch,omitempty"`
		Variant string `json:"variant,omitempty"`
		Version string `json:"version,omitempty"`
	}

	// Secret represents a secret variable.
	Secret struct {
		Name string `json:"name,omitempty"`
		Env  string `json:"env,omitempty"`
		Data []byte `json:"data,omitempty"`
		Mask bool   `json:"mask,omitempty"`
	}

	// State represents the process state.
	State struct {
		ExitCode  int  // Container exit code
		Exited    bool // Container exited
		OOMKilled bool // Container is oom killed
	}
)

// RunPolicy defines the policy for starting containers
// based on the point-in-time pass or fail state of
// the pipeline.
type RunPolicy int

// RunPolicy enumeration.
const (
	RunOnSuccess RunPolicy = iota
	RunOnFailure
	RunAlways
	RunNever
)
