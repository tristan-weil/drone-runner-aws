// Copyright 2019 Drone.IO Inc. All rights reserved.
// Use of this source code is governed by the Polyform License
// that can be found in the LICENSE file.

package engine

import (
	"bytes"
	"context"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/drone/runner-go/logger"
	"github.com/tristan-weil/drone-runner-aws/internal/platform"
	"github.com/tristan-weil/drone-runner-aws/utils/sshutil"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type (
	EngineArgs struct {
		SSHPrivateKey string
		AWS           EndpointArgs
	}

	EndpointArgs struct {
		Endpoint        string
		Region          string
		AccessKeyID     string
		SecretAccessKey string
	}

	engine struct {
		privatekey string
		aws        EndpointArgs
	}
)

// New returns a new engine.
func New(config *EngineArgs) (Engine, error) {
	var privatekey []byte
	var err error

	if config.SSHPrivateKey != "" {
		privatekey, err = ioutil.ReadFile(config.SSHPrivateKey)
		if err != nil {
			return nil, err
		}
	}

	return &engine{
		privatekey: string(privatekey),
		aws:        config.AWS,
	}, err
}

// Setup the pipeline environment.
func (e *engine) Setup(ctx context.Context, spec *Spec) error {
	// override ENV < yaml
	privatekey := e.privatekey
	if spec.Server.SSHPrivateKey != "" && spec.Server.SSHPrivateKey != e.privatekey {
		privatekey = spec.Server.SSHPrivateKey
	}

	awsEndpoint := e.aws.Endpoint
	if spec.AWS.Endpoint != "" {
		awsEndpoint = spec.AWS.Endpoint
	}

	awsAccessKeyID := e.aws.AccessKeyID
	if spec.AWS.AccessKeyID != "" {
		awsAccessKeyID = spec.AWS.AccessKeyID
	}

	awsSecretAccessKey := e.aws.SecretAccessKey
	if spec.AWS.SecretAccessKey != "" {
		awsSecretAccessKey = spec.AWS.SecretAccessKey
	}

	awsRegion := e.aws.Region
	if spec.AWS.Region != "" {
		awsRegion = spec.AWS.Region
	}

	// provision the server instance.
	instance, err := platform.Provision(ctx, platform.ProvisionArgs{
		// basics
		Name: spec.Server.Name,
		AMI:  spec.Server.AMI,
		Type: spec.Server.Type,

		// spot
		SpotPrice: spec.Server.SpotPrice,

		// capacity
		DiskSize: spec.Server.DiskSize, // in GB
		DiskName: spec.Server.DiskName,

		// credentials
		Username:         spec.Server.Username,
		Password:         spec.Server.Password,
		SSHPrivateKey:    privatekey, // in PEM format
		SSHKeyType:       spec.Server.SSHKeyType,
		SSHPublicKeyName: spec.Server.SSHPublicKeyName,

		// networks
		VPC:                 spec.Server.VPC,
		SecurityGroupsNames: spec.Server.SecurityGroupsNames,

		// aws
		AWS: platform.AWSArgs{
			Endpoint:        awsEndpoint,
			Region:          awsRegion,
			AccessKeyID:     awsAccessKeyID,
			SecretAccessKey: awsSecretAccessKey,
		},
	})
	if err != nil {
		return err
	}
	if instance.ID == "" {
		err = errors.Errorf("cannot create instance: unknown error")
		logger.FromContext(ctx).
			WithError(err).
			WithField("hostname", spec.Server.Name).
			Error("cannot create instance: unknown error")
		return err
	}
	spec.id = instance.ID
	spec.ip = instance.IP
	spec.sshPrivateKey = instance.SSHPrivateKey
	spec.sshPublicKeyName = instance.SSHPublicKeyName
	spec.alreadyCreatedSSHPublicKeyName = instance.AlreadyCreatedSSHPublicKeyName
	spec.securityGroupsIds = instance.SecurityGroupsIds
	spec.alreadyCreatedSecurityGroups = instance.AlreadyCreatedSecurityGroups

	logger.FromContext(ctx).
		WithField("hostname", spec.Server.Name).
		WithField("user", spec.Server.Username).
		WithField("ip", instance.IP).
		WithField("id", instance.ID).
		Debug("dial the server")

	// establish an ssh connection with the server instance
	// to setup the build environment (upload build scripts, etc)
	client, err := sshutil.Dial(
		spec.ip,
		spec.Server.Username,
		spec.Server.Password,
		instance.SSHPrivateKey,
		time.Minute*5,
	)
	if err != nil {
		logger.FromContext(ctx).
			WithError(err).
			WithField("hostname", spec.Server.Name).
			WithField("user", spec.Server.Username).
			WithField("ip", instance.IP).
			WithField("id", instance.ID).
			Debug("failed to dial server")
		return err
	}
	defer client.Close()

	clientftp, err := sftp.NewClient(client)
	if err != nil {
		logger.FromContext(ctx).
			WithError(err).
			WithField("hostname", spec.Server.Name).
			WithField("ip", instance.IP).
			WithField("id", instance.ID).
			Debug("failed to create sftp client")
		return err
	}
	defer clientftp.Close()

	// the pipeline workspace is created before pipeline
	// execution begins. All files and folders created during
	// pipeline execution are isolated to this workspace.
	err = mkdir(clientftp, spec.Root, 0777)
	if err != nil {
		logger.FromContext(ctx).
			WithError(err).
			WithField("path", spec.Root).
			Error("cannot create workspace directory")
		return err
	}

	// the pipeline specification may define global folders, such
	// as the pipeline working directory, wich must be created
	// before pipeline execution begins.
	for _, file := range spec.Files {
		if file.IsDir == false {
			continue
		}
		err = mkdir(clientftp, file.Path, file.Mode)
		if err != nil {
			logger.FromContext(ctx).
				WithError(err).
				WithField("path", file.Path).
				Error("cannot create directory")
			return err
		}
	}

	// the pipeline specification may define global files such
	// as authentication credentials that should be uploaded
	// before pipeline execution begins.
	for _, file := range spec.Files {
		if file.IsDir == true {
			continue
		}
		err = upload(clientftp, file.Path, file.Data, file.Mode)
		if err != nil {
			logger.FromContext(ctx).
				WithError(err).
				Error("cannot write file")
			return err
		}
	}

	logger.FromContext(ctx).
		WithField("hostname", spec.Server.Name).
		WithField("ip", instance.IP).
		WithField("id", instance.ID).
		Debug("server configuration complete")

	return nil
}

// Destroy the pipeline environment.
func (e *engine) Destroy(ctx context.Context, spec *Spec) error {
	// if the server was not successfully created
	// exit since there is no droplet to delete.
	if spec.id == "" {
		return nil
	}

	// override ENV < yaml
	awsEndpoint := e.aws.Endpoint
	if spec.AWS.Endpoint != "" {
		awsEndpoint = spec.AWS.Endpoint
	}

	awsAccessKeyID := e.aws.AccessKeyID
	if spec.AWS.AccessKeyID != "" {
		awsAccessKeyID = spec.AWS.AccessKeyID
	}

	awsSecretAccessKey := e.aws.SecretAccessKey
	if spec.AWS.SecretAccessKey != "" {
		awsSecretAccessKey = spec.AWS.SecretAccessKey
	}

	awsRegion := e.aws.Region
	if spec.AWS.Region != "" {
		awsRegion = spec.AWS.Region
	}

	logger.FromContext(ctx).
		WithField("hostname", spec.Server.Name).
		WithField("ip", spec.ip).
		WithField("id", spec.id).
		Debug("terminating server")

	return platform.Destroy(ctx, platform.DestroyArgs{
		// server
		ID:                             spec.id,
		IP:                             spec.ip,
		SSHPublicKeyName:               spec.sshPublicKeyName,
		AlreadyCreatedSSHPublicKeyName: spec.alreadyCreatedSSHPublicKeyName,
		SecurityGroupsIds:              spec.securityGroupsIds,
		AlreadyCreatedSecurityGroups:   spec.alreadyCreatedSecurityGroups,

		// aws
		AWS: platform.AWSArgs{
			Endpoint:        awsEndpoint,
			Region:          awsRegion,
			AccessKeyID:     awsAccessKeyID,
			SecretAccessKey: awsSecretAccessKey,
		},
	})
}

// Run runs the pipeline step.
func (e *engine) Run(ctx context.Context, spec *Spec, step *Step, output io.Writer) (*State, error) {
	client, err := sshutil.Dial(
		spec.ip,
		spec.Server.Username,
		spec.Server.Password,
		spec.sshPrivateKey,
		time.Minute*5,
	)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	clientftp, err := sftp.NewClient(client)
	if err != nil {
		return nil, err
	}
	defer clientftp.Close()

	// unlike os/exec there is no good way to set environment
	// the working directory or configure environment variables.
	// we work around this by pre-pending these configurations
	// to the pipeline execution script.
	for _, file := range step.Files {
		w := new(bytes.Buffer)
		writeWorkdir(w, step.WorkingDir)
		writeSecrets(w, spec.Platform.OS, step.Secrets)
		writeEnviron(w, spec.Platform.OS, step.Envs)
		w.Write(file.Data)
		err = upload(clientftp, file.Path, w.Bytes(), file.Mode)
		if err != nil {
			logger.FromContext(ctx).
				WithError(err).
				WithField("path", file.Path).
				Error("cannot write file")
			return nil, err
		}
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	session.Stdout = output
	session.Stderr = output
	cmd := step.Command + " " + strings.Join(step.Args, " ")

	log := logger.FromContext(ctx)
	log.Debug("ssh session started")

	done := make(chan error)
	go func() {
		done <- session.Run(cmd)
	}()

	select {
	case err = <-done:
	case <-ctx.Done():
		// BUG(bradrydzewski): openssh does not support the signal
		// command and will not signal remote processes. This may
		// be resolved in openssh 7.9 or higher. Please subscribe
		// to https://github.com/golang/go/issues/16597.
		if err := session.Signal(ssh.SIGKILL); err != nil {
			log.WithError(err).Debug("kill remote process")
		}

		log.Debug("ssh session killed")
		return nil, ctx.Err()
	}

	state := &State{
		ExitCode:  0,
		Exited:    true,
		OOMKilled: false,
	}
	if err != nil {
		state.ExitCode = 255
	}
	if exiterr, ok := err.(*ssh.ExitError); ok {
		state.ExitCode = exiterr.ExitStatus()
	}

	log.WithField("ssh.exit", state.ExitCode).
		Debug("ssh session finished")
	return state, err
}

// helper function writes the file to the remote server and then
// configures the file permissions.
func upload(client *sftp.Client, path string, data []byte, mode uint32) error {
	f, err := client.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	err = f.Chmod(os.FileMode(mode))
	if err != nil {
		return err
	}
	return nil
}

// helper function creates the folder on the remote server and
// then configures the folder permissions.
func mkdir(client *sftp.Client, path string, mode uint32) error {
	err := client.MkdirAll(path)
	if err != nil {
		return err
	}
	return client.Chmod(path, os.FileMode(mode))
}
