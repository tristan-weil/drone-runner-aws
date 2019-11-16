// Copyright 2019 Drone.IO Inc. All rights reserved.
// Use of this source code is governed by the Polyform License
// that can be found in the LICENSE file.

// Package platform contains code to provision and destroy server
// instances on the AWS cloud platform.
package platform

import (
	"context"
	"github.com/drone/runner-go/logger"
)

type (
	// DestroyArgs provides arguments to destroy the instance.
	DestroyArgs struct {
		// instance
		ID string
		IP string

		SSHPublicKeyName               string
		AlreadyCreatedSSHPublicKeyName bool

		SecurityGroupsIds            []string
		AlreadyCreatedSecurityGroups bool

		// endpoint
		AWS AWSArgs
	}

	// ProvisionArgs provides arguments to provision instances.
	ProvisionArgs struct {
		// instance: basics
		Name string
		AMI  string
		Type string

		// instance: spot
		SpotPrice string

		// instance: capacity
		DiskSize int64
		DiskName string

		// instance: credentials
		Username         string
		Password         string
		SSHPrivateKey    string // in PEM format
		SSHKeyType       string
		SSHPublicKeyName string

		// instance: network
		VPC                 string
		Subnet              string
		SecurityGroupsNames []string

		// endpoint
		AWS AWSArgs
	}

	// AWSArgs represents the AWSArgs endpoint.
	AWSArgs struct {
		// endpoint
		Endpoint        string
		Region          string
		AccessKeyID     string
		SecretAccessKey string
	}

	// Server represents a provisioned server instance.
	Instance struct {
		ID string
		IP string

		SSHPrivateKey string // in PEM format

		SSHPublicKeyName               string
		AlreadyCreatedSSHPublicKeyName bool

		SecurityGroupsIds            []string
		AlreadyCreatedSecurityGroups bool
	}
)

// Provision provisions the server instance.
func Provision(ctx context.Context, args ProvisionArgs) (Instance, error) {
	logger := logger.FromContext(ctx).
		WithField("user", args.Username).
		WithField("ami", args.AMI).
		WithField("hostname", args.Name)

	instanceController, errInstance := newInstanceController(ctx, &args, logger)
	if errInstance != nil {
		return Instance{}, errInstance
	}

	logger.Info("instance creation")

	//
	// Keypair
	//
	errKeypair := instanceController.buildKeyPair(logger)
	if errKeypair != nil {
		return instanceController.instance, errKeypair
	}

	// Subnet
	errSubnet := instanceController.getSubnetId(logger)
	if errSubnet != nil {
		// rollback
		instanceController.destroyKeyPair(logger)

		return instanceController.instance, errSubnet
	}

	//
	// SG
	//
	errSG := instanceController.buildSecurityGroups(logger)
	if errSG != nil {
		// rollback
		instanceController.destroyKeyPair(logger)

		return instanceController.instance, errSG
	}

	//
	// Server
	//
	errVM := instanceController.instantiateVM(logger)
	if errVM != nil {
		// rollback
		instanceController.destroyKeyPair(logger)
		instanceController.destroySecurityGroups(logger)

		return instanceController.instance, errVM
	}

	logger = logger.WithField("id", instanceController.instance.ID).
		WithField("hostname", args.Name).
		WithField("ip", instanceController.instance.IP)

	logger.Info("instance created")

	return instanceController.instance, nil
}

// Destroy destroys the server instance.
func Destroy(ctx context.Context, args DestroyArgs) error {
	logger := logger.FromContext(ctx).
		WithField("id", args.ID).
		WithField("ip", args.IP)

	instanceController, errInstance := newInstanceController(ctx, &args, logger)
	if errInstance != nil {
		return errInstance
	}

	logger.Info("instance destruction")

	errCtrl := instanceController.destroyVMAndSecurityGroup(logger)
	if errCtrl != nil {
		return errCtrl
	}

	errKeyPair := instanceController.destroyKeyPair(logger)
	if errKeyPair != nil {
		return errKeyPair
	}

	return nil
}
