// Copyright 2019 Drone.IO Inc. All rights reserved.
// Use of this source code is governed by the Polyform License
// that can be found in the LICENSE file.

// Package platform contains code to provision and destroy server
// instances on the AWS cloud platform.
package platform

import (
	"context"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/drone/runner-go/logger"
	"github.com/pkg/errors"
	"github.com/tristan-weil/drone-runner-aws/utils/sshutil"
	"time"
)

type (
	builderArgs interface {
		getAWSEndpoint() string
		getAWSRegion() string
		getAWSAccessKeyID() string
		getAWSSecretAccessKey() string
	}

	instanceController struct {
		// drone
		ctx context.Context

		// AWSArgs
		ec2client *ec2.EC2
		vpcId     *string
		subnetId  *string
		vmArgs    *vmArgs

		// needed args
		builderArgs builderArgs

		// results to be passed
		instance Instance
	}

	vmArgs struct {
		rootBlockDeviceMapping *ec2.BlockDeviceMapping
		securityGroupsIds      []*string
	}
)

func (p *ProvisionArgs) getAWSEndpoint() string {
	return p.AWS.Endpoint
}

func (p *ProvisionArgs) getAWSAccessKeyID() string {
	return p.AWS.AccessKeyID
}

func (p *ProvisionArgs) getAWSSecretAccessKey() string {
	return p.AWS.SecretAccessKey
}

func (p *ProvisionArgs) getAWSRegion() string {
	return p.AWS.Region
}

func (d *DestroyArgs) getAWSEndpoint() string {
	return d.AWS.Endpoint
}

func (d *DestroyArgs) getAWSAccessKeyID() string {
	return d.AWS.AccessKeyID
}

func (d *DestroyArgs) getAWSSecretAccessKey() string {
	return d.AWS.SecretAccessKey
}

func (d *DestroyArgs) getAWSRegion() string {
	return d.AWS.Region
}

// newInstanceController returns a new controller.
func newInstanceController(ctx context.Context, args builderArgs, logger logger.Logger) (*instanceController, error) {
	instanceController := &instanceController{
		ctx:         ctx,
		builderArgs: args,
		instance:    Instance{},
	}

	if dargs, ok := args.(*DestroyArgs); ok {
		instanceController.instance.ID = dargs.ID
		instanceController.instance.IP = dargs.IP
		instanceController.instance.SSHPublicKeyName = dargs.SSHPublicKeyName
		instanceController.instance.AlreadyCreatedSSHPublicKeyName = dargs.AlreadyCreatedSSHPublicKeyName
		instanceController.instance.SecurityGroupsIds = dargs.SecurityGroupsIds
		instanceController.instance.AlreadyCreatedSecurityGroups = dargs.AlreadyCreatedSecurityGroups
	}

	//
	// Create session
	//
	config := aws.Config{
		Region:      aws.String(args.getAWSRegion()),
		Credentials: credentials.NewStaticCredentials(args.getAWSAccessKeyID(), args.getAWSSecretAccessKey(), ""),
	}
	if args.getAWSEndpoint() != "" {
		config.Endpoint = aws.String(args.getAWSEndpoint())
	}

	sess, err := session.NewSession(&config)
	if err != nil {
		logger.WithError(err).Error("cannot create instance: session error")
		return nil, err
	}

	//
	// Create EC2 service client
	//
	instanceController.ec2client = ec2.New(sess)

	return instanceController, nil
}

func (i *instanceController) destroyKeyPair(logger logger.Logger) error {
	if i.instance.SSHPublicKeyName != "" && !i.instance.AlreadyCreatedSSHPublicKeyName {
		keyPairInput := ec2.DeleteKeyPairInput{
			KeyName: &i.instance.SSHPublicKeyName,
		}

		_, errKeyPair := i.ec2client.DeleteKeyPair(&keyPairInput)
		if errKeyPair != nil {
			logger.WithError(errKeyPair).Error("cannot terminate server, unable to create keypair")
			return errKeyPair
		}
	}

	return nil
}

func (i *instanceController) buildKeyPair(logger logger.Logger) error {
	var err error

	if args, ok := i.builderArgs.(*ProvisionArgs); ok {
		i.instance.AlreadyCreatedSSHPublicKeyName = false

		if args.SSHPublicKeyName != "" {
			logger.Debug("using existing keypair")

			descKeyPairInput := ec2.DescribeKeyPairsInput{
				KeyNames: aws.StringSlice([]string{args.SSHPublicKeyName}),
			}

			desckeyPairOutput, err := i.ec2client.DescribeKeyPairs(&descKeyPairInput)
			if err != nil {
				logger.WithError(err).Error("cannot create instance, unable to get keypairs list")
				return err
			}
			if len(desckeyPairOutput.KeyPairs) == 0 {
				err = errors.New("unable to find keypair")
				logger.WithError(err).Error("cannot create instance, unable to find keypair")
				return err
			}

			i.instance.SSHPrivateKey = args.SSHPrivateKey
			i.instance.SSHPublicKeyName = args.SSHPublicKeyName
			i.instance.AlreadyCreatedSSHPublicKeyName = true
		} else {
			authkey := ""
			privkey := ""
			keyname := ""

			if args.SSHPrivateKey == "none" {
				logger.Debug("no keypair used")
				authkey = ""
				privkey = ""
				keyname = ""
			} else if args.SSHPrivateKey != "" {
				logger.Debug("submitted private key")

				authkey, err = sshutil.GenerateAuthorizedKeyKeyFromPEMPrivateKey(args.SSHPrivateKey)
				if err != nil {
					logger.WithError(err).Error("cannot create instance, unable to get authorized key from private key")
					return err
				}

				privkey = args.SSHPrivateKey
			} else {
				keyType := args.SSHKeyType
				if keyType != "aws" && keyType != "rsa" {
					keyType = "rsa"
				}

				// aws creation
				if keyType == "aws" {
					logger.Debug("aws generated keypair")

					var keyPairOutput *ec2.CreateKeyPairOutput
					keyPairInput := ec2.CreateKeyPairInput{
						KeyName: aws.String(args.Name),
					}

					keyPairOutput, err := i.ec2client.CreateKeyPair(&keyPairInput)
					if err != nil {
						logger.WithError(err).Error("cannot create instance, unable to create AWS keypair")
						return err
					}

					privkey = *keyPairOutput.KeyMaterial
					keyname = *keyPairOutput.KeyName
				} else { // generate
					logger.Debug("generated keypair")

					keyPair, err := sshutil.GeneratePEMKeyPair(&sshutil.Config{KeyType: keyType})
					if err != nil {
						logger.WithError(err).Error("cannot create instance, unable to generate keypair")
						return err
					}

					privkey = keyPair.PrivateKey
					authkey = keyPair.PublicKey
				}
			}

			// import
			if authkey != "" && privkey != "" {
				var keyPairOutput *ec2.ImportKeyPairOutput
				keyPairInput := ec2.ImportKeyPairInput{
					KeyName:           aws.String(args.Name),
					PublicKeyMaterial: []byte(authkey),
				}

				keyPairOutput, err := i.ec2client.ImportKeyPair(&keyPairInput)
				if err != nil {
					logger.WithError(err).Error("cannot create instance, unable to import key in AWS")
					return err
				}

				keyname = *keyPairOutput.KeyName
			}

			// aws or imported
			if privkey != "" {

				descKeyPairInput := ec2.DescribeKeyPairsInput{
					KeyNames: aws.StringSlice([]string{keyname}),
				}

				interval := time.Duration(0)

			pollerSSHKeypair:
				for {
					select {
					case <-i.ctx.Done():
						logger.Debug("cannot create instance, unable to create keypair")

						return i.ctx.Err()
					case <-time.After(interval):
						interval = time.Second * 5

						logger.Debug("check keypair creation")

						desckeyPairOutput, err := i.ec2client.DescribeKeyPairs(&descKeyPairInput)
						if err != nil {
							if awsErr, ok := err.(awserr.Error); ok {
								if awsErr.Code() == "InvalidKeyPair.NotFound" {
									// consistency issue? retry
									continue
								}
							}

							logger.WithError(err).Error("cannot create instance, keypair creation failed")
							return err
						}
						if len(desckeyPairOutput.KeyPairs) == 0 {
							// consistency issue? retry
							continue
						}

						break pollerSSHKeypair
					}
				}
			}

			i.instance.SSHPublicKeyName = keyname
			i.instance.SSHPrivateKey = privkey
		}
	}

	return nil
}

// helper function returns a vpcid.
func (i *instanceController) getVpcId(logger logger.Logger) error {
	if args, ok := i.builderArgs.(*ProvisionArgs); ok {
		if args.VPC != "" {
			describeVpcInput := ec2.DescribeVpcsInput{
				VpcIds: aws.StringSlice([]string{args.VPC}),
				//Filters: []*ec2.Filter{
				//	&ec2.Filter{
				//		Name:   aws.String("tag:Name"),
				//		Values: aws.StringSlice([]string{args.VPC}),
				//	},
				//},
			}

			describeVpcOutput, err := i.ec2client.DescribeVpcs(&describeVpcInput)
			if err != nil {
				logger.WithError(err).Error("cannot create instance, unable to get VPC list")
				return err
			}
			if len(describeVpcOutput.Vpcs) != 1 {
				err = errors.New("unable to find VPC")
				logger.WithError(err).Error("cannot create instance, unable to find VPC")
				return err
			}

			i.vpcId = describeVpcOutput.Vpcs[0].VpcId
		}
	}

	return nil
}

func (i *instanceController) getSubnetId(logger logger.Logger) error {
	if args, ok := i.builderArgs.(*ProvisionArgs); ok {
		var describeSubnetInput *ec2.DescribeSubnetsInput

		if args.Subnet != "" {
			describeSubnetInput = &ec2.DescribeSubnetsInput{
				SubnetIds: aws.StringSlice([]string{args.Subnet}),
				//Filters: []*ec2.Filter{
				//	&ec2.Filter{
				//		Name:   aws.String("tag:Name"),
				//		Values: aws.StringSlice([]string{args.VPC}),
				//	},
				//},
			}
		}

		if args.VPC != "" && args.Subnet == "" {
			err := i.getVpcId(logger)
			if err != nil {
				logger.WithError(err).Error("cannot create instance, unable to find VPC")
				return err
			}

			describeSubnetInput = &ec2.DescribeSubnetsInput{
				Filters: []*ec2.Filter{
					{
						Name:   aws.String("vpc-id"),
						Values: []*string{i.vpcId},
					},
				},
			}
		}

		if describeSubnetInput != nil {
			describeSubnetOutput, err := i.ec2client.DescribeSubnets(describeSubnetInput)
			if err != nil {
				logger.WithError(err).Error("cannot create instance, unable to get subnet list")
				return err
			}
			if len(describeSubnetOutput.Subnets) != 1 {
				err = errors.New("unable to find subnet")
				logger.WithError(err).Error("cannot create instance, unable to find subnet")
				return err
			}

			i.vpcId = describeSubnetOutput.Subnets[0].VpcId
			i.subnetId = describeSubnetOutput.Subnets[0].SubnetId
		}
	}

	return nil
}

func (i *instanceController) destroySecurityGroups(logger logger.Logger) error {
	if !i.instance.AlreadyCreatedSecurityGroups {
		for _, sgId := range i.instance.SecurityGroupsIds {
			delSGInput := ec2.DeleteSecurityGroupInput{
				GroupId: &sgId,
				//GroupName: nil,
			}

			_, err := i.ec2client.DeleteSecurityGroup(&delSGInput)
			if err != nil {
				logger.WithField("sg", sgId).
					WithError(err).
					Error("cannot delete security group")
				return err
			}

			return nil
		}
	}

	return nil
}

func (i *instanceController) buildSecurityGroups(logger logger.Logger) error {
	if args, ok := i.builderArgs.(*ProvisionArgs); ok {
		i.instance.AlreadyCreatedSecurityGroups = false

		//
		// user-defined
		//
		if len(args.SecurityGroupsNames) > 0 {
			logger.Debug("user-defined security groups")

			i.instance.AlreadyCreatedSecurityGroups = true

			describeSGInput := ec2.DescribeSecurityGroupsInput{
				//GroupIds: aws.StringSlice(args.SecurityGroupsIds),
				GroupNames: aws.StringSlice(args.SecurityGroupsNames),
			}

			describeSGOutput, errSG := i.ec2client.DescribeSecurityGroups(&describeSGInput)
			if errSG != nil {
				logger.WithError(errSG).Error("cannot create instance, unable to find user-defined security groups")
				return errSG
			}

			for _, sg := range describeSGOutput.SecurityGroups {
				i.instance.SecurityGroupsIds = append(i.instance.SecurityGroupsIds, *sg.GroupId)
			}

			return nil
		} else {
			//
			// drone-defined
			//

			//
			// sg creation
			//
			logger.Debug("instance's security group creation")

			sgInput := ec2.CreateSecurityGroupInput{
				Description: aws.String(args.Name),
				GroupName:   aws.String(args.Name),
			}
			if args.VPC != "" {
				sgInput.VpcId = i.vpcId
			}

			sgOutput, errSG := i.ec2client.CreateSecurityGroup(&sgInput)
			if errSG != nil {
				logger.WithError(errSG).Error("cannot create instance, unable to create security group")
				return errSG
			}

			sgGroupId := sgOutput.GroupId

			// ingress
			authSGIngressInput := ec2.AuthorizeSecurityGroupIngressInput{
				GroupId: sgGroupId,
				IpPermissions: []*ec2.IpPermission{
					{
						UserIdGroupPairs: []*ec2.UserIdGroupPair{
							{
								GroupId: sgGroupId,
							},
						},
						FromPort:   aws.Int64(22),
						ToPort:     aws.Int64(22),
						IpProtocol: aws.String("TCP"),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("0.0.0.0/0"),
								Description: aws.String("all"),
							},
						},
						Ipv6Ranges: []*ec2.Ipv6Range{
							{
								CidrIpv6:    aws.String("::/0"),
								Description: aws.String("all"),
							},
						},
					},
				},
			}

			_, errIngressRule := i.ec2client.AuthorizeSecurityGroupIngress(&authSGIngressInput)
			if errIngressRule != nil {
				logger.WithError(errIngressRule).Error("cannot create instance, unable to create security group's ingress rule")

				// rollback
				i.destroySecurityGroups(logger)

				return errIngressRule
			}

			// egress already allow everything by default

			//
			// check if it exists
			//
			descInstancesInput := ec2.DescribeSecurityGroupsInput{
				GroupIds: []*string{sgGroupId},
			}

			interval := time.Duration(0)

		pollerSG:
			for {
				select {
				case <-i.ctx.Done():
					logger.Debug("cannot create instance, unable to create security group")

					return i.ctx.Err()
				case <-time.After(interval):
					interval = time.Second * 5

					logger.Debug("check security group creation")

					descInstancesOutput, err := i.ec2client.DescribeSecurityGroups(&descInstancesInput)
					if err != nil {
						if awsErr, ok := err.(awserr.Error); ok {
							if awsErr.Code() == "InvalidSecurityGroupID.NotFound" {
								// consistency issue? retry
								continue
							}
						}

						logger.WithError(err).Error("cannot create instance, security group creation failed")
						return err
					}
					if len(descInstancesOutput.SecurityGroups) == 0 {
						// consistency issue? retry
						continue
					}

					i.instance.SecurityGroupsIds = []string{*sgGroupId}
					break pollerSG
				}
			}
		}
	}

	return nil
}

func (i *instanceController) destroyVMAndSecurityGroup(logger logger.Logger) error {
	// destroy the vm
	err := i.destroyVM(logger)
	if err != nil {
		return err
	}

	// check if its really destroyed
	interval := time.Duration(0)

pollerSGDestroy:
	for {
		select {
		case <-i.ctx.Done():
			logger.Debug("cannot instance server destruction")

			return i.ctx.Err()
		case <-time.After(interval):
			interval = time.Second * 5

			logger.Debug("check instance destruction")

			descInstancesInput := ec2.DescribeInstancesInput{
				InstanceIds: []*string{&i.instance.ID},
			}

			descInstancesOutput, err := i.ec2client.DescribeInstances(&descInstancesInput)
			if err != nil {
				break pollerSGDestroy
			}
			if len(descInstancesOutput.Reservations) == 0 {
				break pollerSGDestroy
			}

			instance := descInstancesOutput.Reservations[0].Instances[0]
			if *instance.State.Name == "terminated" {
				break pollerSGDestroy
			}
		}
	}

	// destroy the security group
	err = i.destroySecurityGroups(logger)
	if err != nil {
		return err
	}

	return nil
}

func (i *instanceController) destroyVM(logger logger.Logger) error {
	terminateInstanceInput := ec2.TerminateInstancesInput{
		InstanceIds: []*string{&i.instance.ID},
	}

	_, errTerm := i.ec2client.TerminateInstances(&terminateInstanceInput)
	if errTerm != nil {
		logger.WithError(errTerm).Error("cannot terminate server")
		return errTerm
	}

	return nil
}

func (i *instanceController) instantiateVM(logger logger.Logger) error {
	if args, ok := i.builderArgs.(*ProvisionArgs); ok {
		//
		// common parameters
		//
		rootBlockDeviceMapping := &ec2.BlockDeviceMapping{
			DeviceName: aws.String(args.DiskName),
			Ebs: &ec2.EbsBlockDevice{
				DeleteOnTermination: aws.Bool(true),
				Encrypted:           aws.Bool(true),
				VolumeType:          aws.String("gp2"),
			},
		}
		if args.DiskSize > 0 {
			rootBlockDeviceMapping.Ebs.VolumeSize = aws.Int64(args.DiskSize)
		}

		var sgIds []*string
		for _, sgId := range i.instance.SecurityGroupsIds {
			sgIds = append(sgIds, &sgId)
		}

		i.vmArgs = &vmArgs{
			rootBlockDeviceMapping: rootBlockDeviceMapping,
			securityGroupsIds:      sgIds,
		}

		//
		// VM
		//
		if args.SpotPrice != "" {
			return i.instantiateVMSpot(logger)
		} else {
			return i.instantiateVMOnDemand(logger)
		}
	}

	return nil
}

func (i *instanceController) instantiateVMSpot(logger logger.Logger) error {
	if args, ok := i.builderArgs.(*ProvisionArgs); ok {
		logger.Debug("spot instance creation")

		//
		// params
		//
		spotLaunchSpec := &ec2.RequestSpotLaunchSpecification{
			BlockDeviceMappings: []*ec2.BlockDeviceMapping{
				i.vmArgs.rootBlockDeviceMapping,
			},
			ImageId:          aws.String(args.AMI),
			InstanceType:     aws.String(args.Type),
			SecurityGroupIds: i.vmArgs.securityGroupsIds,
			UserData:         nil,
		}
		if i.instance.SSHPublicKeyName != "" {
			spotLaunchSpec.KeyName = &i.instance.SSHPublicKeyName
		}
		if i.subnetId != nil {
			spotLaunchSpec.SubnetId = i.subnetId
		}

		//
		// spot request
		//
		spotInput := ec2.RequestSpotInstancesInput{
			InstanceCount:                aws.Int64(1),
			InstanceInterruptionBehavior: aws.String("terminate"),
			LaunchSpecification:          spotLaunchSpec,
			Type:                         aws.String("one-time"),
		}
		if args.SpotPrice != "" {
			spotInput.SpotPrice = aws.String(args.SpotPrice)
		}

		spotOutput, err := i.ec2client.RequestSpotInstances(&spotInput)
		if err != nil {
			logger.WithError(err).Error("cannot create spot instance, unable to request spot instance")
			return err
		}
		if len(spotOutput.SpotInstanceRequests) == 0 {
			err = errors.New("unable to find spot instance request")
			logger.WithError(err).Error("cannot create instance, unable to find spot instance request")
			return err
		}

		//
		// polling to check if the request is created
		//
		descSpotRequest := ec2.DescribeSpotInstanceRequestsInput{
			SpotInstanceRequestIds: []*string{
				spotOutput.SpotInstanceRequests[0].SpotInstanceRequestId,
			},
		}

		cancelSpotRequest := ec2.CancelSpotInstanceRequestsInput{
			SpotInstanceRequestIds: []*string{
				spotOutput.SpotInstanceRequests[0].SpotInstanceRequestId,
			},
		}

		interval := time.Duration(0)

	pollerVMSpot:
		for {
			select {
			case <-i.ctx.Done():
				logger.Debug("cannot instantiate spot instance")

				cancelSpotInstanceReq, err := i.ec2client.CancelSpotInstanceRequests(&cancelSpotRequest)
				if err != nil {
					logger.WithError(err).Error("cannot create instance, unable to cancel spot instance")
					return err
				}
				if len(cancelSpotInstanceReq.CancelledSpotInstanceRequests) == 0 {
					err = errors.New("unable to cancel spot instance")
					logger.WithError(err).Error("cannot create instance, unable to cancel spot instance")
					return err
				}

				return i.ctx.Err()
			case <-time.After(interval):
				interval = time.Second * 10

				//
				// check request creation
				//
				logger.Debug("check instance spot creation")

				descSpotInstanceReq, err := i.ec2client.DescribeSpotInstanceRequests(&descSpotRequest)
				if err != nil {
					if awsErr, ok := err.(awserr.Error); ok {
						if awsErr.Code() == "InvalidSpotInstanceRequestID.NotFound" {
							// consistency issue? retry
							continue
						}
					}

					logger.WithError(err).Error("cannot create spot instance, request creation failed")
					return err
				}
				if len(descSpotInstanceReq.SpotInstanceRequests) == 0 {
					// consistency issue? retry
					continue
				}

				if *descSpotInstanceReq.SpotInstanceRequests[0].Status.Code != "fulfilled" {
					continue
				}

				i.instance.ID = *descSpotInstanceReq.SpotInstanceRequests[0].InstanceId
				break pollerVMSpot
			}
		}

		//
		// polling to check if the instance is created
		//
		err = i.getInstanceIP(logger)
		if err != nil {
			logger.WithError(err).Error("cannot create spot instance, instantiation failed")

			//rollback
			i.destroyVM(logger)
			i.destroySecurityGroups(logger)

			return err
		}
	}

	return nil
}

func (i *instanceController) instantiateVMOnDemand(logger logger.Logger) error {
	if args, ok := i.builderArgs.(*ProvisionArgs); ok {
		logger.Debug("onDemand instance creation")

		//
		// params
		//
		instanceInput := ec2.RunInstancesInput{
			BlockDeviceMappings: []*ec2.BlockDeviceMapping{
				i.vmArgs.rootBlockDeviceMapping,
			},
			ImageId:          aws.String(args.AMI),
			InstanceType:     aws.String(args.Type),
			MinCount:         aws.Int64(1),
			MaxCount:         aws.Int64(1),
			SecurityGroupIds: i.vmArgs.securityGroupsIds,
			UserData:         nil,
		}
		if i.instance.SSHPublicKeyName != "" {
			instanceInput.KeyName = &i.instance.SSHPublicKeyName
		}
		if i.subnetId != nil {
			instanceInput.SubnetId = i.subnetId
		}

		//
		// creation
		//
		reservation, err := i.ec2client.RunInstances(&instanceInput)
		if err != nil {
			logger.WithError(err).Error("cannot create instance, unable to ask a new instance")
			return err
		}

		if len(reservation.Instances) == 0 {
			err := errors.New("no instance found")
			logger.WithError(err).Error("cannot create instance, no instance found")
			return err
		}

		i.instance.ID = *reservation.Instances[0].InstanceId

		//
		// polling to check if the instance is created
		//
		err = i.getInstanceIP(logger)
		if err != nil {
			logger.WithError(err).Error("cannot create instance, instantiation failed")

			//rollback
			i.destroyVM(logger)
			i.destroySecurityGroups(logger)

			return err
		}
	}

	return nil
}

// getInstanceIP polls the VM to get its IP.
func (i *instanceController) getInstanceIP(logger logger.Logger) error {
	if args, ok := i.builderArgs.(*ProvisionArgs); ok {
		descInstancesInput := ec2.DescribeInstancesInput{
			InstanceIds: []*string{&i.instance.ID},
		}

		interval := time.Duration(0)

	pollerIP:
		for {
			select {
			case <-i.ctx.Done():
				logger.Debug("cannot instantiate instance")

				return i.ctx.Err()
			case <-time.After(interval):
				interval = time.Second * 10

				//
				// check creation
				//
				logger.Debug("check instance creation")

				descInstancesOutput, err := i.ec2client.DescribeInstances(&descInstancesInput)
				if err != nil {
					if awsErr, ok := err.(awserr.Error); ok {
						if awsErr.Code() == "InvalidInstanceID.NotFound" {
							// consistency issue? retry
							continue
						}
					}

					return err
				}
				if len(descInstancesOutput.Reservations) == 0 {
					// consistency issue? retry
					continue
				}

				//
				// check network
				//
				instance := descInstancesOutput.Reservations[0].Instances[0]

				if *instance.State.Name == "running" {
					logger.Debug("check instance network")

					if instance.PublicIpAddress != nil {
						logger.WithField("ip", *instance.PublicIpAddress).Debug("check ssh connection")

						sshClient, err := sshutil.Dial(
							*instance.PublicIpAddress,
							args.Username,
							args.Password,
							i.instance.SSHPrivateKey,
							time.Minute*2,
						)
						if err == nil {
							sshClient.Close()
							// found it!
							i.instance.IP = *instance.PublicIpAddress
							break pollerIP
						}
					}
				}
			}
		}
	}

	return nil
}
