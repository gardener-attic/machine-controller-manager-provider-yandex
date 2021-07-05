/*
SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
SPDX-License-Identifier: Apache-2.0
*/

// Package provider contains the cloud provider specific implementations to manage machines
package provider

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gogo/protobuf/proto"
	ycsdk "github.com/yandex-cloud/go-sdk"
	ycsdkoperation "github.com/yandex-cloud/go-sdk/operation"

	api "github.com/flant/machine-controller-manager-provider-yandex/pkg/provider/apis"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/compute/v1"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/operation"

	"github.com/gardener/machine-controller-manager/pkg/util/provider/driver"
	mcmcodes "github.com/gardener/machine-controller-manager/pkg/util/provider/machinecodes/codes"
	mcmstatus "github.com/gardener/machine-controller-manager/pkg/util/provider/machinecodes/status"
	"k8s.io/klog"
)

const (
	apiTimeout = 10 * time.Minute
)

// NOTE
//
// The basic working of the controller will work with just implementing the CreateMachine() & DeleteMachine() methods.
// You can first implement these two methods and check the working of the controller.
// Leaving the other methods to NOT_IMPLEMENTED error status.
// Once this works you can implement the rest of the methods.
//
// Also make sure each method return appropriate errors mentioned in `https://github.com/gardener/machine-controller-manager/blob/master/docs/development/machine_error_codes.md`

// CreateMachine handles a machine creation request
// REQUIRED METHOD
//
// REQUEST PARAMETERS (driver.CreateMachineRequest)
// Machine               *v1alpha1.Machine        Machine object from whom VM is to be created
// MachineClass          *v1alpha1.MachineClass   MachineClass backing the machine object
// Secret                *corev1.Secret           Kubernetes secret that contains any sensitive data/credentials
//
// RESPONSE PARAMETERS (driver.CreateMachineResponse)
// ProviderID            string                   Unique identification of the VM at the cloud provider. This could be the same/different from req.MachineName.
//                                                ProviderID typically matches with the node.Spec.ProviderID on the node object.
//                                                Eg: gce://project-name/region/vm-ProviderID
// NodeName              string                   Returns the name of the node-object that the VM register's with Kubernetes.
//                                                This could be different from req.MachineName as well
// LastKnownState        string                   (Optional) Last known state of VM during the current operation.
//                                                Could be helpful to continue operations in future requests.
//
// OPTIONAL IMPLEMENTATION LOGIC
// It is optionally expected by the safety controller to use an identification mechanisms to map the VM Created by a providerSpec.
// These could be done using tag(s)/resource-groups etc.
// This logic is used by safety controller to delete orphan VMs which are not backed by any machine CRD
//
func (p *Provider) CreateMachine(ctx context.Context, req *driver.CreateMachineRequest) (*driver.CreateMachineResponse, error) {
	// Log messages to track request
	klog.V(2).Infof("Machine creation request has been recieved for %q", req.Machine.Name)
	defer klog.V(2).Infof("Machine creation request has been processed for %q", req.Machine.Name)

	var (
		machine      = req.Machine
		secret       = req.Secret
		machineClass = req.MachineClass
	)

	ctx, cancelFunc := context.WithTimeout(context.Background(), apiTimeout)
	defer cancelFunc()

	ySDK, err := p.YandexSDK.GetSession(ctx, secret)
	if err != nil {
		return nil, mcmstatus.Error(mcmcodes.Internal, err.Error())
	}

	spec, err := unmarshalYandexProviderSpec(machineClass)
	if err != nil {
		return nil, mcmstatus.Error(mcmcodes.InvalidArgument, err.Error())
	}

	var instanceMetadata = make(map[string]string)
	if spec.Metadata != nil {
		instanceMetadata = spec.Metadata
	}

	userData, exists := secret.Data["userData"]
	if !exists {
		return nil, mcmstatus.Error(mcmcodes.InvalidArgument, "userData doesn't exist")
	}
	instanceMetadata["user-data"] = string(userData)

	var networkInterfaceSpecs []*compute.NetworkInterfaceSpec
	for _, netIf := range spec.NetworkInterfaceSpecs {
		var natSpec *compute.OneToOneNatSpec
		if netIf.AssignPublicIPAddress {
			natSpec = &compute.OneToOneNatSpec{
				IpVersion: compute.IpVersion_IPV4,
			}
		}

		var externalIPv4Address = &compute.PrimaryAddressSpec{
			OneToOneNatSpec: natSpec,
		}

		networkInterfaceSpecs = append(networkInterfaceSpecs, &compute.NetworkInterfaceSpec{
			SubnetId:             netIf.SubnetID,
			PrimaryV4AddressSpec: externalIPv4Address,
		})
	}

	createInstanceParams := &compute.CreateInstanceRequest{
		FolderId:   string(secret.Data[api.YandexFolderID]),
		Name:       machine.Name,
		Hostname:   machine.Name,
		Labels:     spec.Labels,
		Metadata:   instanceMetadata,
		ZoneId:     spec.ZoneID,
		PlatformId: spec.PlatformID,
		ResourcesSpec: &compute.ResourcesSpec{
			Memory:       spec.ResourcesSpec.Memory,
			Cores:        spec.ResourcesSpec.Cores,
			CoreFraction: spec.ResourcesSpec.CoreFraction,
			Gpus:         spec.ResourcesSpec.GPUs,
		},
		BootDiskSpec: &compute.AttachedDiskSpec{
			Mode:       compute.AttachedDiskSpec_READ_WRITE,
			AutoDelete: spec.BootDiskSpec.AutoDelete,
			Disk: &compute.AttachedDiskSpec_DiskSpec_{
				DiskSpec: &compute.AttachedDiskSpec_DiskSpec{
					TypeId: spec.BootDiskSpec.TypeID,
					Size:   spec.BootDiskSpec.Size,
					Source: &compute.AttachedDiskSpec_DiskSpec_ImageId{
						ImageId: spec.BootDiskSpec.ImageID,
					},
				},
			},
		},
		NetworkInterfaceSpecs: networkInterfaceSpecs,
		SchedulingPolicy: &compute.SchedulingPolicy{
			Preemptible: spec.SchedulingPolicy.Preemptible,
		},
	}

	result, _, err := waitForResult(ctx, ySDK, func() (*operation.Operation, error) {
		return ySDK.Compute().Instance().Create(ctx, createInstanceParams)
	})
	if err != nil {
		return nil, mcmstatus.Error(mcmcodes.InvalidArgument, err.Error())
	}

	newInstance, ok := result.(*compute.Instance)
	if !ok {
		return nil, mcmstatus.Error(mcmcodes.Internal, fmt.Sprintf("Yandex.Cloud API returned %q instead of \"*compute.Instance\". That shouldn't happen", reflect.TypeOf(result).String()))
	}

	return &driver.CreateMachineResponse{ProviderID: encodeMachineID(newInstance.ZoneId, newInstance.Id), NodeName: machine.Name}, nil
}

// DeleteMachine handles a machine deletion request
//
// REQUEST PARAMETERS (driver.DeleteMachineRequest)
// Machine               *v1alpha1.Machine        Machine object from whom VM is to be deleted
// MachineClass          *v1alpha1.MachineClass   MachineClass backing the machine object
// Secret                *corev1.Secret           Kubernetes secret that contains any sensitive data/credentials
//
// RESPONSE PARAMETERS (driver.DeleteMachineResponse)
// LastKnownState        bytes(blob)              (Optional) Last known state of VM during the current operation.
//                                                Could be helpful to continue operations in future requests.
//
func (p *Provider) DeleteMachine(ctx context.Context, req *driver.DeleteMachineRequest) (*driver.DeleteMachineResponse, error) {
	// Log messages to track delete request
	klog.V(2).Infof("Machine deletion request has been recieved for %q", req.Machine.Name)
	defer klog.V(2).Infof("Machine deletion request has been processed for %q", req.Machine.Name)

	var (
		machine = req.Machine
		secret  = req.Secret
	)

	ctx, cancelFunc := context.WithTimeout(context.Background(), apiTimeout)
	defer cancelFunc()

	ySDK, err := p.YandexSDK.GetSession(ctx, secret)
	if err != nil {
		return nil, mcmstatus.Error(mcmcodes.Internal, err.Error())
	}
	_, instanceID, err := decodeMachineID(machine.Spec.ProviderID)
	if err != nil {
		return nil, mcmstatus.Error(mcmcodes.InvalidArgument, err.Error())
	}

	_, _, err = waitForResult(ctx, ySDK, func() (*operation.Operation, error) {
		return ySDK.Compute().Instance().Delete(ctx, &compute.DeleteInstanceRequest{InstanceId: instanceID})
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			klog.V(2).Infof("No Instance matching the ID %q found on the provider: %s", instanceID, err)
			return &driver.DeleteMachineResponse{}, nil
		} else {
			return nil, mcmstatus.Error(mcmcodes.Internal, err.Error())
		}
	}

	return &driver.DeleteMachineResponse{}, nil
}

// GetMachineStatus handles a machine get status request
// OPTIONAL METHOD
//
// REQUEST PARAMETERS (driver.GetMachineStatusRequest)
// Machine               *v1alpha1.Machine        Machine object from whom VM status needs to be returned
// MachineClass          *v1alpha1.MachineClass   MachineClass backing the machine object
// Secret                *corev1.Secret           Kubernetes secret that contains any sensitive data/credentials
//
// RESPONSE PARAMETERS (driver.GetMachineStatueResponse)
// ProviderID            string                   Unique identification of the VM at the cloud provider. This could be the same/different from req.MachineName.
//                                                ProviderID typically matches with the node.Spec.ProviderID on the node object.
//                                                Eg: gce://project-name/region/vm-ProviderID
// NodeName             string                    Returns the name of the node-object that the VM register's with Kubernetes.
//                                                This could be different from req.MachineName as well
//
// The request should return a NOT_FOUND (5) status error code if the machine is not existing
func (p *Provider) GetMachineStatus(ctx context.Context, req *driver.GetMachineStatusRequest) (*driver.GetMachineStatusResponse, error) {
	// Log messages to track start and end of request
	klog.V(2).Infof("Get request has been recieved for %q", req.Machine.Name)
	defer klog.V(2).Infof("Machine get request has been processed successfully for %q", req.Machine.Name)

	var (
		machine = req.Machine
		secret  = req.Secret
	)

	ctx, cancelFunc := context.WithTimeout(context.Background(), apiTimeout)
	defer cancelFunc()

	ySDK, err := p.YandexSDK.GetSession(ctx, secret)
	if err != nil {
		return nil, mcmstatus.Error(mcmcodes.Internal, err.Error())
	}
	if machine.Spec.ProviderID == "" {
		return nil, mcmstatus.Error(mcmcodes.NotFound, "providerID field is empty")
	}
	_, instanceID, err := decodeMachineID(machine.Spec.ProviderID)
	if err != nil {
		return nil, mcmstatus.Error(mcmcodes.InvalidArgument, err.Error())
	}

	_, err = ySDK.Compute().Instance().Get(ctx, &compute.GetInstanceRequest{InstanceId: instanceID})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, mcmstatus.Error(mcmcodes.NotFound, err.Error())
		}
	}

	return &driver.GetMachineStatusResponse{ProviderID: machine.Spec.ProviderID, NodeName: machine.Name}, nil
}

// ListMachines lists all the machines possibilly created by a providerSpec
// Identifying machines created by a given providerSpec depends on the OPTIONAL IMPLEMENTATION LOGIC
// you have used to identify machines created by a providerSpec. It could be tags/resource-groups etc
// OPTIONAL METHOD
//
// REQUEST PARAMETERS (driver.ListMachinesRequest)
// MachineClass          *v1alpha1.MachineClass   MachineClass based on which VMs created have to be listed
// Secret                *corev1.Secret           Kubernetes secret that contains any sensitive data/credentials
//
// RESPONSE PARAMETERS (driver.ListMachinesResponse)
// MachineList           map<string,string>  A map containing the keys as the MachineID and value as the MachineName
//                                           for all machine's who where possibilly created by this ProviderSpec
//
func (p *Provider) ListMachines(ctx context.Context, req *driver.ListMachinesRequest) (*driver.ListMachinesResponse, error) {
	// Log messages to track start and end of request
	klog.V(2).Infof("List machines request has been recieved for %q", req.MachineClass.Name)
	defer klog.V(2).Infof("List machines request has been recieved for %q", req.MachineClass.Name)

	var (
		machineClass = req.MachineClass
		secret       = req.Secret
		folderID     = string(secret.Data[api.YandexFolderID])
	)

	ctx, cancelFunc := context.WithTimeout(context.Background(), apiTimeout)
	defer cancelFunc()

	ySDK, err := p.YandexSDK.GetSession(ctx, secret)
	if err != nil {
		return nil, mcmstatus.Error(mcmcodes.Internal, err.Error())
	}

	listOfVMs := make(map[string]string)

	clusterName := ""
	nodeRole := ""

	for key := range machineClass.Labels {
		if strings.Contains(key, "kubernetes-io-cluster-") {
			clusterName = key
		} else if strings.Contains(key, "kubernetes-io-role-") {
			nodeRole = key
		}
	}

	if clusterName == "" || nodeRole == "" {
		return nil, mcmstatus.Error(mcmcodes.InvalidArgument, fmt.Sprintf(`no "kubernetes-io-cluster" or "kubernetes-io-role-" labels found in the MachineClass %s/%s`,
			machineClass.Namespace, machineClass.Name))
	}

	// TODO: Replace this abomination with something more Go-like
	var instances []*compute.Instance
	instanceIterator := ySDK.Compute().Instance().InstanceIterator(ctx, folderID)
instanceIteration:
	for {
		next := instanceIterator.Next()
		switch next {
		case true:
			instances = append(instances, instanceIterator.Value())
		case false:
			break instanceIteration
		}
	}
	if instanceIterator.Error() != nil {
		return nil, mcmstatus.Error(mcmcodes.Internal, fmt.Sprintf("could not list instances for FolderID %q: %s", folderID, instanceIterator.Error()))
	}

	for _, instance := range instances {
		matchedCluster := false
		matchedRole := false
		for label := range instance.Labels {
			switch label {
			case clusterName:
				matchedCluster = true
			case nodeRole:
				matchedRole = true
			}
		}
		if matchedCluster && matchedRole {
			listOfVMs[encodeMachineID(instance.ZoneId, instance.Name)] = instance.Name
		}
	}

	return &driver.ListMachinesResponse{MachineList: listOfVMs}, nil
}

// GetVolumeIDs returns a list of Volume IDs for all PV Specs for whom an provider volume was found
//
// REQUEST PARAMETERS (driver.GetVolumeIDsRequest)
// PVSpecList            []*corev1.PersistentVolumeSpec       PVSpecsList is a list PV specs for whom volume-IDs are required.
//
// RESPONSE PARAMETERS (driver.GetVolumeIDsResponse)
// VolumeIDs             []string                             VolumeIDs is a repeated list of VolumeIDs.
//
func (p *Provider) GetVolumeIDs(_ context.Context, req *driver.GetVolumeIDsRequest) (*driver.GetVolumeIDsResponse, error) {
	// Log messages to track start and end of request
	klog.V(2).Infof("GetVolumeIDs request has been recieved for %q", req.PVSpecs)
	defer klog.V(2).Infof("GetVolumeIDs request has been processed successfully for %q", req.PVSpecs)

	var ids []string
	for _, spec := range req.PVSpecs {
		if spec.CSI == nil {
			// Not a CSI-managed volume
			continue
		}
		if spec.CSI.Driver != "yandex.csi.flant.com" {
			// Not a volume provisioned by Yandex.Cloud CSI driver
			continue
		}
		ids = append(ids, spec.CSI.VolumeHandle)
	}
	return &driver.GetVolumeIDsResponse{VolumeIDs: ids}, nil
}

// GenerateMachineClassForMigration helps in migration of one kind of machineClass CR to another kind.
// For instance an machineClass custom resource of `AWSMachineClass` to `MachineClass`.
// Implement this functionality only if something like this is desired in your setup.
// If you don't require this functionality leave is as is. (return Unimplemented)
//
// The following are the tasks typically expected out of this method
// 1. Validate if the incoming classSpec is valid one for migration (e.g. has the right kind).
// 2. Migrate/Copy over all the fields/spec from req.ProviderSpecificMachineClass to req.MachineClass
// For an example refer
//		https://github.com/prashanth26/machine-controller-manager-provider-gcp/blob/migration/pkg/gcp/machine_controller.go#L222-L233
//
// REQUEST PARAMETERS (driver.GenerateMachineClassForMigration)
// ProviderSpecificMachineClass    interface{}                             ProviderSpecificMachineClass is provider specfic machine class object (E.g. AWSMachineClass). Typecasting is required here.
// MachineClass 				   *v1alpha1.MachineClass                  MachineClass is the machine class object that is to be filled up by this method.
// ClassSpec                       *v1alpha1.ClassSpec                     Somemore classSpec details useful while migration.
//
// RESPONSE PARAMETERS (driver.GenerateMachineClassForMigration)
// NONE
//
func (p *Provider) GenerateMachineClassForMigration(_ context.Context, req *driver.GenerateMachineClassForMigrationRequest) (*driver.GenerateMachineClassForMigrationResponse, error) {
	// Log messages to track start and end of request
	klog.V(2).Infof("MigrateMachineClass request has been recieved for %q", req.ClassSpec)
	defer klog.V(2).Infof("MigrateMachineClass request has been processed successfully for %q", req.ClassSpec)

	return &driver.GenerateMachineClassForMigrationResponse{}, status.Error(codes.Unimplemented, "")
}

// FindInstanceByFolderAndName searches for Instance with the specified folderID and instanceName.
func FindInstanceByFolderAndName(ctx context.Context, sdk *ycsdk.SDK, folderID string, instanceName string) (*compute.Instance, error) {
	result, err := sdk.Compute().Instance().List(ctx, &compute.ListInstancesRequest{
		FolderId: folderID,
		Filter:   fmt.Sprintf("name = \"%s\"", instanceName),
		PageSize: 2,
	})
	if err != nil {
		return nil, err
	}

	if len(result.Instances) > 1 {
		return nil, fmt.Errorf("multiple instances found: folderID=%s, instanceName=%s", folderID, instanceName)
	}

	if result == nil || len(result.Instances) == 0 {
		return nil, nil
	}

	return result.Instances[0], nil
}

func encodeMachineID(zone, machineID string) string {
	return fmt.Sprintf("yandex://%s/%s", zone, machineID)
}

var regExpProviderID = regexp.MustCompile(`^yandex://([^/]+)/([^/]+)$`)

func decodeMachineID(machineID string) (string, string, error) {
	matches := regExpProviderID.FindStringSubmatch(machineID)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("unexpected providerID: %s", machineID)
	}

	return matches[1], matches[2], nil
}
func waitForResult(ctx context.Context, sdk *ycsdk.SDK, origFunc func() (*operation.Operation, error)) (proto.Message, *ycsdkoperation.Operation, error) {
	op, err := sdk.WrapOperation(origFunc())
	if err != nil {
		return nil, nil, err
	}

	err = op.Wait(ctx)
	if err != nil {
		return nil, op, err
	}

	resp, err := op.Response()
	if err != nil {
		return nil, op, err
	}

	return resp, op, nil
}
