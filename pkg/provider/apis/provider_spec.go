/*
Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package api

import corev1 "k8s.io/api/core/v1"

const (
	YandexFolderID           string = "folderID"
	YandexServiceAccountJSON string = "serviceAccountJSON"
)

// ProviderSpec is the spec to be used while parsing the calls.
type YandexProviderSpec struct {
	APIVersion string `json:"apiVersion,omitempty"`

	Labels     map[string]string `json:"labels,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	RegionID   string            `json:"regionID,omitempty"`
	ZoneID     string            `json:"zoneID,omitempty"`
	PlatformID string            `json:"platformID,omitempty"`

	ResourcesSpec         YandexProviderSpecResourcesSpec           `json:"resourcesSpec,omitempty"`
	BootDiskSpec          YandexProviderSpecBootDiskSpec            `json:"bootDiskSpec,omitempty"`
	NetworkInterfaceSpecs []YandexProviderSpecNetworkInterfaceSpecs `json:"networkInterfaceSpecs,omitempty"`
	SchedulingPolicy      YandexProviderSpecSchedulingPolicy        `json:"schedulingPolicy,omitempty"`

	SecretRef *corev1.SecretReference `json:"secretRef,omitempty"`
}

type YandexProviderSpecResourcesSpec struct {
	Cores        int64 `json:"cores,omitempty"`
	CoreFraction int64 `json:"coreFraction,omitempty"`
	Memory       int64 `json:"memory,omitempty"`
	GPUs         int64 `json:"gpus,omitempty"`
}

type YandexProviderSpecBootDiskSpec struct {
	AutoDelete bool   `json:"autoDelete,omitempty"`
	TypeID     string `json:"typeID,omitempty"`
	Size       int64  `json:"size,omitempty"`
	ImageID    string `json:"imageID,omitempty"`
}

type YandexProviderSpecNetworkInterfaceSpecs struct {
	SubnetID              string `json:"subnetID,omitempty"`
	AssignPublicIPAddress bool   `json:"assignPublicIPAddress,omitempty"`
}

type YandexProviderSpecSchedulingPolicy struct {
	Preemptible bool `json:"preemptible,omitempty"`
}
