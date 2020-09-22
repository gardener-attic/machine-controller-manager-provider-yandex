// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"encoding/json"
	api "github.com/flant/machine-controller-manager-provider-yandex/pkg/provider/apis"
	"github.com/gardener/machine-controller-manager/pkg/apis/machine/v1alpha1"
)

func unmarshalYandexProviderSpec(machineClass *v1alpha1.MachineClass) (*api.YandexProviderSpec, error) {
	var providerSpec *api.YandexProviderSpec

	err := json.Unmarshal(machineClass.ProviderSpec.Raw, &providerSpec)
	if err != nil {
		return nil, err
	}

	// TODO: validation
	/*
		ValidationErr := validation.ValidateYandexProviderSpec(providerSpec, secret)
		if ValidationErr != nil {
			err = fmt.Errorf("Error while validating ProviderSpec %v", ValidationErr)
			return nil, status.Error(codes.Internal, err.Error())
		}
	*/

	return providerSpec, nil
}
