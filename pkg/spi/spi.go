/*
Copyright (c) 2020 SAP SE or an SAP affiliate company. All rights reserved.

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

package spi

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"

	api "github.com/flant/machine-controller-manager-provider-yandex/pkg/provider/apis"
	corev1 "k8s.io/api/core/v1"

	ycsdk "github.com/yandex-cloud/go-sdk"
	"github.com/yandex-cloud/go-sdk/iamkey"
)

type SecretUIDToYcSDK map[types.UID]*ycsdk.SDK

type YandexSessionStore struct {
	sync.Mutex

	sdk SecretUIDToYcSDK
}

func NewYandexSession() *YandexSessionStore {
	return &YandexSessionStore{
		sdk: make(SecretUIDToYcSDK),
	}
}

func (ys *YandexSessionStore) GetSession(ctx context.Context, secret *corev1.Secret) (*ycsdk.SDK, error) {
	ys.Lock()
	defer ys.Unlock()

	if sdk, ok := ys.sdk[secret.UID]; ok {
		return sdk, nil
	}

	var serviceAccountKey iamkey.Key
	err := json.Unmarshal(secret.Data[api.YandexServiceAccountJSON], &serviceAccountKey)
	if err != nil {
		return nil, err
	}

	creds, err := ycsdk.ServiceAccountKey(&serviceAccountKey)
	if err != nil {
		return nil, err
	}

	return ycsdk.Build(ctx, ycsdk.Config{Credentials: creds})
}

func (ys *YandexSessionStore) GC() {
	ys.Lock()
	defer ys.Unlock()

	ctx, cancelFunc := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelFunc()

	for k, v := range ys.sdk {
		_ = v.Shutdown(ctx)
		delete(ys.sdk, k)
	}
}
