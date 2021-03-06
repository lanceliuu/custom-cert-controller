/*
Copyright 2019 The Knative Authors

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

package certificate

import (
	"context"

	"knative.dev/pkg/client/injection/kube/client"

	"knative.dev/pkg/configmap"
	"knative.dev/pkg/controller"
	"knative.dev/pkg/logging"

	kcertinformer "knative.dev/networking/pkg/client/injection/informers/networking/v1alpha1/certificate"
	certreconciler "knative.dev/networking/pkg/client/injection/reconciler/networking/v1alpha1/certificate"

	secretinformer "knative.dev/pkg/client/injection/kube/informers/core/v1/secret"
)

const certManagerCertificateClassName = "custom-cert.certificate.networking.knative.dev"

// NewController creates a Reconciler and returns the result of NewImpl.
func NewController(
	ctx context.Context,
	cmw configmap.Watcher,
) *controller.Impl {
	logger := logging.FromContext(ctx)

	kcertInformer := kcertinformer.Get(ctx)

	// use global secret lister
	secretInformer := secretinformer.Get(ctx)

	r := &Reconciler{
		client:            client.Get(ctx),
		secretLister:      secretInformer.Lister(),
		certificateLister: kcertInformer.Lister(),
	}

	impl := certreconciler.NewImpl(ctx, r, certManagerCertificateClassName)

	logger.Info("Setting up event handlers.")

	kcertInformer.Informer().AddEventHandler(controller.HandleAll(impl.Enqueue))

	secretInformer.Informer().AddEventHandler(controller.HandleAll(
		impl.EnqueueControllerOf,
	))

	return impl
}
