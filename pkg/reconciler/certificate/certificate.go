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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"knative.dev/pkg/logging"
	"knative.dev/pkg/reconciler"

	v1alpha1 "knative.dev/networking/pkg/apis/networking/v1alpha1"
	certreconciler "knative.dev/networking/pkg/client/injection/reconciler/networking/v1alpha1/certificate"

	v1alpha1Lister "knative.dev/networking/pkg/client/listers/networking/v1alpha1"
	"knative.dev/pkg/kmeta"
)

const (
	organization    = "knative.dev"
	certificateCert = "tls.crt"
	certificateKey  = "tls.key"
)

// Reconciler implements addressableservicereconciler.Interface for
// AddressableService resources.
type Reconciler struct {
	client kubernetes.Interface

	secretLister corev1listers.SecretLister

	certificateLister v1alpha1Lister.CertificateLister
}

// Check that our Reconciler implements Interface
var _ certreconciler.Interface = (*Reconciler)(nil)

// ReconcileKind implements Interface.ReconcileKind.
func (r *Reconciler) ReconcileKind(ctx context.Context, o *v1alpha1.Certificate) reconciler.Event {
	logger := logging.FromContext(ctx)
	secret, err := r.secretLister.Secrets(o.Namespace).Get(o.Spec.SecretName)
	if apierrs.IsNotFound(err) {
		logger.Info("Generateing self-signed secret")
		serverKey, serverCert, caCert, err := createSelfSignCert(ctx, o)
		if err != nil {
			return err
		}
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            o.Spec.SecretName,
				Namespace:       o.Namespace,
				OwnerReferences: []metav1.OwnerReference{*kmeta.NewControllerRef(o)}},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				certificateKey:  serverKey,
				certificateCert: append(append(serverCert, '\n'), caCert...),
			},
		}
		_, err = r.client.CoreV1().Secrets(secret.Namespace).Create(secret)
		if err != nil {
			return err
		}
		o.Status.MarkReady()
		return nil
	} else if err != nil {
		logger.Error("Check secret error", zap.Error(err))
		return err
	} else {
		logger.Info("Certificate secret already exists")
		return nil
	}
}

func isValidSecret(ctx context.Context, o *v1alpha1.Certificate, secret *corev1.Secret) bool {
	// not implemented yet
	return true
}

func createSelfSignCert(ctx context.Context, o *v1alpha1.Certificate) (serverKey, serverCert, caCert []byte, err error) {

	logger := logging.FromContext(ctx)
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logger.Errorw("error generating random key", zap.Error(err))
		return nil, nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, nil, errors.New("failed to generate serial number: " + err.Error())
	}

	rootCert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   organization,
		},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootCert, rootCert, &rootKey.PublicKey, rootKey)
	if err != nil {
		logger.Errorw("error signing the CA cert", zap.Error(err))
		return nil, nil, nil, err
	}

	b := pem.Block{Type: "CERTIFICATE", Bytes: rootCertDER}
	caCert = pem.EncodeToMemory(&b)

	serverPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logger.Errorw("error generating random key", zap.Error(err))
		return nil, nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   organization,
		},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		BasicConstraintsValid: true,
		DNSNames:              o.Spec.DNSNames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, rootCert, &serverPrivateKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, err
	}

	b = pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	serverCert = pem.EncodeToMemory(&b)
	serverKey = pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPrivateKey),
	})
	return
}
