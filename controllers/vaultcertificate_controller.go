/*
Copyright 2021.

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

package controllers

import (
	"context"
	coreErrors "errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	xov1alpha1 "github.com/90poe/vault-secrets-operator/api/v1alpha1"
	"github.com/90poe/vault-secrets-operator/pkg/certificates"
	"github.com/90poe/vault-secrets-operator/pkg/config"
	"github.com/90poe/vault-secrets-operator/pkg/consts"
	"github.com/90poe/vault-secrets-operator/pkg/utils"
	"github.com/90poe/vault-secrets-operator/pkg/vault"
	"github.com/90poe/vault-secrets-operator/pkg/vaultclient"
	"github.com/go-logr/logr"
	vaultapi "github.com/hashicorp/vault/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Replace certificate 1min before it expires
	SecondsBeforeExpire = time.Second * 60
)

// VaultCertificateReconciler reconciles a VaultCertificate object
type VaultCertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Added variables
	vault *vaultclient.Client
	ctx   context.Context
	// For test purposes
	VaultAPI   *vaultapi.Config
	AuthMethod string
	Log        logr.Logger
}

//+kubebuilder:rbac:groups=xo.90poe.io,resources=vaultcertificates,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=xo.90poe.io,resources=vaultcertificates/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=xo.90poe.io,resources=vaultcertificates/finalizers,verbs=update

// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *VaultCertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, reterr error) {
	// Will implement logic:
	// 1. Check if we don't have Secret in cluster.
	// 2. If we don't - create it
	// 3. If we do - update it, which will check if we need to re-create secret
	reqLogger := log.FromContext(r.ctx).WithValues("vaultcertificate", req.NamespacedName)

	// Fetch the VaultCertificate instance
	instance := &xov1alpha1.VaultCertificate{}
	err := r.Get(r.ctx, req.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			reqLogger.Info("object deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return ctrl.Result{}, err
	}

	if len(instance.Status.Conditions) > 0 {
		// decide if we should stop reconcile and exit immediately
		if ret, stop := r.decideToStopReconcilation(instance); stop {
			return ret, nil
		}
	}

	reqLogger.Info("Reconciling VaultCertificate")

	before := instance.DeepCopy()
	defer func() {
		// Patch after every reconcile loop, if needed
		err = utils.PatchVaultCertificate(r.ctx, r.Client, before, instance)
		if err != nil {
			reterr = kerrors.NewAggregate([]error{reterr, err})
		}
	}()

	// Check if this Secret already exists
	found := &corev1.Secret{}
	err = r.Get(r.ctx, types.NamespacedName{
		Name:      instance.Spec.Name,
		Namespace: instance.Namespace,
	}, found)
	if err != nil && errors.IsNotFound(err) {
		// Create secret
		return r.createSecret(instance, found, false)
	} else if err != nil {
		// some other error occured
		return ctrl.Result{}, err
	}

	// Update is required
	return r.updateSecret(instance, found)
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultCertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	c := config.Get()
	skipVerify := c.VaultSkipVerify == "1"
	ctx, cancel := context.WithCancel(context.Background())

	logger := log.FromContext(r.ctx).WithValues("Vault.Addr", c.VaultAddr, "Vault.Role", c.VaultRole2Assume)
	vaultInt, err := vault.New(
		c.VaultAddr,
		c.VaultRole2Assume,
		skipVerify,
		vault.ContextWithCancelFN(ctx, cancel),
		vault.Logger(logger),
	)
	if err != nil {
		logger.Error(err, "can't get vault client interface")
		return nil
	}
	vault, err := vaultclient.New(
		vaultclient.VaultClient(vaultInt),
		vaultclient.SecretsPathPrefix(c.VaultSecretsPrefix),
		vaultclient.ContextWithCancelFN(ctx, cancel),
		vaultclient.Logger(logger),
	)
	if err != nil {
		logger.Error(err, "can't get vault client")
		return nil
	}
	go func() {
		<-ctx.Done()
		logger.Info("Fatal error occured, exiting")
		os.Exit(1)
	}()
	r.vault = vault
	r.ctx = ctx
	return ctrl.NewControllerManagedBy(mgr).
		For(&xov1alpha1.VaultCertificate{}).
		Owns(&corev1.Secret{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: c.MaxConcurrentReconciles}).
		Complete(r)
}

// decideToStopReconcilation will decide if we should stop reconcile and with what output
// It will return either empty result and stop or continue bool (true or false)
func (r *VaultCertificateReconciler) decideToStopReconcilation(instance *xov1alpha1.VaultCertificate) (reconcile.Result, bool) {
	if instance.Status.Conditions[len(instance.Status.Conditions)-1].Reason == consts.RecoverableError {
		// Return and requeue after 1 hour
		return ctrl.Result{
			Requeue:      true,
			RequeueAfter: 1 * time.Hour,
		}, false
	}
	if instance.Status.Conditions[len(instance.Status.Conditions)-1].Reason == consts.SuccessReconcile {
		after := time.Now().After(instance.Status.Conditions[len(instance.Status.Conditions)-1].LastTransitionTime.Add(2 * time.Second))
		// if last condition is success, check if it was more than 2 seconds ago
		if after {
			// it was more than 2 seconds ago - it must be delete or update, don't stop
			return ctrl.Result{}, false
		}
	}
	return ctrl.Result{}, true
}

// createSecret will create new Secret in K8S
func (r *VaultCertificateReconciler) createSecret(instance *xov1alpha1.VaultCertificate,
	found *corev1.Secret, force bool) (reconcile.Result, error) {
	// validate PKI path is known in our config
	if _, ok := config.Get().PKIs[instance.Spec.VaultPKIPath]; !ok {
		return r.setLatestError(instance, errors.NewBadRequest(fmt.Sprintf("unknown PKI path '%s', not found in config", instance.Spec.VaultPKIPath)), consts.UnrecoverableError)
	}
	reqLogger := log.FromContext(r.ctx).WithName("Inserting Certificate Secret")

	var cert *certificates.Certificate
	var err error
	if !force {
		// try to get certificate from cache
		cert, err = r.fetchCert(instance)
		if err != nil {
			var cacheMiss *vaultclient.CacheMiss
			if coreErrors.As(err, &cacheMiss) {
				reqLogger.V(1).Info("%v", cacheMiss)
			} else {
				reqLogger.V(1).Info("error occured while fetching from cache - ignoring: %v", err)
			}
			cert = nil
		}
	}
	if cert == nil {
		// create certificate and sign it
		cert, err = r.createCert(instance)
		if err != nil {
			return r.setLatestError(instance, err, consts.RecoverableError)
		}
	}
	// Update VaultCertificate
	instance.Status.CertValidUntil = metav1.NewTime(cert.ValidUntil)

	// Fill in secret
	found.Name = instance.Spec.Name
	found.Namespace = instance.Namespace
	found.Type = instance.Spec.Type
	found.Data = map[string][]byte{
		"ca.crt":  []byte(cert.IssuingCA),
		"tls.crt": []byte(cert.PemCert),
		"tls.key": []byte(cert.PemKey),
	}

	// Set VaultSecret instance as the owner and controller
	reqLogger.V(1).Info(fmt.Sprintf("Setting controller reference on secret %s/%s",
		found.Namespace, found.Name))
	if err = controllerutil.SetControllerReference(instance,
		found, r.Scheme); err != nil {
		return r.setLatestError(instance, err, consts.RecoverableError)
	}
	reqLogger.V(1).Info("Creating a new Secret", "Secret.Namespace",
		found.Namespace, "Secret.Name", found.Name)
	err = r.Create(r.ctx, found)
	if err != nil {
		return r.setLatestError(instance, err, consts.RecoverableError)
	}
	// Secret created successfully
	reqLogger.Info("Inserted controlled secret",
		"Secret.Namespace", found.Namespace,
		"Secret.Name", found.Name)
	instance.Status.CertValidUntil = metav1.NewTime(cert.ValidUntil)
	return r.succReconcileRet(instance, reqLogger)
}

// createCert will create and sign certificate
func (r *VaultCertificateReconciler) createCert(instance *xov1alpha1.VaultCertificate) (*certificates.Certificate, error) {
	// Create new certificate for signing
	currTime := time.Now()
	cert, err := certificates.New(instance.Spec.CommonName,
		instance.Spec.KeyType,
		int(instance.Spec.KeyLength),
		certificates.ValidUntil(currTime.Add(time.Duration(instance.Spec.CertTTL)*time.Second)),
		certificates.ECDSACurve(instance.Spec.ECDSACurve),
		certificates.AltNames(instance.Spec.AltNames),
	)
	if err != nil {
		return nil, err
	}
	err = cert.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	// Sign certificate
	cert, err = r.vault.GetSignedCertificate(instance.Spec.VaultPKIPath, config.Get().PKIs[instance.Spec.VaultPKIPath], cert)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// fetchCert will fetch certificate from and sign certificate
func (r *VaultCertificateReconciler) fetchCert(instance *xov1alpha1.VaultCertificate) (*certificates.Certificate, error) {
	cert, key, ca, err := r.vault.GetCertFromCache(config.Get().PKIs[instance.Spec.VaultPKIPath], instance.Spec.CommonName)
	if err != nil {
		return nil, err
	}
	crl, err := r.vault.GetCRL(config.Get().PKIs[instance.Spec.VaultPKIPath])
	if err != nil {
		return nil, err
	}
	retCert, err := certificates.GetCertificateFromPem(cert, key, ca, crl)
	if err != nil {
		return nil, err
	}
	return retCert, nil
}

// deleteSecretIfRequired will delete secret if it's required
func (r *VaultCertificateReconciler) recreateIsRequired(
	instance *xov1alpha1.VaultCertificate,
	found *corev1.Secret,
) (bool, error) {
	reqLogger := log.FromContext(r.ctx).WithName("Deleting Certificate Secret")
	// First check if Type haven't changed. If it did - we need to re-create
	if found.Type != instance.Spec.Type {
		reqLogger.V(1).Info(fmt.Sprintf("secret type changed from '%s' to '%s'", found.Type, instance.Spec.Type))
		return r.deleteSecretIsRequired(true, found)
	}

	// Also check if cert has not expired, then we also need to re-create
	timeNow := metav1.NewTime(time.Now().Add(-SecondsBeforeExpire))
	if !instance.Status.CertValidUntil.Before(&timeNow) {
		reqLogger.V(1).Info(fmt.Sprintf("certificate expire at %v", timeNow))
		return r.deleteSecretIsRequired(true, found)
	}
	// check if certificate requirements have changed
	oldCert, err := certificates.LoadCertPair(found.Data["tls.crt"], found.Data["tls.key"])
	if err != nil {
		return true, err
	}
	if oldCert.Leaf.Subject.CommonName != instance.Spec.CommonName {
		reqLogger.V(1).Info(fmt.Sprintf("common name changed from '%s' to '%s'", oldCert.Leaf.Subject.CommonName, instance.Spec.CommonName))
		return r.deleteSecretIsRequired(true, found)
	}
	if !reflect.DeepEqual(oldCert.Leaf.DNSNames, instance.Spec.AltNames) {
		reqLogger.V(1).Info(fmt.Sprintf("alt names changed from '%v' to '%v'", oldCert.Leaf.DNSNames, instance.Spec.AltNames))
		return r.deleteSecretIsRequired(true, found)
	}

	oldType, oldLength, err := certificates.GetPrivateKeyTypeAndBitLenght(oldCert)
	if err != nil {
		return true, err
	}
	// check if private key type changed
	if instance.Spec.KeyType != strings.ToLower(oldType) {
		reqLogger.V(1).Info(fmt.Sprintf("private key type changed from '%s' to '%s'", strings.ToLower(oldType), instance.Spec.KeyType))
		return r.deleteSecretIsRequired(true, found)
	}

	// check if bit lenghts for private key changed
	if instance.Spec.KeyType == consts.CertTypeRSA {
		if instance.Spec.KeyLength != uint(oldLength) {
			reqLogger.V(1).Info(fmt.Sprintf("RSA private key bit lenght changed from '%v' to '%v'", uint(oldLength), instance.Spec.KeyLength))
			return r.deleteSecretIsRequired(true, found)
		}
	}
	if instance.Spec.KeyType == consts.CertTypeECDCA {
		if instance.Spec.ECDSACurve == strings.ToLower(fmt.Sprintf("p%v", oldLength)) {
			reqLogger.V(1).Info(fmt.Sprintf("ECDSA private key bit lenght changed from '%v' to '%v'", uint(oldLength), instance.Spec.KeyLength))
			return r.deleteSecretIsRequired(true, found)
		}
	}

	return false, nil
}

// deleteSecret will delete secret it takes required bool to have similar output type
// as recreateIsRequired function, as it allows to return early
func (r *VaultCertificateReconciler) deleteSecretIsRequired(req bool, found *corev1.Secret) (bool, error) {
	reqLogger := log.FromContext(r.ctx).WithName("Deleting Certificate Secret")
	err := r.Delete(r.ctx, found)
	if err != nil {
		return req, fmt.Errorf("can't delete secret %s/%s", found.Namespace, found.Name)
	}
	reqLogger.V(1).Info("Secret deleted",
		"Secret.Namespace", found.Namespace, "Secret.Name", found.Name)
	return req, nil
}

// we are going to recreate Cert and secret if it's required, otherways just reconcile before cert expiration
func (r *VaultCertificateReconciler) updateSecret(
	instance *xov1alpha1.VaultCertificate,
	found *corev1.Secret,
) (reconcile.Result, error) {
	reqLogger := log.FromContext(r.ctx).WithName("Updating Certificate Secret")
	required, err := r.recreateIsRequired(instance, found)
	if err != nil {
		return r.setLatestError(instance, err, consts.UnrecoverableError)
	}
	if required {
		return r.createSecret(instance, found, true)
	}
	return r.succReconcileRet(instance, reqLogger)
}

// setLatestError will set latest error on condition
func (r *VaultCertificateReconciler) setLatestError(
	cr *xov1alpha1.VaultCertificate,
	err error,
	errType string,
) (reconcile.Result, error) {
	condition := metav1.Condition{
		Type:               "Error",
		LastTransitionTime: metav1.NewTime(time.Now()),
		Status:             "True",
		Reason:             errType,
		Message:            fmt.Sprintf("%v", err),
	}
	cr.Status.Conditions = append(cr.Status.Conditions, condition)
	return ctrl.Result{}, err
}

// Function would always return reconcile with requeue and time to requeue
func (r *VaultCertificateReconciler) succReconcileRet(cr *xov1alpha1.VaultCertificate,
	reqLogger logr.Logger) (reconcile.Result, error) {
	diff := r.updateRequiredAt(cr)
	condition := metav1.Condition{
		Type:               "Success",
		LastTransitionTime: metav1.NewTime(time.Now()),
		Status:             "True",
		Reason:             consts.SuccessReconcile,
		Message:            "Reconcile was successful",
	}
	cr.Status.Conditions = append(cr.Status.Conditions, condition)
	reqLogger.Info(fmt.Sprintf("Done reconcile of certificate cn='%s'. Re-create certificate after %v at %v",
		cr.Spec.Name,
		diff, time.Now().Add(diff)), "Secret.Namespace", cr.Namespace,
		"Secret.Name", cr.Spec.Name)
	return ctrl.Result{
		Requeue:      true,
		RequeueAfter: diff,
	}, nil
}

// updateRequired will check when certificate re-create is required
func (r *VaultCertificateReconciler) updateRequiredAt(cr *xov1alpha1.VaultCertificate) time.Duration {
	diff := time.Until(cr.Status.CertValidUntil.Time) - SecondsBeforeExpire
	if diff < 0 {
		diff = 0
	}
	return diff
}
