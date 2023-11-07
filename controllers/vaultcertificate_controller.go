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
	"reflect"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	xov1alpha1 "github.com/90poe/vault-secrets-operator/api/v1alpha1"
	"github.com/90poe/vault-secrets-operator/internal/certificates"
	"github.com/90poe/vault-secrets-operator/internal/config"
	"github.com/90poe/vault-secrets-operator/internal/consts"
	"github.com/90poe/vault-secrets-operator/internal/healthchecker"
	"github.com/90poe/vault-secrets-operator/internal/utils"
	"github.com/90poe/vault-secrets-operator/internal/vault"
	"github.com/90poe/vault-secrets-operator/internal/vaultclient"
	"github.com/go-logr/logr"
	vaultapi "github.com/hashicorp/vault/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
)

const (
	// Replace certificate 10min before it expires
	SecondsBeforeExpire = 600
	// RequeToWorkAfterH will have 48 hours in seconds
	RequeToWorkAfterH = 48 * 3600
)

// VaultCertificateReconciler reconciles a VaultCertificate object
type VaultCertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Added variables
	ctx   context.Context
	vault *vaultclient.Client
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
	r.Log = log.FromContext(ctx).WithValues("vaultcertificate", req.NamespacedName)
	r.ctx = ctx

	// Fetch the VaultCertificate instance
	instance := &xov1alpha1.VaultCertificate{}
	err := r.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			r.Log.V(1).Info("resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return ctrl.Result{}, err
	}

	before := instance.DeepCopy()
	defer func() {
		// Patch after every reconcile loop, if needed
		err = utils.PatchVaultCertificate(ctx, r.Client, before, instance)
		if err != nil {
			reterr = kerrors.NewAggregate([]error{reterr, err})
		}
	}()

	if r.upsertCN2AltNames(instance) {
		// we updated Alt names - lets re-run reconcile
		return ctrl.Result{
			Requeue: true,
		}, nil
	}

	// Check if this Secret already exists
	found := &corev1.Secret{}
	err = r.Get(ctx, types.NamespacedName{
		Name:      instance.Spec.Name,
		Namespace: instance.Namespace,
	}, found)
	if err != nil && errors.IsNotFound(err) {
		// Create secret
		return r.createCertificateSecret(instance, found, false)
	} else if err != nil {
		// some other error occured
		return ctrl.Result{}, err
	}

	// Update is required
	return r.updateCertificateSecret(instance, found)
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultCertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	c := config.Get()
	skipVerify := c.VaultSkipVerify == "1"

	logger := log.FromContext(context.TODO()).WithValues("Vault.Addr", c.VaultAddr, "Vault.Role", c.VaultRole2Assume)
	vaultInt, err := vault.New(
		c.VaultAddr,
		c.VaultRole2Assume,
		skipVerify,
		vault.Logger(logger),
	)
	if err != nil {
		return fmt.Errorf("can't get vault client interface: %w", err)
	}
	r.vault, err = vaultclient.New(
		vaultclient.VaultClient(vaultInt),
		vaultclient.SecretsPathPrefix(c.VaultSecretsPrefix),
		vaultclient.TLSCertsCachePath(c.VaultTLSCachePath),
		vaultclient.Logger(logger),
	)
	if err != nil {
		return fmt.Errorf("can't get vault client: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&xov1alpha1.VaultCertificate{}).
		Owns(&corev1.Secret{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: c.MaxConcurrentReconciles}).
		WithEventFilter(ignoreUpdateDeletePredicate()).
		Complete(r)
}

// ignoreUpdateDeletePredicater is brilliantly useful function, it will prevent multiple reconcile calls
func ignoreUpdateDeletePredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Ignore updates to CR status in which case metadata.Generation does not change
			genChanged := e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()
			return genChanged
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			// Evaluates to false if the object has been confirmed deleted.
			return !e.DeleteStateUnknown
		},
	}
}

// createSecret will create new Secret in K8S
func (r *VaultCertificateReconciler) createCertificateSecret(instance *xov1alpha1.VaultCertificate,
	found *corev1.Secret, update bool) (reconcile.Result, error) {
	// validate PKI path is known in our config
	if _, ok := config.Get().PKIs[instance.Spec.VaultPKIPath]; !ok {
		return r.setLatestError(instance, errors.NewBadRequest(fmt.Sprintf("unknown PKI path '%s', not found in config", instance.Spec.VaultPKIPath)), consts.UnrecoverableError)
	}

	var cert *certificates.Certificate
	var err error
	if !update {
		// try to get certificate from cache
		cert, err = r.fetchCertFromCache(instance)
		if err != nil {
			r.Log.V(1).Info(fmt.Sprintf("missed cache (ignoring it), reason: %v", err))
			cert = nil
		}
	}
	if cert == nil {
		if instance.Spec.ManualCreateSecret {
			return r.setLatestError(instance, errors.NewBadRequest("ManualCreateSecret is set, but cert not found in cache - please add it"), consts.UnrecoverableError)
		}
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
	r.Log.V(1).Info(fmt.Sprintf("Setting controller reference on secret %s/%s",
		found.Namespace, found.Name))
	if err = controllerutil.SetControllerReference(instance,
		found, r.Scheme); err != nil {
		return r.setLatestError(instance, err, consts.RecoverableError)
	}
	r.Log.V(1).Info("Creating a new Secret", "Secret.Namespace",
		found.Namespace, "Secret.Name", found.Name)
	err = r.Create(r.ctx, found)
	if err != nil {
		return r.setLatestError(instance, err, consts.RecoverableError)
	}
	// Secret created successfully
	// check if AltNames has CN in them
	r.Log.V(0).Info("Inserted controlled secret",
		"Secret.Namespace", found.Namespace,
		"Secret.Name", found.Name)
	instance.Status.CertValidUntil = metav1.NewTime(cert.ValidUntil)
	message := "successfully created"
	if update {
		message = "succesfully updated"
	}
	// Add PKI AutoTidy - several invocations will not hurt
	err = r.vault.PKIAutoTidy(instance.Spec.VaultPKIPath)
	if err != nil {
		r.Log.V(1).Info(fmt.Sprintf("PKI AutoTidy failed: %v", err))
	}
	return r.succReconcileRet(instance, message)
}

// upsertCN2AltNames will add CN to ALTNames if it's not there.
// It will return true if it added CN.
func (r *VaultCertificateReconciler) upsertCN2AltNames(instance *xov1alpha1.VaultCertificate) bool {
	found := false
	for _, dnsName := range instance.Spec.AltNames {
		if dnsName == instance.Spec.CommonName {
			found = true
			break
		}
	}
	if !found {
		instance.Spec.AltNames = append(instance.Spec.AltNames, instance.Spec.CommonName)
	}
	return !found
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
		// all vault related issues are fatal
		healthchecker.SetOperatorStatusError(err)
		return nil, err
	}
	// Put to cache
	err = r.vault.PutToCache(instance.Spec.VaultPKIPath, cert.CommonName, cert)
	if err != nil {
		// Ignore if we couln't add it to cache, but inform
		r.Log.V(1).Info(err.Error())
	}
	return cert, nil
}

// fetchCert will fetch certificate from and sign certificate
func (r *VaultCertificateReconciler) fetchCertFromCache(
	instance *xov1alpha1.VaultCertificate,
) (*certificates.Certificate, error) {
	cert, key, ca, err := r.vault.GetCertFromCache(instance.Spec.VaultPKIPath, instance.Spec.CommonName)
	if err != nil {
		// all vault related issues are fatal
		healthchecker.SetOperatorStatusError(err)
		return nil, err
	}
	crl, err := r.vault.GetCRL(instance.Spec.VaultPKIPath)
	if err != nil {
		// all vault related issues are fatal
		healthchecker.SetOperatorStatusError(err)
		return nil, err
	}
	retCert, err := certificates.GetCertificateFromPem(cert, key, ca, crl)
	if err != nil {
		var invalid *certificates.CertificateInvalid
		if coreErrors.As(err, &invalid) {
			// delete invalid cert from cache
			err2 := r.vault.DelCertFromCache(config.Get().PKIs[instance.Spec.VaultPKIPath], instance.Spec.CommonName)
			if err2 != nil {
				// error occurred deleting from cache - inform only
				r.Log.V(1).Info(err2.Error())
			}
		}
		return nil, err
	}
	return retCert, nil
}

// deleteSecretIfRequired will delete secret if it's required
func (r *VaultCertificateReconciler) recreateIsRequired(
	instance *xov1alpha1.VaultCertificate,
	found *corev1.Secret,
) (bool, error) {
	// First check if Type haven't changed. If it did - we need to re-create
	if found.Type != instance.Spec.Type {
		r.Log.V(1).Info(fmt.Sprintf("secret type changed from '%s' to '%s'", found.Type, instance.Spec.Type))
		return r.deleteSecretIsRequired(true, found)
	}

	// Also check if cert has not expired, then we also need to re-create
	timeNow := metav1.NewTime(time.Now().Add(-SecondsBeforeExpire))
	if instance.Status.CertValidUntil.Before(&timeNow) {
		r.Log.V(1).Info(fmt.Sprintf("certificate expire at %v", timeNow))
		return r.deleteSecretIsRequired(true, found)
	}
	// check if certificate requirements have changed
	oldCert, err := certificates.LoadCertPair(found.Data["tls.crt"], found.Data["tls.key"])
	if err != nil {
		return true, err
	}
	if oldCert.Leaf.Subject.CommonName != instance.Spec.CommonName {
		r.Log.V(1).Info(fmt.Sprintf("common name changed from '%s' to '%s'", oldCert.Leaf.Subject.CommonName, instance.Spec.CommonName))
		return r.deleteSecretIsRequired(true, found)
	}
	if !reflect.DeepEqual(oldCert.Leaf.DNSNames, instance.Spec.AltNames) {
		r.Log.V(1).Info(fmt.Sprintf("alt names changed from '%v' to '%v'", oldCert.Leaf.DNSNames, instance.Spec.AltNames))
		return r.deleteSecretIsRequired(true, found)
	}

	oldType, oldLength, err := certificates.GetPrivateKeyTypeAndBitLenght(oldCert)
	if err != nil {
		return true, err
	}
	// check if private key type changed
	if instance.Spec.KeyType != strings.ToLower(oldType) {
		r.Log.V(1).Info(fmt.Sprintf("private key type changed from '%s' to '%s'", strings.ToLower(oldType), instance.Spec.KeyType))
		return r.deleteSecretIsRequired(true, found)
	}

	// check if bit lenghts for private key changed
	if instance.Spec.KeyType == consts.CertTypeRSA {
		if instance.Spec.KeyLength != uint(oldLength) {
			r.Log.V(1).Info(fmt.Sprintf("RSA private key bit lenght changed from '%v' to '%v'", uint(oldLength), instance.Spec.KeyLength))
			return r.deleteSecretIsRequired(true, found)
		}
	}
	if instance.Spec.KeyType == consts.CertTypeECDCA {
		if instance.Spec.ECDSACurve == strings.ToLower(fmt.Sprintf("p%v", oldLength)) {
			r.Log.V(1).Info(fmt.Sprintf("ECDSA private key bit lenght changed from '%v' to '%v'", uint(oldLength), instance.Spec.KeyLength))
			return r.deleteSecretIsRequired(true, found)
		}
	}

	return false, nil
}

// deleteSecret will delete secret it takes required bool to have similar output type
// as recreateIsRequired function, as it allows to return early
func (r *VaultCertificateReconciler) deleteSecretIsRequired(req bool, found *corev1.Secret) (bool, error) {
	err := r.Delete(r.ctx, found)
	if err != nil {
		return req, fmt.Errorf("can't delete secret %s/%s", found.Namespace, found.Name)
	}
	r.Log.V(1).Info("Secret deleted",
		"Secret.Namespace", found.Namespace, "Secret.Name", found.Name)
	return req, nil
}

// we are going to recreate Cert and secret if it's required, otherways just reconcile before cert expiration
func (r *VaultCertificateReconciler) updateCertificateSecret(
	instance *xov1alpha1.VaultCertificate,
	found *corev1.Secret,
) (reconcile.Result, error) {
	required, err := r.recreateIsRequired(instance, found)
	if err != nil {
		return r.setLatestError(instance, err, consts.UnrecoverableError)
	}
	if required {
		// we recreating secret and old on is gone already
		return r.createCertificateSecret(instance, &corev1.Secret{}, true)
	}
	return r.succReconcileRet(instance, "no updates during reconcile were required")
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
		Status:             metav1.ConditionTrue,
		Reason:             errType,
		Message:            fmt.Sprintf("%v", err),
	}
	cr.Status.Condition = condition
	r.Log.V(1).Error(err, "Error during reconcile", "Secret.Namespace", cr.Namespace, "Secret.Name", cr.Spec.Name)
	return ctrl.Result{}, nil
}

// Function would always return reconcile with requeue and time to requeue
func (r *VaultCertificateReconciler) succReconcileRet(cr *xov1alpha1.VaultCertificate,
	message string) (reconcile.Result, error) {
	diff := r.updateRequiredAt(cr)
	r.Log.V(1).Info(fmt.Sprintf("we will require reconcyle after %v hours", diff.Hours()))
	condition := metav1.Condition{
		Type:               "Success",
		LastTransitionTime: metav1.NewTime(time.Now()),
		Status:             metav1.ConditionTrue,
		Reason:             consts.SuccessReconcile,
		Message:            message,
	}
	cr.Status.Condition = condition
	r.Log.V(0).Info(fmt.Sprintf("Done reconcile of certificate cn='%s'. Reconcyle certificate after %v at %v",
		cr.Spec.Name,
		diff, time.Now().Add(diff)), "Secret.Namespace", cr.Namespace,
		"Secret.Name", cr.Spec.Name)
	return ctrl.Result{
		RequeueAfter: diff,
	}, nil
}

// updateRequired will check when certificate re-create is required
func (r *VaultCertificateReconciler) updateRequiredAt(cr *xov1alpha1.VaultCertificate) time.Duration {
	// We will use unix timestamp for compare
	diff := (cr.Status.CertValidUntil.Unix() - SecondsBeforeExpire) - time.Now().Unix()
	if diff < 0 {
		diff = 0
	}
	// Is requeue larger than 48 hours?
	if diff > RequeToWorkAfterH {
		// we will reque after 48 hours
		diff = RequeToWorkAfterH
	}
	return time.Duration(diff) * time.Second
}
