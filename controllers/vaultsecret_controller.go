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
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/90poe/vault-secrets-operator/pkg/config"
	"github.com/go-logr/logr"
	vaultapi "github.com/hashicorp/vault/api"
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
	"github.com/90poe/vault-secrets-operator/pkg/utils"
	"github.com/90poe/vault-secrets-operator/pkg/vault"
)

// VaultSecretReconciler reconciles a VaultSecret object
type VaultSecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Added variables
	vault *vault.Client
	ctx   context.Context
	// For test purposes
	VaultAPI   *vaultapi.Config
	AuthMethod string
	Log        logr.Logger
}

//+kubebuilder:rbac:groups=xo.90poe.io,resources=vaultsecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=xo.90poe.io,resources=vaultsecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=xo.90poe.io,resources=vaultsecrets/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the VaultSecret object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.7.0/pkg/reconcile
func (r *VaultSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, reterr error) {
	reqLogger := log.FromContext(r.ctx).WithValues("vaultsecret", req.NamespacedName)
	reqLogger.Info("Reconciling VaultSecret")

	// Fetch the VaultSecret instance
	instance := &xov1alpha1.VaultSecret{}
	err := r.Get(r.ctx, req.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return ctrl.Result{}, err
	}

	before := instance.DeepCopy()
	// Patch after every reconcile loop, if needed
	defer func() {
		err = utils.PatchVaultSecret(r.ctx, r.Client, before, instance)
		if err != nil {
			reterr = kerrors.NewAggregate([]error{reterr, err})
		}
	}()
	// General logic:
	// 1. Try to fetch controlled secret
	// 2. Insert CRD if not found and exit
	// 3. Update CRD if required
	// 4. Exit

	// Check if this Secret already exists
	found := &corev1.Secret{}
	err = r.Get(r.ctx, types.NamespacedName{
		Name:      instance.Spec.Name,
		Namespace: instance.Namespace,
	}, found)
	if err != nil && errors.IsNotFound(err) {
		// Create secret
		return r.createSecret(instance, found)
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// Update logic
	// First check if Type haven't changed. If it did - we need to re-create
	if found.Type != instance.Spec.Type {
		// Deleting old secret to recreate it
		return r.deleteSecret(instance, found)
	}

	// Normal update is required, without Type change
	return r.updateSecret(instance, found)
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	c := config.Get()
	skipVerify := c.VaultSkipVerify == "1"
	ctx, cancel := context.WithCancel(context.Background())

	logger := log.FromContext(r.ctx).WithValues("Vault.Addr", c.VaultAddr, "Vault.Role", c.VaultRole2Assume)
	authMethod := r.AuthMethod
	if len(authMethod) == 0 {
		authMethod = "aws"
	}
	vault, err := vault.New(
		vault.Config(r.VaultAPI),
		vault.Addr(c.VaultAddr, skipVerify),
		vault.Role(c.VaultRole2Assume),
		vault.SecretsPathPrefix(c.VaultSecretsPrefix),
		vault.Logger(logger),
		vault.AuthMethod(authMethod),
		vault.ContextWithCancelFN(ctx, cancel),
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
		For(&xov1alpha1.VaultSecret{}).
		Owns(&corev1.Secret{}).
		WithOptions(controller.Options{MaxConcurrentReconciles: c.MaxConcurrentReconciles}).
		Complete(r)
}

// createSecret will create new Secret in K8S
func (r *VaultSecretReconciler) createSecret(instance *xov1alpha1.VaultSecret,
	found *corev1.Secret) (reconcile.Result, error) {
	reqLogger := log.FromContext(r.ctx).WithName("Inserting")
	// Create secret
	// Add secrets from Vault to Secret object
	err := r.populateVaultSecret(instance, found)
	if err != nil {
		return r.setLatestError(instance, err)
	}
	// Set VaultSecret instance as the owner and controller
	reqLogger.V(1).Info(fmt.Sprintf("Setting controller reference on secret %s/%s",
		found.Namespace, found.Name))
	if err = controllerutil.SetControllerReference(instance,
		found, r.Scheme); err != nil {
		return r.setLatestError(instance, err)
	}
	reqLogger.V(1).Info("Creating a new Secret", "Secret.Namespace",
		found.Namespace, "Secret.Name", found.Name)
	err = r.Create(r.ctx, found)
	if err != nil {
		return r.setLatestError(instance, err)
	}
	// Secret created successfully
	reqLogger.Info("Inserted controlled secret",
		"Secret.Namespace", found.Namespace,
		"Secret.Name", found.Name)
	instance.Status.LastReadTime = time.Now().Unix()
	return r.succReconcileRet(instance, reqLogger), nil
}

func (r *VaultSecretReconciler) deleteSecret(instance *xov1alpha1.VaultSecret,
	found *corev1.Secret) (reconcile.Result, error) {
	reqLogger := log.FromContext(r.ctx).WithName("Deleting")
	// User have changed secret type - we need to delete old one and recreate it
	reqLogger.V(1).Info(fmt.Sprintf("Deleting old secret as type changed from '%s' to '%s'",
		found.Type, instance.Spec.Type),
		"Secret.Namespace", found.Namespace, "Secret.Name", found.Name)
	err := r.Delete(r.ctx, found)
	if err != nil {
		return r.setLatestError(instance, err)
	}
	reqLogger.Info("Secret deleted",
		"Secret.Namespace", found.Namespace, "Secret.Name", found.Name)
	// Lets create a new result by reconciling
	return ctrl.Result{
		Requeue:      true,
		RequeueAfter: 0,
	}, nil
}

func (r *VaultSecretReconciler) updateSecret(instance *xov1alpha1.VaultSecret,
	found *corev1.Secret) (reconcile.Result, error) {
	reqLogger := log.FromContext(r.ctx).WithName("Updating")
	// Normal update is required, without Type change
	patch := client.MergeFrom(found.DeepCopy())
	// Add secrets from Vault to Secret object
	err := r.populateVaultSecret(instance, found)
	if err != nil {
		return r.setLatestError(instance, err)
	}
	// Check what have changed
	changes, err := patch.Data(found)
	if err != nil {
		return r.setLatestError(instance, err)
	}
	// Check if something changed before updating
	if string(changes) == "{}" {
		// Update not required - lets skip it
		reqLogger.V(1).Info("Secret update is not required: secret haven't changed",
			"Secret.Namespace", found.Namespace,
			"Secret.Name", found.Name)
		return r.succReconcileRet(instance, reqLogger), nil
	}
	// Update is really required
	err = r.Patch(r.ctx, found, patch)
	if err != nil {
		reqLogger.Error(err, "can't update secret", "Secret.Namespace",
			found.Namespace, "Secret.Name", found.Name)
		return r.setLatestError(instance, err)
	}
	// Successfully updated
	instance.Status.LastReadTime = time.Now().Unix()
	reqLogger.Info("Secret updated", "Secret.Namespace",
		found.Namespace, "Secret.Name", found.Name)
	return r.succReconcileRet(instance, reqLogger), nil
}

// populateVaultSecret would get secrets from Vault, populate K8S secret and
// would return certificate serials (if any) and set finalizers if serials are found
func (r *VaultSecretReconciler) populateVaultSecret(instance *xov1alpha1.VaultSecret,
	found *corev1.Secret) error {
	// Add secrets from Vault to Secret object
	newData, err := r.getSecretsFromVault(instance)
	if err != nil {
		log.FromContext(r.ctx).Error(err, "can't read Secret(s) from Vault")
		return err
	}
	// Add ProvidedSecrets
	for key, value := range instance.Spec.ProvidedSecrets {
		newData[key] = []byte(value)
	}
	// Populate secret with data we require
	err = r.populateSecret(instance, found, newData)
	if err != nil {
		return err
	}
	return nil
}

func (r *VaultSecretReconciler) updateRequired(cr *xov1alpha1.VaultSecret) time.Duration {
	reDuration := time.Duration(cr.Spec.ReReadIntervals) * time.Second
	now := time.Now()
	if cr.Status.LastReadTime == 0 {
		cr.Status.LastReadTime = now.Unix()
	}
	lastReRead := time.Unix(cr.Status.LastReadTime, 0)
	fmt.Printf("lastReRead=%v\n", lastReRead)
	// Adding 1 sec so we are definitely after re-read time
	diff := lastReRead.Add(reDuration).Sub(now)
	if diff < 0 {
		cr.Status.LastReadTime = now.Unix()
		diff = time.Duration(cr.Spec.ReReadIntervals) * time.Second
	}
	return diff
}

// Function would always return reconcile with requeue and time to requeue
func (r *VaultSecretReconciler) succReconcileRet(cr *xov1alpha1.VaultSecret,
	reqLogger logr.Logger) reconcile.Result {
	diff := r.updateRequired(cr)
	// Adding 1 sec so we are definitely after re-read time
	diff += 1 * time.Second
	reqLogger.Info(fmt.Sprintf("Done reconcile. Re-read secret after %v at %v", diff,
		time.Now().Add(diff)), "Secret.Namespace", cr.Namespace,
		"Secret.Name", cr.Spec.Name)
	return ctrl.Result{
		RequeueAfter: diff,
	}
}

// getSecretsFromVault would fetch requered secrets from Vault
func (r *VaultSecretReconciler) getSecretsFromVault(cr *xov1alpha1.VaultSecret) (map[string][]byte, error) {
	data := make(map[string][]byte)
	// Get secrets from Vault
	for key, value := range cr.Spec.SecretsPaths {
		secValue, binary, err := r.vault.GetSecret(value)
		if err != nil {
			return nil, fmt.Errorf("can't make new Secret: %w", err)
		}
		if !binary {
			data[key] = []byte(secValue)
			continue
		}
		// Base64 Decode secret data as it's base64 encoded already
		secValueByte, err := base64.StdEncoding.DecodeString(secValue)
		if err != nil {
			return nil, fmt.Errorf("can't decode secret: %w", err)
		}
		data[key] = secValueByte
	}
	return data, nil
}

// populateSecret function would populate secret with data we require
func (r *VaultSecretReconciler) populateSecret(cr *xov1alpha1.VaultSecret,
	secret *corev1.Secret, data map[string][]byte) error {
	secret.ObjectMeta.Name = cr.Spec.Name
	secret.ObjectMeta.Namespace = cr.Namespace
	secret.Data = data
	secret.Type = cr.Spec.Type
	return nil
}

func (r *VaultSecretReconciler) setLatestError(cr *xov1alpha1.VaultSecret, err error) (reconcile.Result, error) {
	cr.Status.LatestError = fmt.Sprintf("%v", err)
	return ctrl.Result{}, err
}
