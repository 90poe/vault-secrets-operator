package vaultsecret

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	xov1alpha1 "github.com/90poe/vault-secrets-operator/pkg/apis/xo/v1alpha1"
	"github.com/90poe/vault-secrets-operator/pkg/config"
	"github.com/90poe/vault-secrets-operator/pkg/utils"
	"github.com/90poe/vault-secrets-operator/pkg/vault"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_vaultsecret")

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new VaultSecret Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	c := config.Get()
	skipVerify := c.VaultSkipVerify == "1"
	ctx, cancel := context.WithCancel(context.Background())

	vault, err := vault.New(
		vault.Addr(c.VaultAddr, skipVerify),
		vault.Role(c.VaultRole2Assume),
		vault.SecretsPathPrefix(c.VaultSecretsPrefix),
		vault.Logger(log.WithValues("Vault.Addr", c.VaultAddr, "Vault.Role", c.VaultRole2Assume)),
		vault.ContextWithCancelFN(ctx, cancel),
	)
	if err != nil {
		log.Error(err, "can't get vault client")
		return nil
	}
	go func() {
		<-ctx.Done()
		log.Info("Fatal error occured, exiting")
		os.Exit(1)
	}()
	return &ReconcileVaultSecret{
		client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
		vault:  vault,
		ctx:    ctx,
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("vaultsecret-controller", mgr,
		controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource VaultSecret
	err = c.Watch(&source.Kind{Type: &xov1alpha1.VaultSecret{}},
		&handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Pods and requeue the owner VaultSecret
	err = c.Watch(&source.Kind{Type: &corev1.Pod{}},
		&handler.EnqueueRequestForOwner{
			IsController: true,
			OwnerType:    &xov1alpha1.VaultSecret{},
		})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcileVaultSecret implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileVaultSecret{}

// ReconcileVaultSecret reconciles a VaultSecret object
type ReconcileVaultSecret struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
	//Added variables
	vault *vault.Client
	ctx   context.Context
	log   logr.Logger
}

// Reconcile reads that state of the cluster for a VaultSecret object and makes changes based on the state read
// and what is in the VaultSecret.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileVaultSecret) Reconcile(request reconcile.Request) (_ reconcile.Result, reterr error) {
	r.log = log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	r.log.Info("Reconciling VaultSecret")

	// Fetch the VaultSecret instance
	instance := &xov1alpha1.VaultSecret{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	before := instance.DeepCopyObject()
	// instancePatch := client.MergeFrom(instance.DeepCopy())
	// Patch after every reconcile loop, if needed
	defer func() {
		err = utils.Patch(r.ctx, r.client, before, instance)
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
	err = r.client.Get(r.ctx, types.NamespacedName{
		Name:      instance.Spec.Name,
		Namespace: instance.Namespace,
	}, found)
	if err != nil && errors.IsNotFound(err) {
		// Create secret
		return r.createSecret(instance, found)
	} else if err != nil {
		return reconcile.Result{}, err
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

// createSecret will create new Secret in K8S
func (r *ReconcileVaultSecret) createSecret(instance *xov1alpha1.VaultSecret,
	found *corev1.Secret) (reconcile.Result, error) {
	reqLogger := r.log.WithName("Inserting")
	// Create secret
	// Add secrets from Vault to Secret object
	err := r.populateVaultSecret(instance, found)
	if err != nil {
		return r.setLatestError(instance, err)
	}
	// Set VaultSecret instance as the owner and controller
	reqLogger.V(1).Info(fmt.Sprintf("Setting controller reference on secret %s/%s",
		found.Namespace, found.Name))
	if err := controllerutil.SetControllerReference(instance,
		found, r.scheme); err != nil {
		return r.setLatestError(instance, err)
	}
	reqLogger.V(1).Info("Creating a new Secret", "Secret.Namespace",
		found.Namespace, "Secret.Name", found.Name)
	err = r.client.Create(r.ctx, found)
	if err != nil {
		return r.setLatestError(instance, err)
	}
	// Secret created successfully
	log.Info("Inserted controlled secret",
		"Secret.Namespace", found.Namespace,
		"Secret.Name", found.Name)
	instance.Status.LastReadTime = time.Now().Unix()
	return r.succReconcileRet(instance, reqLogger), nil
}

func (r *ReconcileVaultSecret) deleteSecret(instance *xov1alpha1.VaultSecret,
	found *corev1.Secret) (reconcile.Result, error) {
	reqLogger := r.log.WithName("Deleting")
	// User have changed secret type - we need to delete old one and recreate it
	reqLogger.V(1).Info(fmt.Sprintf("Deleting old secret as type changed from '%s' to '%s'",
		found.Type, instance.Spec.Type),
		"Secret.Namespace", found.Namespace, "Secret.Name", found.Name)
	err := r.client.Delete(r.ctx, found)
	if err != nil {
		return r.setLatestError(instance, err)
	}
	reqLogger.Info("Secret deleted",
		"Secret.Namespace", found.Namespace, "Secret.Name", found.Name)
	// Lets create a new result by reconciling
	return reconcile.Result{
		Requeue:      true,
		RequeueAfter: 0,
	}, nil
}

func (r *ReconcileVaultSecret) updateSecret(instance *xov1alpha1.VaultSecret,
	found *corev1.Secret) (reconcile.Result, error) {
	reqLogger := r.log.WithName("Updating")
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
	err = r.client.Patch(r.ctx, found, patch)
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
func (r *ReconcileVaultSecret) populateVaultSecret(instance *xov1alpha1.VaultSecret,
	found *corev1.Secret) error {
	// Add secrets from Vault to Secret object
	newData, err := r.getSecretsFromVault(instance)
	if err != nil {
		r.log.Error(err, "can't read Secret(s) from Vault")
		return err
	}
	// Populate secret with data we require
	err = r.populateSecret(instance, found, newData)
	if err != nil {
		return err
	}
	return nil
}

func (r *ReconcileVaultSecret) updateRequired(cr *xov1alpha1.VaultSecret) (bool, time.Duration) {
	reDuration := time.Duration(cr.Spec.ReReadIntervals) * time.Second
	now := time.Now()
	if cr.Status.LastReadTime == 0 {
		cr.Status.LastReadTime = now.Unix()
	}
	lastReRead := time.Unix(cr.Status.LastReadTime, 0)
	// Adding 1 sec so we are definitely after re-read time
	diff := lastReRead.Add(reDuration).Sub(now)
	updateReq := diff < 0
	if updateReq {
		cr.Status.LastReadTime = now.Unix()
		diff = time.Duration(cr.Spec.ReReadIntervals) * time.Second
	}
	return updateReq, diff
}

//Function would always return reconcile with requeue and time to requeue
func (r *ReconcileVaultSecret) succReconcileRet(cr *xov1alpha1.VaultSecret,
	reqLogger logr.Logger) reconcile.Result {
	_, diff := r.updateRequired(cr)
	// Adding 1 sec so we are definitely after re-read time
	diff = diff + 1*time.Second
	reqLogger.Info(fmt.Sprintf("Done reconcile. Re-read secret after %v at %v", diff,
		time.Now().Add(diff)), "Secret.Namespace", cr.Namespace,
		"Secret.Name", cr.Spec.Name)
	return reconcile.Result{
		Requeue:      true,
		RequeueAfter: diff,
	}
}

// getSecretsFromVault would fetch requered secrets from Vault
func (r *ReconcileVaultSecret) getSecretsFromVault(cr *xov1alpha1.VaultSecret) (map[string][]byte, error) {
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
func (r *ReconcileVaultSecret) populateSecret(cr *xov1alpha1.VaultSecret,
	secret *corev1.Secret, data map[string][]byte) error {
	secret.ObjectMeta.Name = cr.Spec.Name
	secret.ObjectMeta.Namespace = cr.Namespace
	secret.Data = data
	secret.Type = cr.Spec.Type
	return nil
}

func (r *ReconcileVaultSecret) setLatestError(cr *xov1alpha1.VaultSecret, err error) (reconcile.Result, error) {
	cr.Status.LatestError = fmt.Sprintf("%v", err)
	return reconcile.Result{}, err
}
