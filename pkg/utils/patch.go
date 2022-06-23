package utils

import (
	"context"
	"reflect"

	xov1alpha1 "github.com/90poe/vault-secrets-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Patch would patch runtime Object
func PatchVaultSecret(ctx context.Context, cl client.Client, before *xov1alpha1.VaultSecret, after *xov1alpha1.VaultSecret) error {
	resBef := before.DeepCopy()
	statBef := before.DeepCopy()
	resourcePatch := client.MergeFrom(resBef)
	statusPatch := client.MergeFrom(statBef)
	// Convert resources to unstructured for easier comparison
	beforeUnstructured, err := runtime.DefaultUnstructuredConverter.ToUnstructured(before)
	if err != nil {
		return err
	}
	afterUnstructured, err := runtime.DefaultUnstructuredConverter.ToUnstructured(after)
	if err != nil {
		return err
	}

	beforeHasStatus := false
	afterHasStatus := false
	// Attempt to remove the status for easier comparison
	beforeStatus, ok, err := unstructured.NestedFieldCopy(beforeUnstructured, "status")
	if err != nil {
		return err
	}
	if ok {
		beforeHasStatus = true
		// Remove status from object so they can be patched separately
		unstructured.RemoveNestedField(beforeUnstructured, "status")
	}
	afterStatus, ok, err := unstructured.NestedFieldCopy(afterUnstructured, "status")
	if err != nil {
		return err
	}
	if ok {
		afterHasStatus = true
		// Remove status from object so they can patched separately
		unstructured.RemoveNestedField(afterUnstructured, "status")
	}

	var errs []error

	// Check if there's any difference to patch
	if !reflect.DeepEqual(beforeUnstructured, afterUnstructured) {
		err = cl.Patch(ctx, after, resourcePatch)
		if err != nil {
			errs = append(errs, err)
		}
	}

	// Check if there's any difference in status to patch
	if (beforeHasStatus || afterHasStatus) && !reflect.DeepEqual(beforeStatus, afterStatus) {
		err = cl.Status().Patch(ctx, after, statusPatch)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.NewAggregate(errs)
}
