.PHONY: install
install:
	kubectl apply -f service_account.yaml
	kubectl apply -f role.yaml
	kubectl apply -f role_binding.yaml
	kubectl apply -f clusterrole.yaml
	kubectl apply -f clusterrole_binding.yaml
	kubectl apply -f crds/xo.90poe.io_vaultsecrets_crd.yaml
	kubectl apply -f crds/xo.90poe.io_vaultcertificates_crd.yaml
	kubectl apply -f operator.yaml

.PHONY: delete
delete:
	kubectl delete -f operator.yaml
	kubectl delete -f crds/xo.90poe.io_vaultsecrets_crd.yaml
	kubectl delete -f crds/xo.90poe.io_vaultcertificates_crd.yaml
	kubectl delete -f role_binding.yaml
	kubectl delete -f role.yaml
	kubectl delete -f clusterrole_binding.yaml
	kubectl delete -f clusterrole.yaml
	kubectl delete -f service_account.yaml
