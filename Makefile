SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
CONAINER_NAME	= registry.gitlab.com/trivialsec/batch/${BUILD_ENV}
.PHONY: help
.ONESHELL: # Applies to every targets in the file!
help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

ifndef CI_BUILD_REF
	CI_BUILD_REF = local
endif

pylint-ci: ## run pylint for CI
	@pylint --version
	pylint --exit-zero --persistent=n -f json -r n --jobs=0 --errors-only src/**/*.py > pylint.json

semgrep-sast-ci: ## run core semgrep rules for CI
	semgrep --disable-version-check -q --strict --error -o semgrep-ci.json --json --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

init: ## Runs tf init tf
	cd plans
	terraform init -reconfigure -upgrade=true

output:
	cd plans
	terraform output cronicle_password

deploy: plan apply attach-firewall output ## tf plan and apply -auto-approve -refresh=true

plan: init ## Runs tf validate and tf plan
	cd plans
	terraform validate
	terraform plan -no-color -out=.tfplan
	terraform show --json .tfplan | jq -r '([.resource_changes[]?.change.actions?]|flatten)|{"create":(map(select(.=="create"))|length),"update":(map(select(.=="update"))|length),"delete":(map(select(.=="delete"))|length)}' > tfplan.json

apply: ## tf apply -auto-approve -refresh=true
	cd plans
	terraform apply -auto-approve -refresh=true .tfplan

destroy: init ## tf destroy -auto-approve
	cd plans
	terraform validate
	terraform plan -destroy -no-color -out=.tfdestroy
	terraform show --json .tfdestroy | jq -r '([.resource_changes[]?.change.actions?]|flatten)|{"create":(map(select(.=="create"))|length),"update":(map(select(.=="update"))|length),"delete":(map(select(.=="delete"))|length)}' > tfdestroy.json
	terraform apply -auto-approve -destroy .tfdestroy

attach-firewall:
	curl -s -H "Content-Type: application/json" \
		-H "Authorization: Bearer ${TF_VAR_linode_token}" \
		-X POST -d '{"type": "linode", "id": $(shell curl -s -H "Authorization: Bearer ${TF_VAR_linode_token}" https://api.linode.com/v4/linode/instances | jq -r '.data[] | select(.label=="prd-batch.trivialsec.com") | .id')}' \
		https://api.linode.com/v4/networking/firewalls/${LINODE_FIREWALL}/devices

#####################
# Development Only
#####################
prep: ## Cleanup tmp files
	@find . -type f -name '*.pyc' -delete 2>/dev/null
	@find . -type d -name '__pycache__' -delete 2>/dev/null
	@find . -type f -name '*.DS_Store' -delete 2>/dev/null
	@rm -rf python-libs 2>/dev/null

setup: ## Creates docker networks and volumes
	@echo $(shell docker --version)
	@echo $(shell docker-compose --version)
	@pip --version
	pip install --progress-bar off -U pip
	pip install --progress-bar off -U  setuptools wheel semgrep pylint
	pip install --progress-bar off -U -r requirements.txt
	docker network create trivialsec 2>/dev/null || true
	docker volume create --name=cronicle-datadir 2>/dev/null || true
	docker volume create --name=batch-cache 2>/dev/null || true

tfinstall:
	curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
	sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(shell lsb_release -cs) main"
	sudo apt-get update
	sudo apt-get install -y terraform
	terraform -install-autocomplete || true

docker-clean: ## quick docker environment cleanup
	docker rmi $(docker images -qaf "dangling=true")
	yes | docker system prune
	sudo service docker restart

docker-purge: ## thorough docker environment cleanup
	docker rmi $(docker images -qa)
	yes | docker system prune
	sudo service docker stop
	sudo rm -rf /tmp/docker.backup/
	sudo cp -Pfr /var/lib/docker /tmp/docker.backup
	sudo rm -rf /var/lib/docker
	sudo service docker start

python-libs: prep ## download and install the trivialsec python libs locally (for IDE completions)
	yes | pip uninstall -q trivialsec-common
	git clone -q -c advice.detachedHead=false --depth 1 --branch ${TRIVIALSEC_PY_LIB_VER} --single-branch git@gitlab.com:trivialsec/python-common.git python-libs
	cd python-libs
	make install

up: ## Starts latest container images
	docker-compose up -d

down: ## Bring down containers
	docker-compose down --remove-orphans

rebuild: down build ## alias for down && build

restart: down up ## alias for down && up

build: ## Build
	docker-compose build

buildnc: ## Build
	docker-compose build --no-cache

test-local: ## Prettier test outputs for local dev
	@echo semgrep $(semgrep --version)
	pylint --exit-zero -f colorized --persistent=y -r y --jobs=0 src/**/*.py
	semgrep -q --strict --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py
