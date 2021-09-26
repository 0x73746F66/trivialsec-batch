SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
CONAINER_NAME	= registry.gitlab.com/trivialsec/scheduler/${BUILD_ENV}
.PHONY: help
.ONESHELL: # Applies to every targets in the file!
help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

ifndef CI_BUILD_REF
	CI_BUILD_REF = local
endif

prep: ## Cleanup tmp files
	@find . -type f -name '*.pyc' -delete 2>/dev/null
	@find . -type d -name '__pycache__' -delete 2>/dev/null
	@find . -type f -name '*.DS_Store' -delete 2>/dev/null
	@rm -rf python-libs 2>/dev/null

python-libs: prep ## download and install the trivialsec python libs locally (for IDE completions)
	yes | pip uninstall -q trivialsec-common
	@$(shell rm -rf python-libs; git clone -q -c advice.detachedHead=false --depth 1 --branch ${COMMON_VERSION} --single-branch https://${DOCKER_USER}:${DOCKER_PASSWORD}@gitlab.com/trivialsec/python-common.git python-libs)
	cd python-libs
	make install
	@rm -rf python-libs

setup: ## first time local setup activities
	@echo $(docker --version)
	@echo $(docker-compose --version)
	@pip --version
	@echo node $(node --version)
	@echo yarn $(yarn --version)
	docker volume create --name=scheduler-cache
	pip install -q -U pip setuptools wheel semgrep pylint
	pip install -q -U --no-cache-dir --find-links=python-libs/build/wheel --no-index --isolated -r requirements.txt

test-local: ## Prettier test outputs for local dev
	@echo semgrep $(semgrep --version)
	pylint --exit-zero -f colorized --persistent=y -r y --jobs=0 src/**/*.py
	semgrep -q --strict --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

pylint-ci: ## run pylint for CI
	@pylint --version
	pylint --exit-zero --persistent=n -f json -r n --jobs=0 --errors-only src/**/*.py > pylint.json

semgrep-sast-ci: ## run core semgrep rules for CI
	semgrep --disable-version-check -q --strict --error -o semgrep-ci.json --json --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

test-all: semgrep-sast-ci pylint-ci ## Run all CI tests

build: ## Builds images using docker cli directly for CI
	@docker build  --compress $(BUILD_ARGS) \
		-t $(CONAINER_NAME):$(CI_BUILD_REF) \
		--cache-from $(CONAINER_NAME):latest \
        --build-arg COMMON_VERSION=$(COMMON_VERSION) \
        --build-arg BUILD_ENV=$(BUILD_ENV) \
        --build-arg GITLAB_USER=$(DOCKER_USER) \
        --build-arg GITLAB_PASSWORD=$(DOCKER_PASSWORD) \
		--build-arg PYTHONUNBUFFERED=1 .

push-tagged: ## Push tagged image
	docker push -q $(CONAINER_NAME):${CI_BUILD_REF}

push-ci: ## Push latest image using docker cli directly for CI
	docker tag $(CONAINER_NAME):${CI_BUILD_REF} $(CONAINER_NAME):latest
	docker push -q $(CONAINER_NAME):latest

rebuild: down build ## alias for down && build

up: ## Starts the container
	docker-compose up -d

down: ## Bring down all running containers
	@docker-compose down --remove-orphans

restart: down up ## alias for down && up
