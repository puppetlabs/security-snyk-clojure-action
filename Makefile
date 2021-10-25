delete:
	-docker rm clojure_action
build:
	docker build -t clojure_action .
copy_testfiles:
	-rm -rf ./testfiles/pe-puppet-server-extensions
	-mkdir -p ./testfiles/pe-puppet-server-extensions
	cp -r /Users/jeremy.mill/Documents/forks/pe-puppet-server-extensions/ ./testfiles/pe-puppet-server-extensions

itest:
	make delete
	make build
	make copy_testfiles
	docker run --name clojure_action \
		-e INPUT_SNYKORG=sectest \
		-e INPUT_SNYKPROJECT=puppetserver \
		-e INPUT_SNYKTOKEN=$(SNYK_TOKEN) \
		-e GITHUB_WORKSPACE=/github/workspace \
		-e RPROXY_KEY=$(RPROXY_KEY) \
		-v "/Users/jeremy.mill/Documents/security-snyk-clojure-action/testfiles/pe-puppet-server-extensions":"/github/workspace" \
		-t clojure_action 
exec:
	make delete
	make build
	docker run --name clojure_action \
		-e INPUT_SNYKORG=sectest \
		-e INPUT_SNYKPROJECT=puppetserver \
		-e INPUT_SNYKTOKEN=$(SNYK_TOKEN) \
		-e GITHUB_WORKSPACE=/github/workspace \
		-e RPROXY_KEY=$(RPROXY_KEY) \
		-v "/Users/jeremy.mill/Documents/security-snyk-clojure-action/testfiles/pe-puppet-server-extensions":"/github/workspace" \
		-it clojure_action /bin/bash
