# testFolder = pe-puppet-server-extensions
# testFolder = code-manager
testFolder = clj-parent

delete:
	-docker rm clojure_action
build:
	docker build -t clojure_action .
copy_testfiles:
	-rm -rf ./testfiles/$(testFolder)
	-mkdir -p ./testfiles/$(testFolder)
	cp -r /Users/jeremy.mill/Documents/forks/$(testFolder)/ ./testfiles/$(testFolder)

itest:
	make delete
	make build
	make copy_testfiles
	docker run --name clojure_action \
		-e INPUT_SNYKORG=sectest \
		-e INPUT_SNYKPROJECT=puppetserver \
		-e INPUT_SNYKTOKEN=$(SNYK_TOKEN) \
		-e GITHUB_WORKSPACE=/github/workspace \
		-e INPUT_NOMONITOR=true \
		-v "/Users/jeremy.mill/Documents/security-snyk-clojure-action/testfiles/$(testFolder)":"/github/workspace" \
		-t clojure_action 
itest_ignore:
	make delete
	make build
	make copy_testfiles
	cp ./testfiles/.snyk ./testfiles/$(testFolder)/
	docker run --name clojure_action \
		-e INPUT_SNYKORG=sectest \
		-e INPUT_SNYKPROJECT=puppetserver \
		-e INPUT_SNYKTOKEN=$(SNYK_TOKEN) \
		-e GITHUB_WORKSPACE=/github/workspace \
		-e INPUT_NOMONITOR=true \
		-e INPUT_SNYKPOLICY=.snyk \
		-v "/Users/jeremy.mill/Documents/security-snyk-clojure-action/testfiles/$(testFolder)":"/github/workspace" \
		-t clojure_action 
exec:
	make delete
	make build
	docker run --name clojure_action \
		-e INPUT_SNYKORG=sectest \
		-e INPUT_SNYKPROJECT=puppetserver \
		-e INPUT_SNYKTOKEN=$(SNYK_TOKEN) \
		-e GITHUB_WORKSPACE=/github/workspace \
		-v "/Users/jeremy.mill/Documents/security-snyk-clojure-action/testfiles/$(testFolder)":"/github/workspace" \
		-it clojure_action /bin/bash
