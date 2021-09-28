delete:
	-docker rm clojure_action
build:
	docker build -t clojure_action .
itest:
	make delete
	make build
	docker run --name clojure_action \
		-e INPUT_SNYKORG=sectest \
		-e INPUT_SNYKPROJECT=puppetserver \
		-e INPUT_SNYKTOKEN=$(SNYK_TOKEN) \
		-e GITHUB_WORKSPACE=/github/workspace \
		-v "/Users/jeremy.mill/Documents/forks/sectest-puppet-server":"/github/workspace" \
		-t clojure_action 
exec:
	make delete
	make build
	docker run --name clojure_action -it clojure_action /bin/bash