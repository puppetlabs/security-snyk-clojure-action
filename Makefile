delete:
	-docker rm clojure_action
build:
	docker build -t clojure_action .
exec:
	make delete
	make build
	docker run --name clojure_action -it clojure_action /bin/bash