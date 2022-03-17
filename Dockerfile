#FROM openjdk:11-slim-bullseye
FROM clojure:openjdk-11-lein-slim-buster
# move into the puppet directory
RUN mkdir -p /puppet/
ADD clojure_action.py /puppet/clojure_action
RUN chmod 751 /puppet/clojure_action
# download the snyk CLI
ADD https://github.com/snyk/snyk/releases/latest/download/snyk-linux /puppet/snyk
RUN chmod 751 /puppet/snyk 
# add puppet to the path
ENV PATH="/puppet/:${PATH}"
# we need maven to support snyk
RUN apt update
RUN apt install maven python3 -y
# run the action
CMD [ "clojure_action" ]