FROM openjdk:11-slim-buster
# move into the puppet directory
RUN mkdir -p /puppet/
ADD clojure_action.py /puppet/clojure_action
RUN chmod 751 /puppet/clojure_action
# download leiningen
ADD https://raw.githubusercontent.com/technomancy/leiningen/stable/bin/lein /puppet/lein.sh
RUN chmod 751 /puppet/lein.sh
# download the snyk CLI
ADD https://github.com/snyk/snyk/releases/download/v1.720.0/snyk-linux /puppet/snyk 
RUN chmod 751 /puppet/snyk 
# add puppet to the path
ENV PATH="/puppet/:${PATH}"
#lein needs wget, snyk needs maven, we need python3
RUN apt update
RUN apt install wget maven python3 -y
# run the action
CMD [ "clojure_action" ]