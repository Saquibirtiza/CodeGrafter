# /home/utd
#		  +-erlking
#		  +-Dockerfile
#		  +-README
#		  +-logs
#		  +-scripts
#		  +- sw
#			+- neo4j
#			+- neo4j-gremlin
#		  +-targets

#FROM ubuntu:latest
FROM shamilautd/erl_base:3.0
MAINTAINER Shamila Wickramasuriya <scw130030@utdallas.edu>

ENV DEBIAN_FRONTEND=noninteractive

USER utd
WORKDIR /home/utd



#Packages for Joern	
RUN sudo apt-get -y --fix-missing install ant \
	software-properties-common \
	build-essential \
	pkg-config \
	python-setuptools \
	python-dev \
	graphviz \
	libgraphviz-dev \
	apt-utils \
	net-tools \
	lsof
	

#Making the project structure
RUN mkdir erlking && mkdir sw/joern && mkdir sw/1 && mkdir sw/2 && mkdir sw/3 && mkdir sw/4 && mkdir sw/5
ADD scripts /home/utd/scripts

#Neo4J for Joern

RUN wget https://neo4j.com/artifact.php?name=neo4j-community-2.1.5-unix.tar.gz -O tmp/neo4j-2.1.5.tar.gz && \
	tar xfzv tmp/neo4j-2.1.5.tar.gz -C sw
#RUN wget http://mlsec.org/joern/lib/neo4j-gremlin-plugin-2.1-SNAPSHOT-server-plugin.zip -O tmp/neo4j-gremlin-plugin-2.1.zip && \
#	unzip tmp/neo4j-gremlin-plugin-2.1.zip -d sw/neo4j-community-2.1.5/plugins
COPY ext_libs/neo4j-gremlin-plugin-2.1.zip tmp
RUN unzip tmp/neo4j-gremlin-plugin-2.1.zip -d sw/neo4j-community-2.1.5/plugins
#If more neo4j instances needed add them in the following way	
RUN tar xfzv tmp/neo4j-2.1.5.tar.gz -C sw/1
RUN unzip tmp/neo4j-gremlin-plugin-2.1.zip -d sw/1/neo4j-community-2.1.5/plugins
RUN tar xfzv tmp/neo4j-2.1.5.tar.gz -C sw/2
RUN unzip tmp/neo4j-gremlin-plugin-2.1.zip -d sw/2/neo4j-community-2.1.5/plugins
RUN tar xfzv tmp/neo4j-2.1.5.tar.gz -C sw/3
RUN unzip tmp/neo4j-gremlin-plugin-2.1.zip -d sw/3/neo4j-community-2.1.5/plugins
RUN tar xfzv tmp/neo4j-2.1.5.tar.gz -C sw/4
RUN unzip tmp/neo4j-gremlin-plugin-2.1.zip -d sw/4/neo4j-community-2.1.5/plugins
RUN tar xfzv tmp/neo4j-2.1.5.tar.gz -C sw/5
RUN unzip tmp/neo4j-gremlin-plugin-2.1.zip -d sw/5/neo4j-community-2.1.5/plugins

#Components for Joern

COPY joern-py3/joern-0.3.1 sw/joern/joern-0.3.1
COPY joern-py3/python-joern-0.3.1 sw/joern/python-joern-0.3.1
COPY joern-py3/joern-pytools sw/joern/joern-pytools
#RUN sudo chown -R utd:utd /home/utd/sw/joern
RUN sudo chown -R utd:utd /home/utd/sw
#Each ne4j instance's conf directory should be given the write permission
RUN sudo chmod 664 /home/utd/sw/1/neo4j-community-2.1.5/conf/*
RUN sudo chmod 664 /home/utd/sw/2/neo4j-community-2.1.5/conf/*
RUN sudo chmod 664 /home/utd/sw/3/neo4j-community-2.1.5/conf/*
RUN sudo chmod 664 /home/utd/sw/4/neo4j-community-2.1.5/conf/*
RUN sudo chmod 664 /home/utd/sw/5/neo4j-community-2.1.5/conf/*

#RUN pip3 install --user py2neo==2.0


#Other installations
RUN pip3 install bap termcolor pyelftools cxxfilt networkx graphviz pygraphviz pydot neo4j neo4j-driver
#neobolt neomodel neotime

# Install prerequisites of integration framework and topic config gen tool
RUN pip3 install pyzmq==18.1.0 protobuf==3.7.1 ruamel.yaml==0.15.97
#RUN pip3 install pyzmq protobuf ruamel.yaml

# Install prerequisite of challenge broker
RUN pip3 install requests

# Install mqtt client with python bindings.
# Paho was chosen because it is under the same umbrella as mosquitto,
# as both are Eclipse Foundation projects.
# Also install json schema verifier and python-daemon
RUN pip3 install paho-mqtt jsonschema python-daemon

# Generate messages and install integration framework
#COPY dependencies/chess_system_sandbox /home/utd/tmp/chess_integration_framework
#COPY dependencies/message_set_coordination /home/utd/tmp/message_set_coordination
#RUN sudo /home/utd/tmp/chess_integration_framework/autogen/generate_messages/setup.sh
#RUN PROTO_INPUT=/home/utd/tmp/message_set_coordination/proto_files PROTO_OUTPUT=/home/utd/tmp/message_set_coordination_autogen/ /home/utd/tmp/chess_integration_framework/autogen/generate_messages/create_protobuf_packages.sh
#RUN pip3 install /home/utd/tmp/message_set_coordination_autogen/message_packages/python/chess_messages
#RUN PIP_IGNORE_INSTALLED=0 pip3 install /home/utd/tmp/chess_integration_framework/api/python/chess_integration_framework

# Generate topic config file
#COPY config /home/utd/config
#RUN sudo chown utd /home/utd/config
#RUN python3 /home/utd/tmp/chess_integration_framework/autogen/generate_topic_config/generate.py --input_file=/home/utd/config/topic_parameters.yaml --output_file=/home/utd/config/chess_topics.json

# Set environment

# Set environment
#ENV JAVA_HOME /home/utd/sw/jdk1.8.0_131
#ENV PATH ${PATH}:${JAVA_HOME}/bin
RUN echo "JAVA_HOME=/home/utd/sw/jdk1.8.0_131" >> ~/.bashrc
RUN echo "PATH=\$JAVA_HOME/bin:\$PATH" >> ~/.bashrc
RUN echo "JOERN=/home/utd/sw/joern/joern-0.3.1" >> ~/.bashrc
RUN echo "alias joern='java -Xmx8g -jar \$JOERN/bin/joern.jar'" >> ~/.bashrc
RUN echo "eval \"$(opam env)\"" >> ~/.bashrc
RUN /bin/bash -c "source ~/.bashrc"

#Building Joern
RUN cd sw/joern/joern-0.3.1 && ls -l /home/utd/sw/joern && ant && ant tools
RUN cd sw/joern/python-joern-0.3.1 && sudo python3 setup.py install
RUN cd sw/joern/joern-pytools && sudo python3 setup.py install


COPY scripts/run.sh /home/utd/scripts
#COPY run.sh /home/utd
COPY scripts/config.sh /home/utd/scripts
COPY scripts/erlking /bin
#RUN pip3 install -U memory_profiler

#Neo4j configuration instance 1
RUN sudo bash /home/utd/scripts/config.sh uncomment "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.initmemory"
RUN sudo bash /home/utd/scripts/config.sh uncomment "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.maxmemory"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.initmemory" "2048"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.maxmemory" "3000"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j.properties" "use_memory_mapped_buffers" "true"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j.properties" "cache_type" "soft"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.nodestore.db.mapped_memory" "1G"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.relationshipstore.db.mapped_memory" "2G"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.mapped_memory" "1G"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.strings.mapped_memory" "1300M"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.arrays.mapped_memory" "130M"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.index.keys.mapped_memory" "200M"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.index.mapped_memory" "200M"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j-server.properties" "org.neo4j.server.webserver.port" "8471"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j-server.properties" "org.neo4j.server.webserver.https.port" "8481"
#RUN sudo bash /home/utd/scripts/config.sh uncomment "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j.properties" "remote_shell_port"
#RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/1/neo4j-community-2.1.5/conf/neo4j.properties" "remote_shell_port" "8331"

#Neo4j configuration instance 2
RUN sudo bash /home/utd/scripts/config.sh uncomment "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.initmemory"
RUN sudo bash /home/utd/scripts/config.sh uncomment "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.maxmemory"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.initmemory" "2048"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.maxmemory" "3000"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j.properties" "use_memory_mapped_buffers" "true"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j.properties" "cache_type" "soft"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.nodestore.db.mapped_memory" "1G"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.relationshipstore.db.mapped_memory" "2G"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.mapped_memory" "1G"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.strings.mapped_memory" "1300M"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.arrays.mapped_memory" "130M"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.index.keys.mapped_memory" "200M"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.index.mapped_memory" "200M"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j-server.properties" "org.neo4j.server.webserver.port" "8472"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j-server.properties" "org.neo4j.server.webserver.https.port" "8482"
#RUN sudo bash /home/utd/scripts/config.sh uncomment "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j.properties" "remote_shell_port"
#RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/2/neo4j-community-2.1.5/conf/neo4j.properties" "remote_shell_port" "8332"

#Neo4j configuration instance 3
RUN sudo bash /home/utd/scripts/config.sh uncomment "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.initmemory"
RUN sudo bash /home/utd/scripts/config.sh uncomment "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.maxmemory"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.initmemory" "2048"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.maxmemory" "3000"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j.properties" "use_memory_mapped_buffers" "true"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j.properties" "cache_type" "soft"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.nodestore.db.mapped_memory" "1G"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.relationshipstore.db.mapped_memory" "2G"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.mapped_memory" "1G"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.strings.mapped_memory" "1300M"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.arrays.mapped_memory" "130M"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.index.keys.mapped_memory" "200M"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.index.mapped_memory" "200M"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j-server.properties" "org.neo4j.server.webserver.port" "8473"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j-server.properties" "org.neo4j.server.webserver.https.port" "8483"
#RUN sudo bash /home/utd/scripts/config.sh uncomment "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j.properties" "remote_shell_port"
#RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/3/neo4j-community-2.1.5/conf/neo4j.properties" "remote_shell_port" "8333"

#Neo4j configuration instance 4
RUN sudo bash /home/utd/scripts/config.sh uncomment "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.initmemory"
RUN sudo bash /home/utd/scripts/config.sh uncomment "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.maxmemory"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.initmemory" "2048"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.maxmemory" "3000"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j.properties" "use_memory_mapped_buffers" "true"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j.properties" "cache_type" "soft"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.nodestore.db.mapped_memory" "1G"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.relationshipstore.db.mapped_memory" "2G"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.mapped_memory" "1G"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.strings.mapped_memory" "1300M"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.arrays.mapped_memory" "130M"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.index.keys.mapped_memory" "200M"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.index.mapped_memory" "200M"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j-server.properties" "org.neo4j.server.webserver.port" "8474"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j-server.properties" "org.neo4j.server.webserver.https.port" "8484"
#RUN sudo bash /home/utd/scripts/config.sh uncomment "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j.properties" "remote_shell_port"
#RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/4/neo4j-community-2.1.5/conf/neo4j.properties" "remote_shell_port" "8334"

#Neo4j configuration instance 5
RUN sudo bash /home/utd/scripts/config.sh uncomment "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.initmemory"
RUN sudo bash /home/utd/scripts/config.sh uncomment "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.maxmemory"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.initmemory" "2048"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j-wrapper.conf" "wrapper.java.maxmemory" "3000"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j.properties" "use_memory_mapped_buffers" "true"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j.properties" "cache_type" "soft"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.nodestore.db.mapped_memory" "1G"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.relationshipstore.db.mapped_memory" "2G"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.mapped_memory" "1G"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.strings.mapped_memory" "1300M"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.arrays.mapped_memory" "130M"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.index.keys.mapped_memory" "200M"
RUN sudo bash /home/utd/scripts/config.sh add "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j.properties" "neostore.propertystore.db.index.mapped_memory" "200M"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j-server.properties" "org.neo4j.server.webserver.port" "8475"
RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j-server.properties" "org.neo4j.server.webserver.https.port" "8485"
#RUN sudo bash /home/utd/scripts/config.sh uncomment "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j.properties" "remote_shell_port"
#RUN sudo bash /home/utd/scripts/config.sh set "/home/utd/sw/5/neo4j-community-2.1.5/conf/neo4j.properties" "remote_shell_port" "8335"

RUN mkdir sw/pySym
RUN git clone https://github.com/bannsec/pySym.git sw/pySym
RUN cd sw/pySym && pip3 install .

RUN pip3 install pycparser

#RUN echo "## To start the container run $ docker-compose up"
#RUN echo "## To start the container by 'make run'"

#CMD ["/bin/bash"]
CMD ["su", "-", "user", "-c", "/bin/bash"]
#RUN /bin/bash -c "source /usr/local/bin/virtualenvwrapper.sh"
