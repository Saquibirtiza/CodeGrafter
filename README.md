# ERLking

Author: Shamila Wickramasuriya <scw130030@utdallas.edu>

Author: Erick Bauman <erick.bauman@utdallas.edu>

## ERLking DESCRIPTION
The dockerfile creates an image of UTD system, ERLking.

VERSION = 5.0

ERLking is capable of creating Code Property Graphs for both Source and Binary. The graphs are then used to query about 
memory layout to look for buffer over-writes and hence effected variables.

Given a POI (line of interest), it is important to identify the associated variables and the branches that could get effected.

Due to different optimizations, the stack layout may be different from one another. With the dwarf reading library it is possible to identify the order of variables and hence the variables that could get effected by such overwrites.

ERLking's first release demonstrates the analysis on Apogee example 1. It yields relative addresses of possible over-writable 
variables and a set of Conditional branches.

| INPUT	                 | OUTPUT        |
| ---------------------- | ------------  |
| Source Binary Queries  | Query Results |

## ERLking Capabilities

*	Creates Source CPG for source availble in src folder
*	Creates Asm CPG for binary available in bin folder
*	Connect both CPG's with DWARF line information.
*	Use DWARF information to understand about memory layout
*	Provides a single script to start all services and an interactive session in the docker container
*	Provides a command in the container (erlking) to generate and run queries on the graph

## ERLking System requirements

*	Hard Disk : Minimum 64G (Preferred 100G +)
*	RAM : Minimum 8G (Preferred 32G +)
*	Processor : Preferred 4 cores +

## Prerequisites to Install

Install DOCKER in your HOST machine

	$ sudo apt update && install docker.io curl git make

Adding current user	

	$ sudo groupadd docker
	$ sudo usermod -aG docker $USER
	$ newgrp docker
	$ docker run hello-world

Install DOCKER-COMPOSE

	$ sudo curl -L "https://github.com/docker/compose/releases/download/1.23.2/docker-compose-$(uname -s)-$(uname -m)" \
		 -o /usr/local/bin/docker-compose
	$ sudo chmod +x /usr/local/bin/docker-compose

## Creating ERLking container

	$ git clone --recurse-submodules https://git-softseclab.utdallas.edu/darpa/erlking.git
	$ cd erlking
	$ make build				#To build the image
		optionally $ sudo docker build -t erlking-img<:VERSION> .	
	$ make run					#To create and enter the container
		optionally $ sudo docker-compose run erlking bash				


docker-compose will mount erlking/logs/targets folders to the container and initialize the container with run.sh.

After starting the container you will enter an interactive shell.

* Running "erlking" in the home directory will execute queries on an existing database (or build a new database if one does not exist yet).

The Checker consist of interfaces to Databases, sigBIN(binary parser), DWARVENking(dwarf parser).

We have apogee example_1 as the sample source and binary compiled with -g to be analysed. 


The sample test query checks for LEA on Base relative addresses and shows what are the conditional branches depends on base relative addresses.

## ERLking Analysis
** Make sure that each target in targets folder has all three src, bin, db folders. If db folder doesn't exist, please create one.

* Run the command "erlking" inside the container

		$ erlking

		<<[[ ERLking (UTD) ]]>>
		1: sudo_1_8_25p1
		2: openssh_7.3
		3: adams

* Select the target number. Then, if analysing this target for the first time

		1: Effected variables (Variables affected by insecure functions)
		2: Check BOILs (Buffer overflow inducible loops)
		3: Insecure Paths (From external input sources to sensitive sinks)
		4: Plot (Plots specified function)
		5: Check ForConditions (UpBound check for For-condition used as indices)
		6: Pointer Check (Null dereferences and use after free)
		0: Back

Choose any analysis to execute

* If this target is not running for first time

		1: Recreate Full CPG(SRC and BIN)
		2: Recreate Bin CPG only
		3: Use Existing CPG
		0: Back

Choose any number to continue

## ERLking Status Check

The status of ERLking system can be checked by

	$ erlking status

##### Following are the current status

*	Neo4j 		(neo4j)	: RESTARTING, STARTED
*	sibBIN		(sb)	: RUNNING, COMPLETED
*	DWARFking	(dk)	: RUNNING, COMPLETED
*	ERLking		(ek)	: STOPPED (Any state except this is equvalent to ek ACTIVE state)

## Explanation (example_1)

recv function has a buffer overwrite bug. We first check what base relative address contains that buffer.
Then using DWARVENking we check what other variables reside before the found buffer which should be effected
by the over-write.

DWARVENking records the size of each variables, so that we can tell what value could effect the variable.

## Graph plotting

Call graph and src/bin level CFGs can be plotted using sigbinMain.py
Run 

	python3 sigbinMain.py --bin <path-to-bin/bin>

The graphs are generated inside logs folder
They can be viewed by running 

	dot -Tsvg <file_name>.dot -o <some_name>.svg; eog <some_name>.svg

## Known Issues

Issue:
When building the image apt resource fails

	E: Failed to fetch http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc-dev-bin_2.27-3ubuntu1_amd64.deb
	Undetermined Error [IP: 91.189.88.24 80]

Solution:
Could be due to dangling image. Remove the image totally (docker rmi -f <image-id>) , then, run again.
