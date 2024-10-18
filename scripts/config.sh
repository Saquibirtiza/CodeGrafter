#!/bin/bash

### usage: setProperty $filename $key $newvalue
setProperty(){
	echo $1,$2, $3
	# set,/home/utd/sw/neo4j-community-2.1.5/conf/neo4j-server.properties, org.neo4j.server.database.location, /home/utd/src/.joernIndex
	# awk -v pat="^org.neo4j.server.database.location=" -v value="org.neo4j.server.database.location=/home/utd/src/test" '{ if ($0 ~ pat) print value; else print $0; }' /home/utd/sw/neo4j-community-2.1.5/conf/neo4j-server.properties > /home/utd/sw/neo4j-community-2.1.5/conf/neo4j-server.properties.tmp
	# echo awk -v pat=^"$3"= -v value="$3=$4" '{ if ($0 ~ pat) print value; else print $0; }' "$2 > $2.tmp"
    awk -v pat="^$2=" -v value="$2=$3" '{ if ($0 ~ pat) print value; else print $0; }' $1 > $1.tmp
    mv -f $1.tmp $1
}

### usage: comment target
comment() {
  sed -i "s/^$2/#$2/" $1
}

### usage: uncomment target
uncomment() {
  sed -i "s/^#$2/$2/" $1
}

### usage: addProperty $filename $key $value
addProperty(){
	echo $2 " = " $3 >> $1 
}


case $1 in
set)
	setProperty $2 $3 $4
	# break
	;;
comment)
	comment $2 $3
	# break
	;;
uncomment)
	uncomment $2 $3
	# break
	;;
add)
	addProperty $2 $3 $4
	#break
	;;	
*)
	echo "Unknown command"
	;;
esac
# cd /home/utd/sw/neo4j-community-2.1.5/conf
# Usage
# setProperty /home/utd/sw/neo4j-community-2.1.5/conf/neo4j-server.properties "org.neo4j.server.database.location" "/home/utd/src/.joernIndex"

# setProperty "org.neo4j.server.database.location" "/home/utd/src/.joernIndex" "neo4j-server.properties"
# uncomment "org.neo4j.server.webserver.address" "neo4j-server.properties"
# uncomment "remote_shell_host" "neo4j.properties"
# setProperty "org.neo4j.server.webserver.address" "0.0.0.0" "neo4j-server.properties"
# setProperty "remote_shell_host" "0.0.0.0" "neo4j.properties"
# uncomment "allow_store_upgrade" "neo4j.properties"
