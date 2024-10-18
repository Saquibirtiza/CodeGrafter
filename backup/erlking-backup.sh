#!/bin/sh
# Backs up POI database and logs from ERLking 

if [ $# -ne 2 ]; then
    echo "Usage: ${0} <ERLking's container ID> <Path to Backup Folder>"
    exit
fi

mkdir -p ${2}/db
mkdir -p ${2}/logs
docker cp ${1}:/home/utd/db ${2}
docker cp ${1}:/home/utd/logs ${2}
