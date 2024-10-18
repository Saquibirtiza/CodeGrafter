#!/bin/bash

eval $(opam env)
echo $PATH
mkdir -p /home/utd/db
python3.9 /home/utd/erlking/chess/web_daemon.py & 
python3 /home/utd/erlking/chess/chess_daemon.py
