#!/bin/bash

echo "The template is python code. This script downloads and parses the code from github."

if [ $# -ne 1 ]
then
	echo "Usage:"
	echo $0 "<where do you want the template file>"
	exit
fi

curl https://raw.githubusercontent.com/EmpireProject/Empire/master/data/agent/stagers/http.py | grep -v \# | grep -v -e '^$' > $1 
