#!/bin/bash
IFS='
'

for FILENAME in *
do
    if [[ $FILENAME == *"Pasted "* ]]; then
        NEWFILENAME=$(echo $FILENAME | sed 's/[^0-9]*//g')
        NEWFILENAME=$(echo $NEWFILENAME.png)
        FILENAME=$(echo $FILENAME)
        mv $FILENAME $NEWFILENAME
    fi
done
