#!/bin/bash

echo "Parsing environment variables at ${1}..."

new=$(<$1)

while IFS='=' read -r name value ; do
    new="${new/$name/"$value"/g}" 
done < <(env)

echo "$new" > "$2"

echo "Parsing completed successfully!"
echo "New file created at $2"