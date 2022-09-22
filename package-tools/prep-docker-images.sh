#!/bin/sh
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "${SCRIPT_DIR}/docker-image-defs/rpmbuild6"
docker build -t vermouth/rpmbuild6 .
cd "${SCRIPT_DIR}/docker-image-defs/rpmbuild7"
docker build -t vermouth/rpmbuild7 .
cd "${SCRIPT_DIR}/docker-image-defs/ubuntu-xenial"
docker build -t vermouth/debpkg .

