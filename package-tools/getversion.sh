#!/bin/bash

export TAG_COMMIT=$(git rev-list --abbrev-commit --tags --max-count=1)
#echo TAG_COMMIT=$TAG_COMMIT 
export TAG=$(git describe --abbrev=0 --tags ${TAG_COMMIT} 2>/dev/null || true)
if [ "${TAG:0:1}" != "v" ]
then
	export TAG=""
fi
#echo TAG=$TAG
export COMMIT=$(git rev-parse --short HEAD)
#echo COMMIT=$COMMIT
export DATE=$(git log -1 --format=%cd --date=format:"%Y%m%d")
#echo DATE=$DATE
export VERSION=${TAG##v}
#echo VERSION=$VERSION
if [ "$COMMIT" != "$TAG_COMMIT" ]
then
    export VERSION=0.${DATE}.${COMMIT}.dev
fi
#echo VERSION=$VERSION
export GIT_UNCLEAN=$(git status --porcelain)
if [ "$GIT_UNCLEAN" != "" ]
then
	export VERSION=${VERSION}.dirty
fi
echo VERSION=${VERSION}
#echo TAG=${TAG}
