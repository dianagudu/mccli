#!/bin/bash

VERSION_FILE=mccli/VERSION


[ "$CI" == "true" ] && {
    git config --global --add safe.directory "$PWD"
}

# Get master branch name:
#   use origin if exists
#   else use last found remote
REMOTES=$(git remote show)
for R in $REMOTES; do
    MASTER=$(git remote show "$R"  2>/dev/null \
        | sed -n '/HEAD branch/s/.*: //p')
    MASTER_BRANCH="refs/remotes/${R}/${MASTER}"
    # echo "Master-branch: ${MASTER_BRANCH}"
    [ "$R" == "origin" ] && break
done

PREREL=$(git rev-list --count HEAD ^"$MASTER_BRANCH")

# if we use a version file, things are easy:
[ -e $VERSION_FILE ] && {
    VERSION=$(cat $VERSION_FILE)
    PR_VERSION="${VERSION}.dev${PREREL}"
    echo "$PR_VERSION" > $VERSION_FILE
    echo "$PR_VERSION"
}
