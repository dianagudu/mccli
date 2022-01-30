#!/bin/bash

rm -rf /tmp/gh-pages
cp -r doc/build /tmp/gh-pages \
    && git checkout gh-pages \
    && rm -rf * \
    && cp -r /tmp/gh-pages/* ./ \
    && rm -rf /tmp/gh-pages \
    && git add . \
    && git commit -m "Updated gh-pages" \
    && git push \
    && git checkout main