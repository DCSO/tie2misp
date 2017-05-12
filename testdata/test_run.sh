#!/bin/bash
set -e



if [ -z ${TIE_TOKEN+x} ]; then
   # TIE_TOKEN is not set, simply checking whether tool can run
   ./tie2misp --help
else
    sed "s/SETME/$TIE_TOKEN/" testdata/config.yml > settings/config.yml
    cp testdata/tags.yml settings/tags.yml
    ./tie2misp c2server --date 2017-03-13 --noupload --file | tail -n 1 | xargs jq '.Event.Attribute | length' > length
    test `cat length` -gt "0"
    rm -f settings/config.yml
    rm -f settings/tags.ym
fi
