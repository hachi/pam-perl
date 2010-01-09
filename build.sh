#!/bin/bash

set -x
set -e

PERL="perl"

gcc $($PERL -MExtUtils::Embed -e ccopts) -Wall -g -fPIC -c pam_perl.c
gcc $($PERL -MExtUtils::Embed -e ldopts) -shared -lpam -o pam_perl.so pam_perl.o
