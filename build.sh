#!/bin/bash

set -x
set -e

PERL="perl"

$PERL -MExtUtils::Embed -e xsinit
gcc $($PERL -MExtUtils::Embed -e ccopts) -Wall -g -fPIC -c perlxsi.c
gcc $($PERL -MExtUtils::Embed -e ccopts) -Wall -g -fPIC -c pam_perl.c
gcc $($PERL -MExtUtils::Embed -e ldopts) -shared -lpam -o pam_perl.so pam_perl.o perlxsi.o
