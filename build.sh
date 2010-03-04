#!/bin/bash

set -x
set -e

PERL="perl"

$PERL -MExtUtils::Embed -e xsinit
gcc $($PERL -MExtUtils::Embed -e ccopts) -Wall -g -fPIC -c perlxsi.c
gcc $($PERL -MExtUtils::Embed -e ccopts) -I/home/hachi/lib-local/x86_64-linux-gnu-thread-multi/XS/Object/Magic/Install -Wall -g -fPIC -c perl_helper.c
gcc $($PERL -MExtUtils::Embed -e ldopts) -shared -lpam -o perl_helper.so perl_helper.o perlxsi.o
gcc -Wall -g -fPIC -c pam_perl.c
gcc -Wl,-E -fstack-protector -ldl -shared -o pam_perl.so pam_perl.o
