#!/bin/bash

set -x
set -e

gcc $(perl -MExtUtils::Embed -e ccopts) -Wall -g -fPIC -c pam_perl.c
gcc $(perl -MExtUtils::Embed -e ldopts) -shared -lpam -o pam_perl.so pam_perl.o
