#!/bin/bash

set -x
set -e

gcc -Wall -I/usr/lib/perl/5.10.1/CORE/ -g -fPIC -c pam_perl.c
gcc -Wall -I/usr/lib/perl/5.10.1/CORE/ -L/usr/lib/perl/5.10.1/CORE/ -shared -lpam -lperl -lm -o pam_perl.so pam_perl.o
