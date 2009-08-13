#!/bin/bash

set -x
set -e

gcc -I/usr/lib/perl/5.10.0/CORE/ -g -fPIC -c pam_perl.c
gcc -I/usr/lib/perl/5.10.0/CORE/ -L/usr/lib/perl/5.10.0/CORE/ -shared -lpam -lperl -lm -o pam_perl.so pam_perl.o
