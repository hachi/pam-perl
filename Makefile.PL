use inc::Module::Install;
use ExtUtils::Depends;

# Define metadata
name           'PAM';
all_from       'lib/PAM.pm';

my $pkg = ExtUtils::Depends->new('PAM', 'XS::Object::Magic');

makemaker_args(
    $pkg->get_makefile_vars,
);

postamble(<<'EOT');
perlxsi.c:
	$(PERLRUN) -MExtUtils::Embed -e xsinit

perlxsi.o: perlxsi.c
	$(CCCMD) "-I$(PERL_INC)" -Wall -g -fPIC -c perlxsi.c

perl_helper.o: perl_helper.c
	$(CCCMD) "-I$(PERL_INC)" -Wall -g -fPIC -c perl_helper.c

perl_helper.so: perl_helper.o perlxsi.o
	$(LD) $(CCDLFLAGS) $(LDDLFLAGS) "-L$(PERL_INC)" -lperl -lpam -o perl_helper.so perl_helper.o perlxsi.o

pam_perl.o: pam_perl.c
	$(CCCMD) -Wall -g -fPIC -c pam_perl.c

pam_perl.so: pam_perl.o
	$(LD) $(CCDLFLAGS) $(LDDLFLAGS) -o pam_perl.so pam_perl.o

pam: pam_perl.so perl_helper.so

all :: pam


EOT

clean_files(qw(perlxsi.c perlxsi.o perl_helper.o perl_helper.so pam_perl.o pam_perl.so const-c.inc const-xs.inc));

WriteAll;

use ExtUtils::Constant qw (WriteConstants);

open my $const_fh, '<', 'constants.txt'
    or die "Couldn't open constants list file: $!\n";

my @constants = <$const_fh>;
chomp @constants;

WriteConstants(
    NAME => 'PAM',
    NAMES => [@constants],
);
