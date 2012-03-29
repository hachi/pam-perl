use inc::Module::Install;
use ExtUtils::Depends;

# Define metadata
name           'PAM';
all_from       'lib/PAM.pm';

requires 'ExtUtils::Constant' => 0;
requires 'ExtUtils::Embed'    => 0;
requires 'ExtUtils::Depends'  => 0;
requires 'XS::Object::Magic'  => 0;

my $pkg = ExtUtils::Depends->new('PAM', 'XS::Object::Magic');

makemaker_args(
    $pkg->get_makefile_vars,
    depend => { 'PAM.c' => 'const-xs.inc', '$(OBJECT)' => 'const-c.inc' },
    LIBS => [ '-lpam' ],
);

postamble(<<'EOT');
CCOPTS = $(shell $(PERLRUN) -MExtUtils::Embed -e ccopts)
LDOPTS = $(shell $(PERLRUN) -MExtUtils::Embed -e ldopts)

perlxsi.c:
	$(PERLRUN) -MExtUtils::Embed -e xsinit

perlxsi.o: perlxsi.c
	$(CC) $(CCOPTS) $(CCCDLFLAGS) $(OPTIMIZE) "-I$(PERL_INC)" -Wall -c perlxsi.c

perl_helper.o: perl_helper.c
	$(CC) $(CCOPTS) $(CCCDLFLAGS) $(OPTIMIZE) "-I$(PERL_INC)" $(INC) -Wall -c perl_helper.c

perl_helper.so: perl_helper.o perlxsi.o
	$(LD) $(LDOPTS) $(LDDLFLAGS) $(EXTRALIBS) -o perl_helper.so perl_helper.o perlxsi.o

pam_perl.o: pam_perl.c
	$(CC) $(CCOPTS) $(CCCDLFLAGS) $(OPTIMIZE) $(INC) -Wall -c pam_perl.c

pam_perl.so: pam_perl.o
	$(LD) $(LDOPTS) $(LDDLFLAGS) -o pam_perl.so pam_perl.o

pam: pam_perl.so perl_helper.so

pam-install: pam_perl.so perl_helper.so
	install --owner=root --group=root pam_perl.so perl_helper.so /lib/security/

const-xs.inc const-c.inc :: pm_to_blib
	$(PERLRUN) -MExtUtils::Constant=WriteConstants -Mblib -MPAM::Constants \
                   -e 'WriteConstants(NAME => "PAM", NAMES => \@PAM::Constants::EXPORT_OK)'

all :: pam

install :: pam-install


EOT

clean_files(qw(perlxsi.c perlxsi.o perl_helper.o perl_helper.so pam_perl.o pam_perl.so const-c.inc const-xs.inc));

WriteAll;
