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

my $pam_lib_dir = "/lib/x86_64-linux-gnu/security/";

$pam_lib_dir = "/usr/lib/pam" if $^O eq 'darwin';

preamble(<<"EOT");
PAM_LIB_DIR = $pam_lib_dir
EOT

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
	$(CC) $(CCOPTS) $(CCCDLFLAGS) $(OPTIMIZE) $(INC) -D'PAM_LIB_DIR="$(PAM_LIB_DIR)"' -Wall -c pam_perl.c

pam_perl.so: pam_perl.o
	$(LD) $(LDOPTS) $(LDDLFLAGS) -o pam_perl.so pam_perl.o

pam: pam_perl.so perl_helper.so

pam-install: pam_perl.so perl_helper.so
	install -o 0 -g 0 pam_perl.so perl_helper.so $(PAM_LIB_DIR)

const-xs.inc const-c.inc :: pm_to_blib
	$(PERLRUN) -MExtUtils::Constant=WriteConstants -Mblib -MPAM::Constants \
                   -e 'WriteConstants(NAME => "PAM", NAMES => [ map { { name => $$_, macro => 1 } } @PAM::Constants::EXPORT_OK ])'

all :: pam

install :: pam-install


EOT

clean_files(qw(perlxsi.c perlxsi.o perl_helper.o perl_helper.so pam_perl.o pam_perl.so const-c.inc const-xs.inc));

WriteAll;
