package inc::PAMMakeMaker;

use strict;
use warnings;

use Moose;

extends 'Dist::Zilla::Plugin::MakeMaker::Awesome';

override _build_WriteMakefile_args => sub { +{
    %{ super() },
    LIBS => [ '-lpam' ],
    clean => { FILES => "perlxsi.c perlxsi.o perl_helper.o perl_helper.so pam_perl.o pam_perl.so const-c.inc const-xs.inc" },
} };

override _build_WriteMakefile_dump => sub {
    return super() . <<'EOT';

use ExtUtils::Depends;
my $pkg = ExtUtils::Depends->new('PAM', 'XS::Object::Magic');

%WriteMakefileArgs = ($pkg->get_makefile_vars, %WriteMakefileArgs);
EOT
};

override _build_MakeFile_PL_template => sub {
    my ($self) = @_;
    my $template = super();

    $template .= <<'TEMPLATE';
package MY;

sub depend {
    return <<'EOT';
PAM.c : const-xs.inc
$(OBJECT) : const-c.inc
EOT
}

sub postamble {
    my $pam_lib_dir = "/lib/security/";

    $pam_lib_dir = "/usr/lib/pam" if $^O eq 'darwin';

    return "PAM_LIB_DIR = $pam_lib_dir\n" . <<'EOT'
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
}
TEMPLATE

    return $template;
};

__PACKAGE__->meta->make_immutable;
