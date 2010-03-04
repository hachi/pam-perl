use inc::Module::Install;
use ExtUtils::Depends;

# Define metadata
name           'PAM';
all_from       'lib/PAM.pm';

my $pkg = ExtUtils::Depends->new('PAM', 'XS::Object::Magic');

use Data::Dumper;
print Dumper($pkg->get_makefile_vars);

makemaker_args(
    $pkg->get_makefile_vars,
);

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
