package PAM::Constants;

use strict;
use warnings;

use Carp qw(croak);
use Exporter;
use PAM;

use base 'Exporter';

our %EXPORT_TAGS = ( 'all' => [ qw(
    PAM_SUCCESS
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw();

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&PAM::Constants::constant not defined" if $constname eq 'constant';
    my ($error, $val) = constant($constname);
    if ($error) {
        if ($error =~  /is not a valid/) {
            $AutoLoader::AUTOLOAD = $AUTOLOAD;
            goto &AutoLoader::AUTOLOAD;
        } else {
            croak $error;
        }
    }
    {
        no strict 'refs';
        # Fixed between 5.005_53 and 5.005_61
#        if ($] >= 5.00561) {
#            *$AUTOLOAD = sub () { $val };
#        }
#        else {
            *$AUTOLOAD = sub { $val };
#        }
    }
    goto &$AUTOLOAD;
}


1;
