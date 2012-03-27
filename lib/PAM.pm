package PAM;

=head1 NAME

PAM - Invoke perl code at PAM phases

=head1 SYNOPSIS

  package Example::PAM;
  
  use PAM::Constants qw(PAM_SUCCESS);
  use PAM::Handle;
  
  sub open_session {
    my $class = shift;
    my ($pamh, $flags, @ARGS) = @_;
    my $user = $pamh->get_user($prompt);
    
    return PAM_SUCCESS;
  }

=head1 DESCRIPTION

This Perl and PAM module allow you to invoke a perl interpreter and call package
methods during pam phases. It also includes bindings for most of the pam functions
and constants.

=cut

require 5.008001;
use parent qw(DynaLoader);

our $VERSION = '0.02';

sub dl_load_flags {0x01}

__PACKAGE__->bootstrap($VERSION);

$VERSION = eval $VERSION;

1;

=head1 COPYRIGHT

Copyright 2010 - Jonathan Steinert

=head1 AUTHOR

Jonathan Steinert

=head1 LICENSE

This module is licensed under the same terms as Perl itself.

=cut
