package PAM;

require 5.008001;
use parent qw(DynaLoader);

our $VERSION = '0.00_01';

sub dl_load_flags {0x01}

__PACKAGE__->bootstrap($VERSION);

$VERSION = eval $VERSION;

1;
