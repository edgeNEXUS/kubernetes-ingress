package Edge::ClientAPI::JSON;
use strict;
use warnings;
use Edge::ClientAPI;

our $VERSION = $Edge::ClientAPI::VERSION;

sub coder() {
   eval { require JSON::XS; JSON::XS->new->utf8 } ||
     do { require JSON::PP; JSON::PP->new->utf8 }
}

1;
