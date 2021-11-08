package Edge::ClientAPI::Object::FP;
use common::sense;

sub bless {
    my ($class, $href) = @_;
    die "No VS hashref: $href" unless ref $href eq 'HASH';
    CORE::bless $href, $class;
}

sub name        { $_[0]{flightPathName}  }
sub id          { $_[0]{fId}             }
sub in_use      { $_[0]{flightPathInUse} }
sub description { $_[0]{flightPathDesc}  }

1;
