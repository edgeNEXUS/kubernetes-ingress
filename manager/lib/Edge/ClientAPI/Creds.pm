package Edge::ClientAPI::Creds;
use common::sense;
use Carp;
use Data::Dumper;
use Edge::ClientAPI;
use Edge::ClientAPI::Request;
use Edge::ClientAPI::E
    API_CREDS_IP_INVALID       => [ 1000, "Invalid ADC IP"       ],
    API_CREDS_USERNAME_INVALID => [ 1001, "Invalid ADC username" ],
    API_CREDS_PASSWORD_INVALID => [ 1002, "Invalid ADC password" ],
    API_CREDS_GUID_INVALID     => [ 1003, "Invalid ADC GUID"     ],
    API_CREDS_AUTH_IMPOSSIBLE  => [ 1004, "ADC API username and password required" ],
;

sub new {
    my ($class, %args) = @_;

    # Set default values.
    $args{host} = "127.0.0.1" unless defined $args{host};
    $args{port} = 443         unless defined $args{port};

    my $self = bless +{}, $class;

    $self->host($args{host}); # Required.
    $self->port($args{port}); # Required.

    $self->guid($args{guid})
        if exists $args{guid};

    $self->user($args{user})
        if exists $args{user};

    $self->pass($args{pass})
        if exists $args{pass};

    return $self;
}

sub ready_to_use { # $self
    # For API client creds must contain userpass or GUID.
    return $_[0]->has_userpass || $_[0]->has_guid;
}

sub ensure_ready_to_use { # $self
    my $self = shift;

    die e40 API_CREDS_AUTH_IMPOSSIBLE
        unless $self->ready_to_use;

    return 1;
}

sub host { # $self [, $host ]
    my $self = shift;

    if (@_) {
        die e40 API_CREDS_IP_INVALID
            unless Edge::ClientAPI::Request::is_valid_ip $_[0];

        $self->{host} = $_[0]; # Required.
    }

    return $self->{host};
}

sub port { # $self [, $host ]
    my $self = shift;

    if (@_) {
        my $port = shift;
        Edge::ClientAPI::Data::validate_port($port);
        $self->{port} = $port; # Required.
    }

    return $self->{port};
}

sub guid { # $self [, $guid ]
    my $self = shift;

    if (@_) {
        if (defined $_[0]) {
            die e40 API_CREDS_GUID_INVALID
                unless Edge::ClientAPI::Request::is_valid_guid $_[0];
        }

        $self->{guid} = $_[0]; # Can be undefined.
    }

    return $self->{guid};
}

sub userpass { # $self [, $user, $pass ]
    my $self = shift;

    if (@_) {
        die e40 API_CREDS_USERNAME_INVALID
            unless Edge::ClientAPI::Request::is_valid_username $_[0];

        die e40 API_CREDS_PASSWORD_INVALID
            unless Edge::ClientAPI::Request::is_valid_password $_[1];

        $self->{user} = $_[0]; # Required.
        $self->{pass} = $_[1]; # Required.
    }

    return ($self->{user}, $self->{pass});
}

sub user { # $self [, $username ]
    my $self = shift;

    if (@_) {
        die e40 API_CREDS_USERNAME_INVALID
            unless Edge::ClientAPI::Request::is_valid_username $_[0];

        $self->{user} = $_[0]; # Required.
    }

    return $self->{user};
}

sub pass { # $self [, $password ]
    my $self = shift;

    if (@_) {
        die e40 API_CREDS_PASSWORD_INVALID
            unless Edge::ClientAPI::Request::is_valid_password $_[0];

        $self->{pass} = $_[0]; # Required.
    }

    return $self->{pass};
}

sub has_userpass { # $self
    return defined $_[0]{user} && defined $_[0]{pass};
}

sub has_user { # $self
    return defined $_[0]{user};
}

sub has_pass { # $self
    return defined $_[0]{pass};
}

sub has_guid { # $self
    return defined $_[0]{guid};
}

sub get_url {
    my $self = shift;
    return sprintf "https://%s:%u", $self->host, $self->port;
}

sub clone { # $self
    my $self = shift;
    my %copy = %$self;
    for (sort keys %$self) {
        $copy{$_} = $self->{$_};
    }

    return bless \%copy, ref $self;
}

1;
