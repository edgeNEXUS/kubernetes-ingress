package Edge::ClientAPI::Object::VS;
use common::sense;

sub bless {
    my ($class, $href) = @_;
    die "No VS hashref: $href" unless ref $href eq 'HASH';
    CORE::bless $href, $class;
}

sub service_type { $_[0]{serviceType} }
sub ip           { $_[0]{ipAddr}      }
sub subnet       { $_[0]{subnetMask}  }
sub port         { $_[0]{port}        }

sub fp {
    my ($self) = @_;
    my $fp = $self->{flightPath};
    return undef unless ref $fp eq 'HASH';
    return undef unless ref $fp->{flightPathId} eq 'ARRAY';
    return $self->{flightPath};
}

sub get_fp_id_by_name {
    my ($self, $name) = @_;
    return undef unless length $name;
    my $fp = $self->fp;
    return undef unless $fp;

    for (@{$fp->{flightPathId}}) {
        if ($_->{Name} eq $name) {
            return $_->{fId};
        }
    }

    return undef;
}

sub get_fp_idx_by_name {
    my ($self, $name) = @_;
    return undef unless length $name;
    my $fp = $self->fp;
    return undef unless $fp;

    for (@{$fp->{flightPathId}}) {
        if ($_->{Name} eq $name) {
            if ($_->{flightPathSelected} > 0) {
                return $_->{flightPathSelected};
            }
            return undef; # Not enabled/applied.
        }
    }

    return undef;
}

sub get_fp_name_by_idx {
    my ($self, $fp_idx) = @_;
    return undef unless $fp_idx > 0;
    my $fp = $self->fp;
    return undef unless $fp;

    for (@{$fp->{flightPathId}}) {
        if ($_->{flightPathSelected} == $fp_idx) {
            return $_->{Name};
        }
    }

    return undef;
}

sub get_fp_names_by_regex {
    my ($self, $regex) = @_;
    return undef unless ref $regex eq 'Regexp';
    my $fp = $self->fp;
    return undef unless $fp;

    my %names;
    for (@{$fp->{flightPathId}}) {
        if ($_->{Name} =~ $regex) {
            if ($_->{flightPathSelected} > 0) {
                $names{$_->{Name}} = 1;
            } else {
                # Not enabled/applied.
            }
        }
    }

    return %names ? [ sort keys %names ] : undef;
}

sub get_fp_names_all_by_regex {
    my ($self, $regex) = @_;
    return undef unless ref $regex eq 'Regexp';
    my $fp = $self->fp;
    return undef unless $fp;

    my %names;
    for (@{$fp->{flightPathId}}) {
        if ($_->{Name} =~ $regex) {
            # Set flag if flightPATH is applied to the VS.
            $names{$_->{Name}} = $_->{flightPathSelected} ? 1 : 0;
        }
    }

    return %names ? \%names : undef;
}

sub is_enabled {
    my ($self) = @_;
    return $self->{localPortEnabledChecked} eq 'true' ? 1 : 0;
}

sub is_online {
    my ($self) = @_;
    # Rely on interfaceStatusReason, not channelStatusReason
    return $self->{interfaceStatusReason} eq 'Online' ? 1 : 0;
}

sub has_connected_rs {
    my ($self) = @_;
    return 0 unless ref $self->{contentServer} eq 'HASH';
    my $rss = $self->{contentServer}{CServerId};
    return 0 unless ref $rss eq 'ARRAY' && @$rss;

    for my $hash (@$rss) {
        if ($hash->{statusReason} eq 'Connected') {
            return 1;
        }
    }

    return 0;
}

sub is_same_vip {
    my ($self, $vip) = @_;
    # $vip is "{ip}/{subnet}:{port}
    my $vip_cmp = sprintf "%s/%s:%s", $self->ip, $self->subnet, $self->port;
    return $vip_cmp eq $vip ? 1 : 0;
}

sub has_fp_by_name {
    my ($self, $fp_name) = @_;
    my $id = $self->get_fp_id_by_name($fp_name);
    return defined $id ? 1 : 0;
}

sub has_rs {
    my ($self, $addr, $port) = @_;
    return 0 unless ref $self->{contentServer} eq 'HASH';
    my $rss = $self->{contentServer}{CServerId};
    return 0 unless ref $rss eq 'ARRAY' && @$rss;

    for my $hash (@$rss) {
        if ($hash->{CSIPAddr} eq $addr &&
            $hash->{CSPort}   == $port) {
            return 1;
        }
    }

    return 0;
}

sub enum_rs {
    my ($self, $cb) = @_;
    return unless ref $self->{contentServer} eq 'HASH';
    my $rss = $self->{contentServer}{CServerId};
    return unless ref $rss eq 'ARRAY' && @$rss;

    for my $hash (@$rss) {
        # Return even empty RS that has no length at $hash->{CSIPAddr}.
        $cb->($hash); # CSIPAddr and CSPort define RS IP/Port.
    }
    ()
}

sub ssl_certificate_names_aref {
    my $self = shift;
    return undef unless length $self->ssl_certificate_names;

    my @names = split /,/, $self->ssl_certificate_names;
    my %valid;
    for (@names) {
        if (length $_) {
            $valid{$_}++;
        }
    }

    return %valid ? [ sort keys %valid ] : undef;
}

sub has_ssl_certificate_name {
    my ($self, $name) = @_;
    my $names = $self->ssl_certificate_names_aref;
    return 0 unless defined $names;

    for (@$names) {
        if ($_ eq $name) {
            return 1; # Certificate name exists
        }
    }

    return 0;
}

sub has_same_ssl_certificate_names {
    my ($self, $aref) = @_;
    my $names = $self->ssl_certificate_names_aref;
    unless (defined $aref && @$aref) {
        return 1 unless defined $names; # Both are with no names.
        return 0;
    }

    return 0 unless defined $names; # $aref is not empty, but VS is.

    # @$names and @$aref are not empty array refs.
    my %hash;
    $hash{$_} .= 'vs'    for @$names;
    $hash{$_} .= 'found' for @$aref;

    for my $name (sort keys %hash) {
        my $val = $hash{$name};
        unless ($val eq 'vsfound') {
            return 0;
        }
    }

    return 1;
}

sub service_name { $_[0]{serviceName} }
sub interface_id { $_[0]{InterfaceID} }
sub channel_id   { $_[0]{ChannelID}   }
sub channel_key  { $_[0]{ChannelKey}  }

sub ssl_certificate_names { $_[0]{sslCertificate} } # Comma-separated: no spaces

1;
