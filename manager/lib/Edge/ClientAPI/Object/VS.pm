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

sub service_name { $_[0]{serviceName} }
sub interface_id { $_[0]{InterfaceID} }
sub channel_id   { $_[0]{ChannelID}   }
sub channel_key  { $_[0]{ChannelKey}  }

1;
