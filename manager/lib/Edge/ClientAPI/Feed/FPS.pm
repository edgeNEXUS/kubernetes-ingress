package Edge::ClientAPI::Feed::FPS;
use common::sense;
use Try::Tiny;
use YAML::Tiny;
use Data::Dumper;
use Safe::Isa;
use Digest::SHA;
use Edge::ClientAPI::E;

sub new {
    my ($class, $config, $vs_ip, $vs_port) = @_;
    my $fps_aref = __get_fps_for_vs($config, $vs_ip, $vs_port);
    return bless $fps_aref, $class;
}

sub __upsert_rss_by_ip_port(\@$$) {
    my ($rss, $ip, $port) = @_;
    for (@$rss) {
        if ($_->{ip} eq $ip && $_->{port} eq $port) {
            return $_;
        }
    }

    my %rs = (
        ip   => $ip,
        port => $port,
    );

    push @$rss, \%rs;
    return \%rs;
}

sub __get_fps_for_vs {
    my ($config, $ip, $port) = @_;
    my $services    = $config->data_services;
    my $external_ip = $config->data_external_ip;

    my @rss; # All RSs addresses (IP/Port) for the VS.
    my @flight_paths;

    for my $svc (@$services) {
        my $hostname = $svc->{hostname};
        next unless length $hostname;

        my $listeners = $svc->{listeners};
        next unless $listeners && @$listeners;

        for my $lst (@$listeners) {
            next unless $lst->{port};
            my $address = $lst->{address};
            $address = $external_ip unless length $address;
            unless ($address eq $ip) {
                next;
            }
            unless ($lst->{port} eq $port) {
                next;
            }

            # No duplicates are expected in `listeners` of `services`.
            last;
        }

        my $locations = $svc->{locations};
        next unless $locations && @$locations;

        # Collect addressed and ports of used RSs.
        my $has_local = 1;
        for my $loc (@$locations) {
            my $upstream_name = $loc->{upstream};
            unless (length $upstream_name) {
                AE::log warn => "Upstream name is not set in locations";
                next;
            }

            my $upstream = $config->get_upstream_by_name($upstream_name);
            unless ($upstream) {
                AE::log error => "Upstream is not found by name %s",
                                 $upstream_name;
                next;
            }
            my $servers = $upstream->{servers};
            unless ($servers && @$servers) {
                AE::log error => "Upstream is without servers";
                next;
            }

            my @fp_rss;
            for my $svr (@$servers) {
                next unless $svr->{address};
                next unless $svr->{port};

                # Add only unique IP/Port.
                my $rs = __upsert_rss_by_ip_port
                                @rss, $svr->{address}, $svr->{port};

                push @fp_rss, $rs;
            }

            unless (@fp_rss) {
                AE::log warn => "No addresses for RS found in analyzed " .
                                "'location'; no need to configure " .
                                "flaghtPATHs as well";
                next;
            }

            my $rss_str;
            for my $rs (@fp_rss) {
                $rss_str .= ", " if length $rss_str;
                $rss_str .= "$rs->{ip}:$rs->{port}";
            }

            AE::log info => "Define flightPATH related to RSs: %s...", $rss_str;
            my %flight_path = (
                # For FP conditions.
                hostname     => $hostname,
                path         => $loc->{path},
                # For FP actions.
                rewrite      => $loc->{rewrite},
                real_ip_from => $svc->{real_ip_from},
                rss          => \@fp_rss,
            );

            push @flight_paths, \%flight_path;
        }
    }

    unless (@rss && @flight_paths) {
        die sprintf "No RSs addresses and/or flightPATHs for VS %s:%s",
                    $ip, $port;
    }

    #return @flight_paths ? \@flight_paths : undef;
    return \@flight_paths;
}

sub get_unique_rss {
    my $self = shift;

    my %uniq;
    for my $fp (@$self) {
        my $rss = $fp->{rss};
        for my $rs (@$rss) {
            my $rs_str = "$rs->{ip}:$rs->{port}";
            next if exists $uniq{$rs_str};
            $uniq{$rs_str} = $rs;
        }
    }

    return [ values %uniq ];
}

sub enum_fps_hashes {
    my ($self, $cb) = @_;
    die "No callback" unless ref $cb eq 'CODE';
    for my $fp (@$self) {
        my $data = '';
        for my $key (sort keys %$fp) {
            my $value = $fp->{$key};
            if ($key eq 'rss') {
                for my $ip_port_hash (@$value) {
                    $data .= "|" if length $data;
                    $data .= "$key=$ip_port_hash->{ip}:$ip_port_hash->{port}";
                }
            }
            elsif (!ref $value) {
                $data .= "|" if length $data;
                $data .= "$key=$value";
            } elsif (ref $value eq 'ARRAY') {
                $data .= "|" if length $data;
                $data .= "$key=" . join(',', @$value);
            } else {
                die "Not supported type to make hash";
            }
        }
        my $digest = Digest::SHA::sha1_hex($data);
        $cb->($fp, $digest);
    }
    ()
}

sub get_fps_names {
    my $self = shift;
    my %names;
    $self->enum_fps_hashes(sub {
        my ($fp, $sha1) = @_;
        my $fp_name = "Kubernetes IC sha1 $sha1";
        $names{$fp_name} = 1;
    });

    return %names ? \%names : undef;
}

1;
