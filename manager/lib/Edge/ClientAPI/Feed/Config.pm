package Edge::ClientAPI::Feed::Config;
use common::sense;
use Try::Tiny;
use YAML::Tiny;
use Data::Dumper;
use Safe::Isa;
use Edge::ClientAPI::Feed::FPS;
use Edge::ClientAPI::Feed::VSS_FPS;
use Edge::ClientAPI::E
    API_FEED_INVALID_YAML_INPUT => [ 5750, "Input YAML input (use file name or data reference)" ],
    API_FEED_INVALID_YAML_DATA  => [ 5751, "Input YAML data (must be a hash)" ],
    API_FEED_INVALID_YAML_SERVICES => [ 5752, "Invalid services (must be an array)" ],
    API_FEED_INVALID_YAML_UPSTREAMS => [ 5753, "Invalid upstreams (must be an array)" ],
;

sub __read_file($);
sub __read_yaml(\@);

sub new {
    my ($class, $input) = @_;
    my $yaml = __read_yaml @$input;
    my $self = bless { yaml => $yaml }, $class;
    return $self;
}

sub data  { $_[0]{yaml}[0] }
sub data_services  { $_[0]->data->{services}  } # Arrayref (can be empty).
sub data_upstreams { $_[0]->data->{upstreams} } # Arrayref (can be empty).

sub data_balancer_ip { $_[0]->data->{balancer_ip} } # Always defined.
sub data_external_ip { $_[0]->data->{external_ip} } # Always defined.

sub build_required_vss_fps {
    my ($self) = @_;

    my $vss_array = $self->_get_unique_vss_to_run;
    unless ($vss_array) {
        AE::log info => "No VSs to set on the balancer";
        return undef;
    }

    my $vss_fps = Edge::ClientAPI::Feed::VSS_FPS->new;
    for (@$vss_array) {
        my ($vs_ip, $vs_port) = @$_;
        my $fps = Edge::ClientAPI::Feed::FPS->new($self, $vs_ip, $vs_port);
        $vss_fps->add($vs_ip, $vs_port, $fps);
    }

    return $vss_fps;
}


sub get_upstream_by_name {
    my ($self, $name) = @_;
    Scalar::Util::weaken($self);

    die "No upstream name in arguments" unless length $name;
    my $upstreams = $self->data_upstreams;

    my $found;
    for (@$upstreams) {
        if ($_->{name} eq $name) {
            return $_;
        }
    }

    return undef;
}



sub make_adc_commands {
    my ($self, $vss, %args) = @_;
    my @commands;
    #my $vss_array = $self->_get_unique_vss_to_run;
    #
    #if ($vss_array) {
    #    # Check what VSs are not created.
    #    AE::log info => "Need to run %u VSs for Ingress Controller",
    #                    scalar @$vss_array;
    #
    #} else {
    #    AE::log info => "No VSs for Ingress Controller";
    #
    #}
    #
    #exit;
    #
    #my $vs_ingress  = $self->find_ingress_vs;
    #
    #unless ($vs_ingress) {
#        AE::log info => "Ingress VS with IP %s is not found on the ADC",
#                        $external_ip;
#        push @commands, '';
   # }
   # else {
   #
  # }



 #   for my $el (@$vss) {
 #       for my $vs (@$el) {
 #           if ($vs->ip ne $external_ip || !@{$self->data_services}) {
 #               push @del, [ $vs->ip, $vs->port ];
 #           }
 #       }
 #   }




}

#sub find_ingress_vs {
#    my ($self, $vss) = @_;
#    my $external_ip = $self->data_external_ip;
#
#    for my $el (@$vss) {
#        for my $vs (@$el) {
#            if ($vs->ip eq $external_ip) {
#                return $vs;
#            }
#        }
#    }
#
#    return undef;
#}


sub _get_unique_vss_to_run {
    my ($self) = @_;

    my $services    = $self->data_services;
    my $external_ip = $self->data_external_ip;

    my @vss_array;
    my %uniq;
    for my $service (@$services) {
        my $listeners = $service->{listeners};
        next unless $listeners && @$listeners;
        for my $lst (@$listeners) {
            my $port = $lst->{port};
            next unless $port > 0 && $port <= 0xFFFF;
            my $ip = $lst->{address};
            $ip = $external_ip unless length $ip;
            $uniq{"$ip:$port"} = [ $ip, $port ];
        }
    }

    return undef unless %uniq;

    for (sort keys %uniq) {
        # TODO: Add SSL details when port is 443 (or SSL is TRUE).
        push @vss_array, $uniq{$_}; # [ IP, PORT ]
    }

    return \@vss_array;
}

sub __read_yaml(\@) {
    my ($input) = @_;

    my $data;
    for (@$input) {
        if (ref $_ eq 'SCALAR') {
            # String data.
            $data .= "\n" . $$_;
        } elsif (!ref $_) {
            # File or directory path.
            if (m!/$!) {
                # Directory path. Get all files in directory and read them.
                my @files = <$_*.yaml>;
                for my $filepath (@files) {
                    AE::log info => "Open EdgeNEXUS Manager config file: %s",
                                    $filepath;
                    $data .= "\n---\n";
                    $data .= __read_file $filepath;
                }
            } else {
                # File path.
                AE::log info => "Open EdgeNEXUS Manager config file: %s", $_;
                $data .= "\n---\n";
                $data .= __read_file $_;
            }
        }
        else {
            die e40 API_FEED_INVALID_YAML_INPUT;
        }
    }

    AE::log info => "Config %s", $data;

    my $yaml = +{};
    my $yaml = YAML::Tiny->read_string($data); # Data can be empty.
    unless ($yaml) {
        die e40 API_FEED_INVALID_YAML_DATA;
    }

    # Merge all in one.
    for (my $i = 1; $i < @$yaml; $i++) {
        my $el = $yaml->[$i];
        next unless ref $el eq 'HASH';
        for my $key (sort keys %$el) {
            my $val = $el->{$key};
            if ($key eq 'services' || $key eq 'upstreams') {
                # Merge arrays.
                next unless ref $val eq 'ARRAY';
                for my $copy_el (@$val) {
                    push @{$yaml->[0]->{$key}}, $copy_el;
                }
            }
            elsif ($key eq 'config') {
                # Config hash.
                $yaml->[0]->{config} = $val;
            }
            elsif (!ref $val) {
                # Strings.
                $yaml->[0]->{$key} = $val;
            }
            else {
                # Ignore such value.
            }
        }

        $yaml->[$i] = undef;
    }

    unless (defined $yaml->[0]{services}) {
        # It is allowed that no `services` are defined.
        $yaml->[0]{services} = [];
    }
    elsif (ref $yaml->[0]{services} ne 'ARRAY') {
        die e40 API_FEED_INVALID_YAML_SERVICES;
    }

    unless (defined $yaml->[0]{upstreams}) {
        # It is allowed that no `upstreams` are defined.
        $yaml->[0]{upstreams} = [];
    }
    elsif (ref $yaml->[0]{upstreams} ne 'ARRAY') {
        die e40 API_FEED_INVALID_YAML_UPSTREAMS;
    }

    unless (length $yaml->[0]{balancer_ip}) {
        $yaml->[0]{balancer_ip} = "127.0.0.1"; # Dummy value.
    }
    unless (length $yaml->[0]{external_ip}) {
        $yaml->[0]{external_ip} = "127.0.0.2"; # Dummy value.
    }

    return $yaml;
}

sub __read_file($) {
    my $filepath = shift;
    my $fh;
    unless (open $fh, '<', $filepath) {
        die sprintf "Couldn't read file '%s': %s\n", $filepath, $!;
    }
    my $data = do { local $/ = undef; <$fh> };
    close $fh;

    return $data;
}

1;

__DATA__
    my $subnet;

    unless (@rss && @flight_paths) {
        die sprintf "No RSs addresses and/or flightPATHs for VS %s:%s",
                    $ip, $port;
    }

    if (1) {
        AE::log info => "VS %s:%s must have %u RS(s)", $ip, $port, scalar @rss;

        my @rss_ref;
        for my $rs (@rss) {
            push @rss_ref, { addr => $rs->{ip}, port => $rs->{port} };
        }

        my ($vs, $hdr) = $self->cli->init_rs_multi_by_specs(
            \@rss_ref, $ip, $subnet, $port);
#        die STOPPED unless $self;

        unless ($hdr->{Success}) {
            die e40_format(EDGE_ERROR, $hdr->{Detail});
        }

        AE::log info => "Created all RSs for VS %s/%s:%s", $ip, $subnet, $port;
        AE::log info => "Determine if there's some RS for deletion...";

        my @del;
        $vs->enum_rs(sub {
            my ($hash) = @_;
            my ($_ip, $_port) = ($hash->{CSIPAddr}, $hash->{CSPort});
            my $found;
            for my $rs (@rss) {
                if ($rs->{ip} eq $_ip && $rs->{port} == $_port) {
                    $found = 1;
                    last;
                }
            }
            unless ($found) {
                push @del, [ $_ip, $_port ];
            }
        });

        if (@del) {
            AE::log info => "Need to delete %u RS(s)", scalar @del;
            for (@del) {
                my ($_ip, $_port) = @$_;
                my (undef, $hdr) = $self->cli->remove_rs_by_specs({ addr => $_ip, port => $_port }, $ip, $subnet, $port);
#                die STOPPED unless $self;

                unless ($hdr->{Success}) {
                    die e40_format(EDGE_ERROR, $hdr->{Detail});
                } else {
                    if (length $_ip) {
                        AE::log info => "Removed not used RS %s:%s from VS %s/%s:%s",
                                        $_ip, $_port, $ip, $subnet, $port;
                    }
                    else {
                        AE::log info => "Removed empty RS from VS %s/%s:%s",
                                        $ip, $subnet, $port;
                    }
                }
            }
        }
    }

    if (1) {
        AE::log trace => "FlightPATHs structure: %s", Dumper+\@flight_paths;

        for my $fp (@flight_paths) {
            my $rs_ip;
            my $rs_port;
            for (@{$fp->{rss}}) {
                $rs_ip   = $_->{ip};
                $rs_port = $_->{port};
            }

            my $fp_name = "Kubernetes Ingress " . AE::time;
            my (undef, $hdr) = $self->cli->create_fp_custom_forward(
                    $fp->{hostname},
                    undef, # Arrayref with VSs that have flightPATH by the name.
                    $ip, $port,
                    $fp_name,
                    'EdgeCertMgr',
                    $rs_ip,
                    $rs_port,
                    $fp->{path}
            );
#            die STOPPED unless $self;

            unless ($hdr->{Success}) {
                die e40_format(EDGE_ERROR, $hdr->{Detail});
            }

            AE::log info => "Created and enabled flightPATH '%s' for %s/%s:%s",
                            $fp_name, $ip, $subnet, $port;
        }
    }

    AE::log info => "VS %s/%s:%s is completely configured",
                    $ip, $subnet, $port;
    ()
