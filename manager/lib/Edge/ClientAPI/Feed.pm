package Edge::ClientAPI::Feed;
use common::sense;
use Try::Tiny;
use YAML::Tiny;
use Data::Dumper;
use Safe::Isa;
use Scalar::Util ();
use Edge::ClientAPI;
use Edge::ClientAPI::Feed::Config;
use Edge::ClientAPI::E
;

our $VS_NAME = 'Kubernetes IC external IP';

#sub __has_vs_in_array(\@$);
#sub __upsert_rss_by_ip_port(\@$$);
sub STOPPED { \&STOPPED }

sub new {
    my ($class, $creds, @input) = @_;
    die "API creds object is invalid"
        unless $creds->$_isa('Edge::ClientAPI::Creds');

    # Create client using cloned creds, because balancer IP may be changed.
    my $self = bless { cli   => undef,   creds  => $creds->clone,
                       input => \@input, config => undef }, $class;

    return $self;
}

sub creds  { $_[0]{creds}   }
sub cli    { $_[0]{cli}     }
sub input  { $_[0]{input}   }
sub config { $_[0]{config}  }

sub update_config {
    my $self = shift;
    $self->{config} = Edge::ClientAPI::Feed::Config->new($self->input);
    ()
}

sub process_until_done {
    my ($self, $success_cb) = @_;
    Scalar::Util::weaken($self);

    my $ok = 0;
    while () {
        last if $ok;
        last unless $self;

        try {
            $self->process($success_cb);
            $ok = 1;
        } catch {
            if ($_ eq STOPPED) {
                $ok = 1;
            } else {
                AE::log crit => "%s", $_;
                AE::log info => "Repeating feeding due to error...";
                $ok = 0;
                Coro::AnyEvent::sleep(1);
            }
        };
    }
    ()
}

sub process {
    my ($self, $success_cb) = @_;
    Scalar::Util::weaken($self);

    $self->update_config;
    AE::log info => "YAML parsed: %s", Dumper+$self->config;

    $self->creds->host($self->config->data_balancer_ip);
    $self->{cli} = Edge::ClientAPI::coro($self->creds);

    my ($vss, $hdr) = $self->cli->get_all_vs;
    die STOPPED unless $self;
    unless ($hdr->{Success}) {
        die e40_format(EDGE_ERROR, $hdr->{Detail});
    }

    my $vss_fps = $self->config->build_required_vss_fps;
    $vss = $self->delete_unused_vss($vss, $vss_fps);

    if ($vss_fps) {
        AE::log info => "VSs FPs: %s", Dumper+$vss_fps;
        $self->configure_used_vss($vss, $vss_fps);
        $self->add_new_vss($vss, $vss_fps);
    } else {
        AE::log info => "No Kubernetes VS/RS to be on the ADC";
    }

    my $config_version = $self->config->data->{config}{version};
    unless (length $self->config->data->{config}{version}) {
        AE::log warn => "No config version in config files; " .
                        "set config version to 0";
        $config_version = 0;
    }

    if (ref $success_cb eq 'CODE') {
        AE::log info => "Provide applied config version: %s", $config_version;
        $success_cb->($config_version);
    } else {
        AE::log warn => "No callback to return applied config version";
    }

    AE::log info => "\n" .
                    "-------------------------------------------------------\n".
                    "Congrats! Feeding done. Config version in use is %s.\n" .
                    "-------------------------------------------------------\n",
                    $config_version;
    ()
}

sub delete_unused_vss {
    my ($self, $vss, $vss_fps) = @_;
    Scalar::Util::weaken($self);

    AE::log info => "Delete unused VSs...";
    my @del;
    for my $el (@$vss) {
        for my $vs (@$el) {
            next unless $vs->service_name eq $VS_NAME;
            my $remove = 1;

            if ($vss_fps) {
                if ($vss_fps->has_vs($vs->ip, $vs->port)) {
                    $remove = 0;
                }
            }

            if ($remove) {
                # Delete only Kubernetes VS.
                push @del, [ $vs->ip, $vs->port ];
            }
        }
    }

    # Delete unused VSs.
    for (@del) {
        my ($vs_ip, $vs_port) = @$_;

        # Determine *actual* VS interface ID and channel ID.
        my $vs;
        my %edit;
        for my $el (@$vss) {
            for my $candidate (@$el) {
                if ($candidate->ip eq $vs_ip && $candidate->port eq $vs_port) {
                    $edit{editedInterface} = $candidate->interface_id;
                    $edit{editedChannel}   = $candidate->channel_id;
                    $vs = $candidate;
                    last;
                }
            }
        }

        unless (%edit) {
            AE::log warn => "Cannot find interface ID and channel ID for %s:%s",
                            $vs_ip, $vs_port;
            next;
        }

        AE::log info => "Removing VS %s/%s:%s...",
                        $vs->ip, $vs->subnet, $vs->port;

        my ($new_vss, $hdr) = $self->cli->delete_vs(\%edit);
        die STOPPED unless $self;

        if ($hdr->{Success}) {
            AE::log info => "VS removed: %s/%s:%s",
                            $vs->ip, $vs->subnet, $vs->port;
            # After deletion, IDs are changed. Use new ones.
            AE::log debug => "Use new VSs table after VS deletion";
            $vss = $new_vss; # Can be undefined.
        }
        else {
            AE::log error => "Couldn't remove VS %s/%s:%s",
                             $vs->ip, $vs->subnet, $vs->port;

            die e40_format(EDGE_ERROR, $hdr->{Detail});
        }
    }

    return $vss; # Return old or updated $vss after deletion.
}

sub configure_used_vss {
    my ($self, $vss_left, $vss_fps) = @_;
    die "Undefined VSS_FPS" unless $vss_fps;
    Scalar::Util::weaken($self);

    AE::log info => "Determine and configure VSs that exist...";

    unless (@$vss_left) {
        AE::log info => "No created VSs found; need to create all (if any)";
        return;
    }

    my @used;
    for my $el (@$vss_left) {
        for my $vs (@$el) {
            my $fps = $vss_fps->get_fps_by_vs($vs->ip, $vs->port);
            next unless $fps;
            # TODO: Mark if we need to change service name to $VS_NAME
            push @used, [ $vs, $fps ];
        }
    }

#    # Add/enable flightPATH
#    for my $pair (@used) {
#        my ($vs, $fps) = @$pair;
#        $fps->enum_fps_hashes(sub {
#            my ($fp, $sha1) = @_;
#            my $fp_name = "Kubernetes IC sha1 $sha1";
#
#            if ($vs->get_fp_names_by_regex($fp_name)) {
#                AE::log info => "FlightPATH %s is configured",
#                                $fp_name;
#            }
#            ()
#        });
#
#        die Dumper+$fps;
#
#        #$vs->has_fp_
#
#        AE::log info => "Remove all flightPATHs from VS %s/%s:%s...",
#                        $vs->ip, $vs->subnet, $vs->port;
#
#        my $names = $vs->get_fp_names_by_regex(qr!Kubernetes\s+Ingress\s+!);
#        next unless $names;
#
#        for my $name (@$names) {
#            AE::log info => "Clean existing VS %s/%s:%s from Kubernetes " .
#                            "Ingress flighPATH '%s'...",
#                       $vs->ip, $vs->subnet, $vs->port, $name;
#
#            # Unique flightPATH names are assigned to VSs. Enough to remove
#            # flightPATH from one VS.
#            my (undef, $hdr) = $self->cli->remove_fp_custom_forward(
#                                        [ $vs ], $name);
#            die STOPPED unless $self;
#
#            unless ($hdr->{Success}) {
#                die e40_format(EDGE_ERROR, $hdr->{Detail});
#            }
#        }
#    }

    for my $pair (@used) {
        my ($vs, $fps) = @$pair;
        AE::log info => "VS %s:%s/%s already created, configure only RSs...",
                        $vs->ip, $vs->subnet, $vs->port;
        $self->configure_vs_rss($vs, $fps);
    }

    ()
}


#sub __has_vs_in_array(\@$) {
#    my ($array, $vs) = @_;
#    die "Invalid VS object: $vs"
#        unless $vs->$_isa('Edge::ClientAPI::Object::VS');
#
#    return 0 unless $array && @$array;
#    for my $ip_port (@$array) {
#        my ($ip, $port) = @$ip_port;
#        if ($vs->ip eq $ip && $vs->port eq $port) {
#            return 1;
#        }
#    }
#
#    return 0;
#}

sub add_new_vss {
    my ($self, $vss_left, $vss_fps) = @_;
    die "Undefined VSS_FPS" unless $vss_fps;
    Scalar::Util::weaken($self);

    AE::log info => "Determine and configure VSs that are not created...";

    my @add;
    $vss_fps->enum(sub {
        my ($vs_fps) = @_;
        my $vs2 = $vs_fps->{vs};
        my $fps = $vs_fps->{fps};
        my $found = 0;

        for my $el (@$vss_left) {
            for my $vs (@$el) {
                if ($vs->ip eq $vs2->{ip} && $vs->port eq $vs2->{port}) {
                    $found = 1;
                    last;
                }
            }
        }

        unless ($found) {
            push @add, [ $vs2->{ip}, $vs2->{port}, $fps ];
        }
    });

    unless (@add) {
        AE::log info => "No new VSs to add";
        return;
    }

    for my $pair (@add) {
        my ($ip, $port, $fps) = @$pair;
        my $subnet = "255.255.255.255"; # TODO: Which one?

        AE::log info => "Create VS %s/%s:%s", $ip, $subnet, $port;
        my ($vs, $hdr) = $self->cli->create_vs(
                            $VS_NAME, $ip, $subnet, $port, 'HTTP');
        die STOPPED unless $self;

        unless ($hdr->{Success}) {
            die e40_format(EDGE_ERROR, $hdr->{Detail});
        }

        die sprintf "Couldn't find created VS %s/%s:%s",
                    $ip, $subnet, $port
            unless defined $vs;

        AE::log info => "Created VS %s/%s:%s; configure RSs...",
                        $vs->ip, $vs->subnet, $vs->port;

        $self->configure_vs_rss($vs, $fps);
    }
    ()
}

sub configure_vs_rss {
    my ($self, $vs, $fps) = @_;
    die "Invalid VS object: $vs"
        unless $vs->$_isa('Edge::ClientAPI::Object::VS');
    die "Invalid FPs object: $fps"
        unless $fps->$_isa('Edge::ClientAPI::Feed::FPS');
    Scalar::Util::weaken($self);

    AE::log info => "Configure flightPATH and RS of VS %s/%s:%s...",
                    $vs->ip, $vs->subnet, $vs->port;

    my %fp_sha1;
    $fps->enum_fps_hashes(sub {
        my ($fp, $sha1) = @_;
        my $fp_name = "Kubernetes IC sha1 $sha1";
        $fp_sha1{$fp_name} = 1;

        my $id  = $vs->get_fp_id_by_name($fp_name);
        my $idx = $vs->get_fp_idx_by_name($fp_name);
        if (!defined $id) {
            AE::log info => "Create flightPATH with name '%s'...", $fp_name;

            my (undef, $hdr) = $self->cli->create_fp_custom_forward(
                    $fp->{hostname},
                    undef, # Arrayref with VSs that have flightPATH by the name.
                    $vs->ip, $vs->port,
                    $fp_name,
                    'Edgenexus-Manager',
                    $fp->{rss}[0]{ip},
                    $fp->{rss}[0]{port},
                    $fp->{path},
            );
            die STOPPED unless $self;
            die e40_format(EDGE_ERROR, $hdr->{Detail}) unless $hdr->{Success};

            AE::log info => "Created and enabled flightPATH '%s' for %s/%s:%s",
                            $fp_name, $vs->ip, $vs->subnet, $vs->port;
        }
        elsif (!defined $idx) {
            AE::log info => "Enable existing flightPATH with name '%s'...",
                            $fp_name;
            my (undef, $hdr) = $self->cli->apply_fp_by_name($fp_name, $vs);
            die STOPPED unless $self;
            die e40_format(EDGE_ERROR, $hdr->{Detail}) unless $hdr->{Success};

            AE::log info => "Enabled flightPATH '%s' for %s/%s:%s",
                            $fp_name, $vs->ip, $vs->subnet, $vs->port;
        }
        else {
            AE::log info => "flightPATH with name '%s' is already enabled",
                            $fp_name;
        }

        ()
    });

    if (1) {
        # TODO: enable only this one:
        #my $names = $vs->get_fp_names_by_regex(qr!Kubernetes\s+IC\s+!);
        my $names = $vs->get_fp_names_by_regex(qr!Kubernetes\s+!);

        my $first = 1;
        for my $name (@$names) {
            next if exists $fp_sha1{$name};
            if ($first) {
                AE::log info => "Unapply not used flightPATHs from VS %s/%s:%s...",
                                $vs->ip, $vs->subnet, $vs->port;
                $first = 0;
            }

            AE::log info => "Unapply flightPATH '%s' on VS %s/%s:%s...",
                            $name, $vs->ip, $vs->subnet, $vs->port;

            my (undef, $hdr) = $self->cli->unapply_fp_by_name($name, $vs);
            die STOPPED unless $self;

            unless ($hdr->{Success}) {
                die e40_format(EDGE_ERROR, $hdr->{Detail});
            }

            AE::log info => "flightPATH '%s' is unapplied", $name;
        }
    }

    my $rss = $fps->get_unique_rss;
    AE::log info => "Configure RSs on VS %s/%s:%s...",
                    $vs->ip, $vs->subnet, $vs->port;
    AE::log info => "VS %s/%s:%s must have %u RS(s)",
                    $vs->ip, $vs->subnet, $vs->port;

    my @add_rss;
    for my $rs (@$rss) {
        AE::log info => "Check if RS %s:%s exists...", $rs->{ip}, $rs->{port};

        if ($vs->has_rs($rs->{ip}, $rs->{port})) {
            AE::log info => "RS %s:%s exists", $rs->{ip}, $rs->{port};
            #next;
        }

        push @add_rss, { ip => $rs->{ip}, port => $rs->{port} };
        AE::log info => "RS %s:%s must be added to VS", $rs->{ip}, $rs->{port};
    }

    my @del_rss;
    if (1) {
        AE::log info => "Determine if there's some RS for removal...";
        $vs->enum_rs(sub {
            my ($hash) = @_;
            my ($_ip, $_port) = ($hash->{CSIPAddr}, $hash->{CSPort});
            my $found;

            for my $rs (@$rss) {
                if ($rs->{ip} eq $_ip && $rs->{port} == $_port) {
                    $found = 1;
                    last;
                }
            }

            unless ($found) {
                push @del_rss, [ $_ip, $_port ];
                AE::log info => "RS %s:%s must be removed from VS",
                                $_ip, $_port;
            }
        });
    }

    AE::log info => "Need to add new %u RSS(s)", scalar @add_rss;
    AE::log info => "Need to delete %u RS(s)",   scalar @del_rss;

    for (@del_rss) {
        my ($_ip, $_port) = @$_;
        AE::log info => "Remove RS %s:%s...", $_ip // 'NULL', $_port // 'NULL';
        my (undef, $hdr) = $self->cli->remove_rs_by_specs(
                    { addr => $_ip, port => $_port },
                    $vs->ip, $vs->subnet, $vs->port
        );
        die STOPPED unless $self;

        unless ($hdr->{Success}) {
            die e40_format(EDGE_ERROR, $hdr->{Detail});
        } else {
            if (length $_ip) {
                AE::log info => "Removed not used RS %s:%s from VS %s/%s:%s",
                                $_ip, $_port, $vs->ip, $vs->subnet, $vs->port;
            }
            else {
                AE::log info => "Removed empty RS from VS %s/%s:%s",
                                $vs->ip, $vs->subnet, $vs->port;
            }
        }
    }

    if (@add_rss) {
        my @rss_ref;
        for my $rs (@add_rss) {
            push @rss_ref, { addr => $rs->{ip}, port => $rs->{port} };
        }

        AE::log info => "Add missed RSs: %s", Dumper+\@rss_ref;
        my ($vs, $hdr) = $self->cli->init_rs_multi_by_specs(
            \@rss_ref, $vs->ip, $vs->subnet, $vs->port);
        die STOPPED unless $self;

        unless ($hdr->{Success}) {
            die e40_format(EDGE_ERROR, $hdr->{Detail});
        }

        AE::log info => "Add all RSs for VS %s/%s:%s",
                        $vs->ip, $vs->subnet, $vs->port;
    }

    AE::log info => "VS %s/%s:%s is completely configured",
                    $vs->ip, $vs->subnet, $vs->port;
    ()
}

#sub __upsert_rss_by_ip_port(\@$$) {
#    my ($rss, $ip, $port) = @_;
#    for (@$rss) {
#        if ($_->{ip} eq $ip && $_->{port} eq $port) {
#            return $_;
#        }
#    }
#
#    my %rs = (
#        ip   => $ip,
#        port => $port,
#    );
#
#    push @$rss, \%rs;
#    return \%rs;
#}

1;
