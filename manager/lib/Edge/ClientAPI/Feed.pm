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

our $VS_NAME                  = 'KUBERNETES INGRESS IP ';
our $VS_INT_NAME              = 'INT_VIP for ';
# FPs are set for $VS_NAME, not for $VS_INT_NAME.
our $QR_FP_NAME_KUBERNETES_IC = qr!^Kube-IC .+-[0-9a-f]{8}$!;

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
                Coro::AnyEvent::sleep(5);
            }
        };
    }
    ()
}

sub process {
    my ($self, $success_cb) = @_;
    die "No success callback" unless ref $success_cb eq 'CODE';

    Scalar::Util::weaken($self);

    $self->update_config;
    AE::log info => "YAML parsed: %s", Dumper+$self->config;

    my $balancer_host = (defined $ENV{EDGE_TEST_API_HOST} &&
                         length $ENV{EDGE_TEST_API_HOST})
        ? $ENV{EDGE_TEST_API_HOST}
        : $self->config->data_balancer_ip;
    my $balancer_user = (defined $ENV{EDGE_TEST_API_USER} &&
                         length $ENV{EDGE_TEST_API_USER})
        ? $ENV{EDGE_TEST_API_USER}
        : $self->config->data_balancer_user;
    my $balancer_pass = (defined $ENV{EDGE_TEST_API_PASS} &&
                         length $ENV{EDGE_TEST_API_PASS})
        ? $ENV{EDGE_TEST_API_PASS}
        : $self->config->data_balancer_pass;

    $self->creds->host($balancer_host);
    $self->creds->user($balancer_user);
    $self->creds->pass($balancer_pass);

    $self->{cli} = Edge::ClientAPI::coro($self->creds);

    my ($vss, $hdr) = $self->cli->get_all_vs;
    die STOPPED unless $self;
    unless ($hdr->{Success}) {
        die e40_format(EDGE_ERROR, $hdr->{Detail});
    }

    my $vss_fps = $self->config->build_required_vss_fps;

    # Step 1: Delete unused VSs.
    $vss = $self->delete_unused_vss($vss, $vss_fps); # VSS FPS can be undefined.

    if ($vss_fps) {
        AE::log trace => "VSs FPs: %s", Dumper+$vss_fps;
        # Step 2: Configure VSs that exist on the ADC.
        $self->configure_used_vss($vss, $vss_fps);
        # Step 3: Add new VSs to the ADC and configure them.
        $self->add_new_vss_and_configure($vss, $vss_fps);
    } else {
        AE::log info => "No Kubernetes VS/RS to be set on the ADC";
    }

    # TODO: move below.
    $self->remove_not_used_fps($vss_fps);
    $self->remove_not_used_ssl_certs($vss_fps);

    my $config_version = $self->config->data->{config}{version};
    unless (length $self->config->data->{config}{version}) {
        AE::log warn => "No config version in config files; " .
                        "set config version to 0";
        $config_version = 0;
    }

    AE::log info => "Provide applied config version: %s", $config_version;
    $success_cb->($config_version);

    AE::log info => "\n" .
                    "-------------------------------------------------------\n".
                    "Congrats! Feeding done. Config version in use is %s.\n" .
                    "-------------------------------------------------------\n",
                    $config_version;

    # Step 4: Optionally, delete outdated Kubernetes FPs and SSL certs.
    # In the above code, we remove FPs as soon as possible. Sometimes, due to
    # errors, FP may be kept on the ADC.

    # TODO: enable after tests.
    #$self->remove_not_used_fps($vss_fps);
    #$self->remove_not_used_ssl_certs($vss_fps);

    ()
}

sub delete_unused_vss {
    my ($self, $vss, $vss_fps) = @_;
    if (defined $vss_fps) {
        die "Invalid VSS FPS"
            unless $vss_fps->$_isa('Edge::ClientAPI::Feed::VSS_FPS');
    }
    Scalar::Util::weaken($self);

    AE::log info => "Delete unused VSs...";
    my @del;
    for my $el (@$vss) {
        for my $vs (@$el) {
            next unless $vs->service_name =~ /^\Q$VS_NAME\E/ ||
                        $vs->service_name =~ /^\Q$VS_INT_NAME\E/;
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

    unless (@del) {
        AE::log debug => "No VSs to be deleted";
    } else {
        AE::log trace => "VSs to be deleted:\n%s", Dumper+\@del;
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
    die "Invalid VSS FPS"
        unless $vss_fps->$_isa('Edge::ClientAPI::Feed::VSS_FPS');
    Scalar::Util::weaken($self);

    AE::log info => "Determine and configure VSs that exist...";

    unless (@$vss_left) {
        AE::log info => "No created VSs found; need to create all (if any)";
        return;
    }

    my @used;
    for my $el (@$vss_left) {
        for my $vs (@$el) {
            my $fps  = $vss_fps->get_fps_by_vs($vs->ip, $vs->port);
            my $tlss = $vss_fps->get_tlss_by_vs($vs->ip, $vs->port);
            next unless $fps;
            # TODO: Mark if we need to change service name to $VS_NAME
            push @used, [ $vs, $fps, $tlss ];
        }
    }

    AE::log trace => "VSs/RSs/FPs final configuration:\n%s", Dumper+\@used;

    for my $pair (@used) {
        my ($vs, $fps, $tlss) = @$pair;
        AE::log info => "VS %s:%s/%s already created, configure only RSs...",
                        $vs->ip, $vs->subnet, $vs->port;
        $self->configure_vs_rss($vs, $fps, $tlss);
    }

    ()
}

sub add_new_vss_and_configure {
    my ($self, $vss_left, $vss_fps) = @_;
    die "Invalid VSS FPS"
        unless $vss_fps->$_isa('Edge::ClientAPI::Feed::VSS_FPS');
    Scalar::Util::weaken($self);

    AE::log info => "Determine and configure VSs that are not created...";

    my @add;
    $vss_fps->enum(sub {
        my ($vs_fps) = @_;
        my $vs2   = $vs_fps->{vs};
        my $fps   = $vs_fps->{fps};
        my $tlss  = $vs_fps->{tlss};
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
            push @add, [ $vs2->{ip}, $vs2->{port}, $fps, $tlss, $vs2->{is_int_vip}, $vs2->{peer_vip_ip} ];
        }
    });

    unless (@add) {
        AE::log info => "No new VSs to add";
        return;
    }

    AE::log trace => "VSs to be added:\n%s", Dumper+\@add;
    for my $pair (@add) {
        my ($ip, $port, $fps, $tlss, $is_int_vip, $peer_vip_ip) = @$pair;
        my $subnet = "255.255.255.255"; # TODO: Which one?
        my $name   = $is_int_vip ? $VS_INT_NAME : $VS_NAME;
        $name .= $peer_vip_ip;

        AE::log info => "Create VS %s/%s:%s with name %s",
                        $ip, $subnet, $port, $name;
        my ($vs, $hdr) = $self->cli->create_vs(
                            $name, $ip, $subnet, $port, 'HTTP');
        die STOPPED unless $self;

        unless ($hdr->{Success}) {
            die e40_format(EDGE_ERROR, $hdr->{Detail});
        }

        die sprintf "Couldn't find created VS %s/%s:%s",
                    $ip, $subnet, $port
            unless defined $vs;

        AE::log info => "Created VS %s/%s:%s; configure RSs...",
                        $vs->ip, $vs->subnet, $vs->port;

        $self->configure_vs_rss($vs, $fps, $tlss);
    }
    ()
}

sub configure_vs_rss {
    my ($self, $vs, $fps, $tlss) = @_;
    die "Invalid VS object: $vs"
        unless $vs->$_isa('Edge::ClientAPI::Object::VS');
    die "Invalid FPs object: $fps"
        unless $fps->$_isa('Edge::ClientAPI::Feed::FPS');
    die "Invalid TLSs object: $tlss"
        unless $tlss->$_isa('Edge::ClientAPI::Feed::TLSS');
    Scalar::Util::weaken($self);

    AE::log info => "Configure SSL, flightPATH, RS of VS %s/%s:%s...",
                    $vs->ip, $vs->subnet, $vs->port;

    my $vs_ssl_configured;
    if ($vs->has_same_ssl_certificate_names($tlss->get_tlss_names_aref)) {
        unless (@$tlss) {
            AE::log info => "VS %s/%s:%s doesn't need any SSL certificates",
                            $vs->ip, $vs->subnet, $vs->port;
        }
        AE::log info => "SSL certificates of VS %s/%s:%s are configured",
                        $vs->ip, $vs->subnet, $vs->port;
        $vs_ssl_configured = 1;
    }
    elsif (@$tlss) {
        AE::log info => "Import SSL certs for VS %s/%s:%s that don't exist ",
                        "on the ADC...", $vs->ip, $vs->subnet, $vs->port;
        $vs_ssl_configured = 0;

        for my $tls (@$tlss) {
            # $tls is unique in @$tlss.
            AE::log info => "Ensure that SSL cert with ID '%s' is applied to " .
                            "VS %s/%s:%s...",
                            $tls->{name}, $vs->ip, $vs->subnet, $vs->port;

            if ($vs->has_ssl_certificate_name($tls->{name})) {
                AE::log info => "SSL cert with ID '%s' is already applied on VS",
                                $tls->{name};
                next;
            }

            # Add PKCS12 with name associated with cert & key permanently.
            # If it exists with the name, copy will be added (to be removed
            # on cleaning stage later -- just save time now).
            my (undef, $hdr) = $self->cli->ADV_import_ssl_cert(
                $tls->{name},
                $tls->{crt}->pkcs12->as_string,
                $tls->{pwd}
            );

            die STOPPED unless $self;
            die e40_format(EDGE_ERROR, $hdr->{Detail}) unless $hdr->{Success};
        }
    }
    else {
        AE::log info => "Need to remove all SSL certs from VS %s/%s:%s...",
                        $vs->ip, $vs->subnet, $vs->port;
        $vs_ssl_configured = 0;
    }

    unless ($vs_ssl_configured) {
        # Set SSL certificate names or remove existing names.
        my $names = $tlss->comma_separated_names; # Can be empty string.
        if (length $names) {
            AE::log info => "Apply the following SSL certs to VS %s/%s:%s: " .
                            "'%s'...", $vs->ip, $vs->subnet, $vs->port, $names;
        } else {
            AE::log info => "Remove all SSL certificates from VS %s/%s:%s...",
                            $vs->ip, $vs->subnet, $vs->port;
        }

        my %new;
        $new{acceleration}         = $vs->{acceleration};
        $new{cachingRule}          = $vs->{cachingRule};
        $new{editedInterface}      = $vs->{InterfaceID};
        $new{editedChannel}        = $vs->{ChannelID};
        $new{loadBalancingPolicy}  = $vs->{loadBalancingPolicy};
        $new{serverMonitoring}     = $vs->{serverMonitoring};
        $new{sslCertificate}       = $vs->{sslCertificate};
        $new{sslCertificate}       = $names; # Empty or multiple names are okay.
        $new{sslClientCertificate} = $vs->{sslClientCertificate};

        my ($vs_changed, $hdr) = $self->cli->change_basic_settings(\%new);
        die STOPPED unless $self;
        die e40_format(EDGE_ERROR, $hdr->{Detail}) unless $hdr->{Success};

        $vs = $vs_changed;
    }

    my %fp_sha1;

    # Enumerate flightPATH to be created for VS. If the same flightPATH is
    # already created, reuse it for current VS.
    $fps->enum_fps_hashes(sub {
        my ($fp, $sha1) = @_;

        return unless $fp->{is_active}; # Currently, inactive FP (for internal VIP)
                                        # is not to be created.

        my $fp_desc = "Kubernetes IC sha1 $sha1";
        # "Kube-IC {metadata > name}-ingress-{last 8 digits of SHA hash in new description}"
        my $ssha1   = substr $sha1, 0, 8;
        my $fp_name = "Kube-IC $fp->{resource_name}-$ssha1";
        $fp_sha1{$fp_name} = 1;

        AE::log info => "FP with the name '%s' is to be created", $fp_name;

        my $id  = $vs->get_fp_id_by_name($fp_name);
        my $idx = $vs->get_fp_idx_by_name($fp_name);
        if (!defined $id) {
            AE::log info => "Create flightPATH with name '%s'...", $fp_name;

            my (undef, $hdr) = $self->cli->create_fp_custom_forward(
                    $fp->{hostname},
                    undef, # Arrayref with VSs that have flightPATH by the name.
                    $vs->ip, $vs->port,
                    $fp_name,
                    $fp_desc,
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
        AE::log info => "Unapply not used flightPATH from VS %s/%s:%s...",
                        $vs->ip, $vs->subnet, $vs->port;

        my $names = $vs->get_fp_names_all_by_regex($QR_FP_NAME_KUBERNETES_IC);

        for my $name (sort keys %$names) {
            # FP name exists in %fp_sha1 if it is active only.
            if (exists $fp_sha1{$name}) {
                AE::log info => "Kubernetes flightPATH '%s' is used", $name;
                next;
            }
            AE::log info => "Kubernetes flightPATH '%s' is not used", $name;

            my $applied = $names->{$name};

            if ($applied) {
                AE::log info => "Unapply flightPATH '%s' from VS %s/%s:%s...",
                                $name, $vs->ip, $vs->subnet, $vs->port;

                my (undef, $hdr) = $self->cli->unapply_fp_by_name($name, $vs);
                die STOPPED unless $self;

                unless ($hdr->{Success}) {
                    die e40_format(EDGE_ERROR, $hdr->{Detail});
                }

                AE::log info => "flightPATH '%s' has been unapplied", $name;
            }
        }

        # Do not delete unapplied FPs, because they can be used in another VS.
        # Better make final cleaning after all VSs are configured.
    }

    my $rss = $fps->get_unique_rss;
    AE::log info  => "Configure RSs on VS %s/%s:%s...",
                     $vs->ip, $vs->subnet, $vs->port;
    AE::log info  => "VS %s/%s:%s must have %u RS(s)",
                     $vs->ip, $vs->subnet, $vs->port, scalar @$rss;
    AE::log trace => "VS %s/%s:%s must have the following RS(s): %s",
                     $vs->ip, $vs->subnet, $vs->port, Dumper+$rss;

    my @add_rss;
    for my $rs (@$rss) {
        AE::log info => "Check if RS %s:%s exists...", $rs->{ip}, $rs->{port};

        if ($vs->has_rs($rs->{ip}, $rs->{port})) {
            AE::log info => "RS %s:%s exists", $rs->{ip}, $rs->{port};
            # TODO: Do we need to use RS upsert?
            next;
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
        my ($vs_changed, $hdr) = $self->cli->remove_rs_by_specs(
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
            #push @rss_ref, { addr => $rs->{ip}, port => $rs->{port} };
            #AE::log info => "Add missed RSs: %s", Dumper+\@rss_ref;

            #my ($vs, $hdr) = $self->cli->init_rs_multi_by_specs(
            #    \@rss_ref, $vs->ip, $vs->subnet, $vs->port, -vs => $vs);
            # TODO: Do we need to use RS upsert?
            my ($vs_changed, $hdr) = $self->cli->upsert_rs(
                { addr => $rs->{ip}, port => $rs->{port} }, $vs->ip, $vs->subnet, $vs->port, -vs => $vs);
            #warn "UPSERT RESULT: self=$self, vs=$vs";
            die STOPPED unless $self;

            #warn "press ENTER: $vs: $hdr->{Detail}\n"; my $in = <STDIN>;

            unless ($hdr->{Success}) {
                die e40_format(EDGE_ERROR, $hdr->{Detail});
            }

            AE::log info => "Added all RSs for VS %s/%s:%s",
                            $vs->ip, $vs->subnet, $vs->port;

            $vs = $vs_changed;
        }
    }

    AE::log info => "VS %s/%s:%s is completely configured",
                    $vs->ip, $vs->subnet, $vs->port;
    ()
}

# This routine is to be called after all Kubernetes FPs are applied.
# It's just cleaning. All errors here are not critical.
sub remove_not_used_fps {
    my ($self, $vss_fps) = @_;
    if (defined $vss_fps) {
        die "Invalid VSS FPS"
            unless $vss_fps->$_isa('Edge::ClientAPI::Feed::VSS_FPS');
    }

    my $used_fp_names = $vss_fps
                      ? $vss_fps->get_all_uniq_fps_names(-only_active => 1) # Can be undefined.
                      : undef;

    AE::log trace => "Used Kubernetes FPs: %s",
                     $used_fp_names ? Dumper+$used_fp_names : '<undef>';

    AE::log info => "Get all FPs on the ADC for cleaning...";
    my ($fps, $hdr) = $self->cli->get_fps;
    die STOPPED unless $self;
    unless ($hdr->{Success}) {
        AE::log error => "Couldn't get list of all FPs: %s", $hdr->{Detail};
        return;
    }

    AE::log info => "Collect FP names for removal...";
    my %del;
    for my $fp (@$fps) {
        my $name = $fp->name;
        next unless $name =~ $QR_FP_NAME_KUBERNETES_IC;
        next if exists $used_fp_names->{$name};
        $del{$name} = $fp->id;
    }

    unless (%del) {
        AE::log info => "No flightPATHs for removal";
        return;
    }

    AE::log info => "Need to remove %u FP(s)...", scalar keys %del;
    # If FPs are applied, ADC doesn't remove them and returns error.
    my $ok = 1;
    my $id;
    my @names = sort keys %del;
    for (my $i = 0; $i < @names; $i++) {
        my $name = $names[$i];

        unless (defined $id) {
            # First FP ID can be taken from first FPs lookup response.
            $id = $del{$name};
        } else {
            my $found = 0;
            for my $fp (@$fps) {
                if ($fp->name eq $name) {
                    $id    = $fp->id;
                    $found = 1;
                }
            }

            unless ($found) {
                AE::log error => "Couldn't get FP ID by name '%s'", $name;
                $ok = 0;
                next;
            }
        }

        # Got ID of FP for removal.
        AE::log info => "Remove FP with name '%s' by ID %s...", $name, $id;
        my ($new_fps, $hdr) = $self->cli->remove_fp_by_id($id);
        die STOPPED unless $self;
        unless ($hdr->{Success}) {
            AE::log error => "Couldn't remove flightPATH: %s; stop cleaning...",
                             $hdr->{Detail};
            # TODO: if error is for FP applied, skip it.
            $ok = 0;
            last;
        }
        AE::log info => "Removed FP by ID %s", $id;

        unless (@$new_fps) {
            if ($i + 1 == @names) {
                # It's okay if there are no FPs received.
                # We removed all not used.
                last;
            }
            else {
                AE::log info => "No flightPATHs in last response";
                AE::log warn => "No reasons to delete next flightPATHs by name " .
                                "while FP IDs are changed after last removal";
                $ok = 0;
                last;
            }
        }

        # Use new FPs rows to determine actual FP IDs from names.
        $fps = $new_fps;
    }

    if ($ok) {
        AE::log info => "All FPs have been removed successfully";
    } else {
        AE::log info => "Not all FPs were removed due to errors";
    }

    ()
}

# This routine is to be called after all Kubernetes SSL certs are applied.
# It's just cleaning. All errors here are not critical.
sub remove_not_used_ssl_certs {
    my ($self, $vss_fps) = @_;
    if (defined $vss_fps) {
        die "Invalid VSS FPS"
            unless $vss_fps->$_isa('Edge::ClientAPI::Feed::VSS_FPS');
    }

    my $used_cert_names = $vss_fps
                        ? $vss_fps->get_all_uniq_cert_names # Can be undefined.
                        : undef;

    AE::log trace => "Used Kubernetes SSL certs: %s",
                     $used_cert_names ? Dumper+$used_cert_names : '<undef>';

    my ($certs, $hdr) = $self->cli->get_all_certificates;

    die STOPPED unless $self;
    unless ($hdr->{Success}) {
        AE::log error => "Couldn't get list of all SSL certs: %s",
                         $hdr->{Detail};
        return;
    }

    my $ok = 1;
    for my $cert (@$certs) {
        my $id = $cert->{id};
        next unless $id =~ /^Kubernetes_IC_SHA1_cert_/;
        next if exists $used_cert_names->{$id};

        AE::log info => "Remove SSL cert with ID '%s'", $id;
        my (undef, $hdr) = $self->cli->ADV_remove_ssl_cert($id);
        die STOPPED unless $self;
        unless ($hdr->{Success}) {
            AE::log error => "Couldn't remove SSL cert: %s", $hdr->{Detail};
            $ok = 0;
            next;
        }

        AE::log info => "SSL cert with ID '%s' has been removed", $id;
        # SSL cert IDs are permanent. No need to fetch SSL cert list again.
    }

    if ($ok) {
        AE::log info => "All SSL certs have been removed successfully";
    } else {
        AE::log info => "Not all SSL certs were removed due to errors";
    }

    ()
}

1;
