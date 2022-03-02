package Edge::ClientAPI::Feed::VSS_FPS;
use common::sense;
use Try::Tiny;
use YAML::Tiny;
use Data::Dumper;
use Safe::Isa;
use Edge::ClientAPI::E;

sub new {
    my ($class) = @_;
    return bless +[], $class;
}

sub add {
    my ($self, $vs_ip, $vs_port, $fps, $tlss, %args) = @_;

    # It is allowed to duplicate $vs_ip and $vs_port.
    push @$self, { vs   => { ip          => $vs_ip,
                             port        => $vs_port,
                             peer_vip_ip => $args{-peer_vip_ip},
                             is_int_vip  => $args{-int_vip} ? 1 : 0 },
                   tlss => $tlss,
                   fps  => $fps };
    ()
}

sub add_on_top {
    my $self = shift;
    $self->add(@_);
    unshift @$self, $self->[-1];
    pop @$self;
    ()
}

sub has_vs {
    my ($self, $ip, $port) = @_;
    for my $el (@$self) {
        if ($ip eq $el->{vs}{ip} && $port == $el->{vs}{port}) {
            return 1;
        }
    }
    return 0;
}

sub get_fps_by_vs {
    my ($self, $ip, $port) = @_;
    for my $el (@$self) {
        if ($ip eq $el->{vs}{ip} && $port == $el->{vs}{port}) {
            return $el->{fps};
        }
    }
    return undef;
}

sub get_tlss_by_vs {
    my ($self, $ip, $port) = @_;
    for my $el (@$self) {
        if ($ip eq $el->{vs}{ip} && $port == $el->{vs}{port}) {
            return $el->{tlss}; # Can be undefined.
        }
    }
    return undef;
}

sub enum {
    my ($self, $cb) = @_;
    die "No callback" unless ref $cb eq 'CODE';
    for my $el (@$self) {
        $cb->($el);
    }
    ()
}

# $args{-only_active}
sub get_all_uniq_fps_names {
    my ($self, %args) = @_;

    my %all;
    for my $el (@$self) {
        my $fps = $el->{fps};
        next unless $fps;
        my $names = $fps->get_fps_names(-only_active => $args{-only_active});
        next unless $names;
        # Merge names
        for my $name (sort keys %$names) {
            $all{$name}++;
        }
    }

    return %all ? \%all : undef;
}

sub get_all_uniq_cert_names {
    my $self = shift;

    my %all;
    for my $el (@$self) {
        my $tlss = $el->{tlss};
        next unless $tlss;
        my $names = $tlss->get_tlss_names;
        next unless $names;
        # Merge names
        for my $name (sort keys %$names) {
            $all{$name}++;
        }
    }

    return %all ? \%all : undef;
}

=head 1

Example of Edge::ClientAPI::Feed::VSS_FPS.

bless( [ {
      'fps' => bless( [
                        {
                          'rss' => [
                                     {
                                       'port' => '80',
                                       'ip' => '10.244.0.16'
                                     },
                                     {
                                       'port' => '80',
                                       'ip' => '10.244.0.12'
                                     }
                                   ],
                          'hostname' => 'edgeecho',
                          'path' => '/',
                          'real_ip_from' => undef,
                          'rewrite' => ''
                        },
                        {
                          'rss' => [
                                     {
                                       'ip' => '10.244.0.44',
                                       'port' => '80'
                                     },
                                     {
                                       'port' => '80',
                                       'ip' => '10.244.0.45'
                                     }
                                   ],
                          'hostname' => 'edgeecho',
                          'path' => '/abc',
                          'real_ip_from' => undef,
                          'rewrite' => ''
                        }
                      ], 'Edge::ClientAPI::Feed::FPS' ),
      'tlss' => bless( [], 'Edge::ClientAPI::Feed::TLSS' ),
      'vs' => {
                'port' => 80,
                'ip' => '192.168.2.135'
              }
    }
], 'Edge::ClientAPI::Feed::VSS_FPS' );
=cut

sub expand_to_internal_vss {
    my $self = shift;

    my @static = @$self;
    for my $vs_fps (@static) {
        my $vs_ext_ip = $vs_fps->{vs}->{ip};
        my $fps       = $vs_fps->{fps};

        for my $fp (@$fps) {
            # Clone RSs with replaced IP to 127.* pattern.
            my (@ip_variants, $port_variant);

            my @rss = @{$fp->{rss}};
            for (@rss) {
                my %hash = %$_;
                #$hash{ip} =~ s!^\d+!127!;
                $_ = \%hash;

                push @ip_variants, $_->{ip};
                #$ip_variants[-1] =~ s!^\d+!127!;
                $ip_variants[-1] = $vs_ext_ip;
                $ip_variants[-1] =~ s!^\d+!127!;

                $port_variant = $_->{port};
            }

            my %fp_copy = %$fp;
            $fp_copy{rss} = \@rss;
            $vs_fps->{vs}->{peer_vip_ip} ||= $ip_variants[0]; # Set INT_VIP
                                                              # address.

            if (1) {
                # It's time to build a new internal VS (127.*).
                my $fps_new = Edge::ClientAPI::Feed::FPS->new_from_array([ \%fp_copy ]);

                $fps_new->[0]{is_int_vip} = 1; # FP for internal VS.
                $fps_new->[0]{is_active}  = 0; # Don't add FP to internal VS.

                # Create empty TLSS because internal VS is not behined TLS.
                my $tlss = Edge::ClientAPI::Feed::TLSS->new_empty;

                # Add internal VS on top (to create/change them first - before
                # real VS).
                my ($vs_ip, $vs_port) = ($ip_variants[0], $port_variant);

                $self->add_on_top($vs_ip, $vs_port, $fps_new, $tlss,
                                  -int_vip => 1, -peer_vip_ip => $vs_ext_ip);

                # Replace IC pod RSs to new internal VS.
                $fp->{rss} = [ { ip => $vs_ip, port => $vs_port } ];
            }
        }
    }

    # In the feed, we need to have unique IP:PORT for VSs.
    $self->merge_internal_vss;

    ()
}

sub merge_internal_vss {
    my $self = shift;
    my %internal_found;
    for (@$self) {
        next unless $_->{vs}{is_int_vip};
        my $key = "$_->{vs}{ip}:$_->{vs}{port}";
        if (exists $internal_found{$key}) {
            # Merge FPs. They are different.
            my $found = $internal_found{$key};
            for my $fp (@{$_->{fps}}) {
                push @{$found->{fps}}, $fp;
            }
            $_ = undef;
        } else {
            $internal_found{$key} = $_;
        }
    }

    my @only_defined = grep { defined $_ } @$self;
    @$self = @only_defined;
    ()
}

1;
