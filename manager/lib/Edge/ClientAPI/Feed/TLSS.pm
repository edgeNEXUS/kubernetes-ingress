package Edge::ClientAPI::Feed::TLSS;
use common::sense;
use Try::Tiny;
use YAML::Tiny;
use Data::Dumper;
use Safe::Isa;
use Digest::SHA;
use Crypt::OpenSSL::PKCS12;
use Edge::ClientAPI::Util::Cert;
use Edge::ClientAPI::E;

sub new {
    my ($class, $config, $vs_ip, $vs_port) = @_;
    my $tlss_aref = __get_tlss_for_vs($config, $vs_ip, $vs_port);
    return bless $tlss_aref, $class;
}

sub new_empty {
    my ($class) = @_;
    return bless [], $class;
}

sub HOOK_CERT_FILEPATHS($$) { # $cert_path, $key_path
    # Redefine this subroutine in your tests to re-assign paths by using
    # $_[0] and $_[1].
    ()
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

sub __get_tlss_for_vs {
    my ($config, $ip, $port) = @_;
    my $services    = $config->data_services;
    my $external_ip = $config->data_external_ip;

    my @tlss;

    for my $svc (@$services) {
        my $hostname = $svc->{hostname};
        next unless length $hostname;
        next unless $svc->{ssl};

        my $listeners = $svc->{ssl}{listeners};
        next unless $listeners && @$listeners;


#            # Collect listeners.
#            my %tls;
#            for my $lst (@$ssl_listeners) {
#                my $port = $lst->{port};
#                next unless $port > 0 && $port <= 0xFFFF;
#                my $ip = $lst->{address};
#                $ip = $external_ip unless length $ip;
#                $uniq{"$ip:$port"} = [ $ip, $port, \%tls ];
#            }

        my $this_vs = 0;

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
            $this_vs = 1;
            last;
        }

        next unless $this_vs;

        my $ssl = $svc->{ssl};
        next unless $ssl && %$ssl;

        # Get certificate. It is common for all SSL listeners from above.
        my %tls;
        my $pkcs12      = Crypt::OpenSSL::PKCS12->new;
        my $pkcs12_name = "Friendly name";
        my $pkcs12_pwd  = "tmppass"; # TODO: random
        my $cert_path   = $ssl->{ssl_certificate};
        my $key_path    = $ssl->{ssl_certificate_key};
        HOOK_CERT_FILEPATHS($cert_path, $key_path);
        my $pkcs12_path = $cert_path . ".p12";

        $pkcs12->create($cert_path,  $key_path,
                        $pkcs12_pwd, $pkcs12_path, $pkcs12_name);

        my $fh;
        if (open $fh, '<', $pkcs12_path) {
            binmode $fh;
            my $buf = do { local $/ = undef; <$fh> };
            close $fh;
            unlink $pkcs12_path;

            my $sha1 = Digest::SHA->new(1);
            $sha1->addfile($cert_path);
            $sha1->addfile($key_path);

            $tls{sum} = $sha1->hexdigest;
            $tls{pwd} = $pkcs12_pwd;
            $tls{crt} = Edge::ClientAPI::Util::Cert->new(
                                pkcs12_string   => $buf,
                                pkcs12_password => 'tmppass');
            $tls{name} = 'Kubernetes_IC_SHA1_cert_' . $tls{sum};
        } else {
            unlink $pkcs12_path;
            die "PKCS12 file is not created from SSL cert and key: $!";
        }

        # Add only unique certificates.
        my $uniq = 1;
        for (@tlss) {
            if ($_->{name} eq $tls{name}) {
                $uniq = 0;
                last;
            }
        }

        push @tlss, \%tls if $uniq;
    }

    #return @tlss ? \@tlss : undef;
    return \@tlss;
}

sub get_tlss_names {
    my $self = shift;
    my %names;

    for my $tls (@$self) {
        my $cert_name = $tls->{name};
        $names{$cert_name} = 1;
    }

    return %names ? \%names : undef;
}

sub get_tlss_names_aref {
    my $self  = shift;
    my $names = $self->get_tlss_names;
    my @names = (sort keys %$names);
    return @names ? \@names : undef;
}

sub comma_separated_names {
    my $self  = shift;
    my $names = $self->get_tlss_names_aref;
    return "" unless defined $names;
    my $string = join ',', @$names;
    return $string;
}

1;
