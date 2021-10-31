#!/usr/bin/perl
package Edge::ClientAPI::Request::alb_api;
#
# An ALB API library of functions for PERL
#

use strict;
use warnings;
use JSON qw( decode_json encode_json );
use File::Basename;


our $DEBUG = 0;
my $JETNEXUS_CONF = "/jetnexus/etc/jetnexus.conf";
my $ALB_API_TIMEOUT = 300;
my $ALB_API_USER = "admin";
my $ALB_API_PASS = "jetnexus";
my $SYSLOG_TAG = "WAF";

my $WAF_SMARTFILE_NAME = "jetNEXUS-Application-Firewall-Edgenexus_TEST_ONLY.add-on.alb";
my $ZAP_SMARTFILE_NAME = "jetNEXUS-OWASP-ZAP-Edgenexus_TEST_ONLY.add-on.alb";
my $DVWA_SMARTFILE_NAME = "DVWA-Edgenexus_TEST_ONLY.add-on.alb";

my $WAF_ADDON_NAME = "waf1";
my $ZAP_ADDON_NAME = "zap1";
my $DVWA_ADDON_NAME = "dvwa1";

my $APP_NAME = "jetNEXUS-Application-Firewall";
my $VS_ADDR = "www.yourdomain.com";
my $SSL_CERT_ID = "2048_Local_Cert";
my $ALB_NAME = "ALB-X-WAF";



sub debug {
    if ($DEBUG >= 1) {
        print(STDERR @_);
        print("\n");
    }
}



# Print error message to STDERR.
# If $fatal == 1, then exit(1).
sub error {
    my $msg = $_[0];
    my $fatal = $_[1];

    print(STDERR "$msg\n");

    if (defined($fatal) && $fatal) {
        exit(1);
    }
}



# Send a GET request to ALB API and return API response JSON.
# Retry if connection failed.
sub alb_api_get {
    my ($guid, $url, $try_num) = @_;

    my $max_tries = 5;

    # Sleep a while before retrying
    if (!defined($try_num)) {
        $try_num = 0;
    }
    if ($try_num == 1) {
        sleep(5);
    }
    elsif ($try_num == 2) {
        sleep(10);
    }
    elsif ($try_num == 3) {
        sleep(20);
    }
    elsif ($try_num == 4) {
        sleep(25);
    }
    elsif ($try_num == 5) {
        sleep(30);
    }
    elsif ($try_num == 6) {
        sleep(45);
    }

    $try_num++;

    my $response = `curl -s -k -H "Cookie: GUID=$guid;" -w "\nHTTP_CODE=%{http_code}\n" "$url"`;
    my $err = $? >> 8;

    my @arr = split(/\n/, $response);
    if ($arr[0] =~ /^Method Not Allowed/) {
        error("ALB API error: '$arr[0]'.");
        return(undef());
    }

    my $http_code = pop(@arr);
    $http_code =~ s/HTTP_CODE=(\d+)/$1/;
    my $json = join("\n", @arr);

    if (($err != 0) || ($http_code != 200)) {
        if ($try_num <= $max_tries) {
            error("Failed to connect to ALB API: $err, HTTP code: $http_code - will retry, try number: $try_num.");
            $json = alb_api_get($guid, $url, $try_num);
        } else {
            error("Failed to connect to ALB API: $err, HTTP code: $http_code - giving up.");
            $json = undef();
        }
    }

    return($json);
}



# Send a POST request to ALB API and return API response JSON.
# Retry if connection failed.
sub alb_api_post {
    my ($guid, $url, $request, $try_num) = @_;

    my $max_tries = 5;

    # Sleep a while before retrying
    if (!defined($try_num)) {
        $try_num = 0;
    }
    if ($try_num == 1) {
        sleep(5);
    }
    elsif ($try_num == 2) {
        sleep(10);
    }
    elsif ($try_num == 3) {
        sleep(20);
    }
    elsif ($try_num == 4) {
        sleep(25);
    }
    elsif ($try_num == 5) {
        sleep(30);
    }
    elsif ($try_num == 6) {
        sleep(45);
    }

    $try_num++;

    my $response;
    if ($request =~ /^[{|\[]/) {
        # JSON POST request
        $response = `curl -s -k -H "Cookie: GUID=$guid;" -d '$request' -w "\nHTTP_CODE=%{http_code}\n" "$url"`;
    } else {
        # File upload request
        $response = `curl -s -k -H "Cookie: GUID=$guid;" $request -w "\nHTTP_CODE=%{http_code}\n" "$url"`;
    }
    my $err = $? >> 8;

    my @arr = split(/\n/, $response);
    if ($arr[0] =~ /^Method Not Allowed/) {
        error("ALB API error: '$arr[0]'.");
        return(undef());
    }

    my $http_code = pop(@arr);
    $http_code =~ s/HTTP_CODE=(\d+)/$1/;
    my $json = join("\n", @arr);

    if (($err != 0) || ($http_code != 200)) {
        if ($try_num <= $max_tries) {
            error("Failed to connect to ALB API: $err, HTTP code: $http_code - will retry, try number: $try_num.");
            $json = alb_api_post($guid, $url, $request, $try_num);
        } else {
            error("Failed to connect to ALB API: $err, HTTP code: $http_code - giving up.");
            $json = undef();
        }
    }

    return($json);
}



# Unlock an OS user account.
# If the account was locked, return 1, otherwise return 0.
sub unlock_user_account {
    my $user = $_[0];
    my $locked = 0;

    if ($user eq '') {
        error("Operation failed: unlock_user_account() requires a user name.");
    }
    
    my $shadow = `getent shadow $user`;
    if ($shadow eq '') {
        error("Failed to get '$user' user acccount data.");
    }
        
    my @shadow_arr = split(/:/, $shadow);
    my $pass = $shadow_arr[1];
        
    if ($pass =~ /^!/) {
        $locked = 1;
        my $err = system('passwd', '-u', $user);
        if ($err != 0) {
            error("Failed to unlock '$user' user account.");
        }
    
    }

    return($locked);
}

    
        
# Lock an OS user account
sub lock_user_account {
    my $user = $_[0];
            
    if ($user eq '') {
        error("Operation failed: lock_user_account() requires a user name.");
    }
    my $err = system('passwd', '-l', $user);
    if ($err != 0) {
        error("Failed to lock '$user' user account.");
    }
}



sub get_alb_api_url {
    my ($ConfigIP, $SecureConfig, $SecureConfigPort, $ConfigPort);
    my ($url, $port, $proto);

    $port = '8081';
    $proto = 'http';
    $ConfigIP = '127.0.0.1';

    $url = "$proto://$ConfigIP:$port";

    if (!defined($proto) || !defined($ConfigIP) || !defined($port)) {
        error("Failed to determine ALB API URL: '$url'", 1);
    }

    return($url);
}



# Get CloudMode ALB config setting
sub get_alb_cloud_mode {
    my $cloud_mode = 0;

    open(CONF, $JETNEXUS_CONF) || error("Cannot open '$JETNEXUS_CONF' for reading", 1);
    while (my $l = <CONF>) {
        $l =~ s/(\n|\r)$//;
        if (my ($k, $v) = split(/=/, $l) ) {
            if (defined($v)) {
                $v =~ s/\"//g;
            }
            if ($k =~ /^CloudMode$/i) {
                $cloud_mode = $v;
                last;
            }
        }
    }
    close(CONF);

    return($cloud_mode);
}



sub get_alb_greenside_ip_and_mask {
    my ($ip, $mask);

    open(CONF, $JETNEXUS_CONF) || error("Cannot open '$JETNEXUS_CONF' for reading", 1);
    while (my $l = <CONF>) {
        $l =~ s/(\n|\r)$//;
        if (my ($k, $v) = split(/=/, $l) ) {
            if (defined($v)) {
                $v =~ s/\"//g;
            }
            if ($k =~ /^GreenSideIP$/i) {
                $ip = $v;
            }
            if ($k =~ /^GreenSideMask$/i) {
                $mask = $v;
            }
            if ($ip && $mask) {
                last;
            }
        }
    }
    close(CONF);

    if (!defined($ip) || !defined($mask)) {
        error("Failed to determine ALB IP or mask: '$ip/$mask'", 1);
    }

    return($ip, $mask);
}



# Wait until ALB API is started by checking for a presence of lighttpd 
# or jetnexusws on the ALB API port. 
# Stop waiting and return error if the give timeout (in seconds) is exceeded.
sub wait_until_alb_api_is_started {
    my ($api_url, $timeout) = @_;

    my $api_port = $api_url;
    $api_port =~ s/.*:([0-9]+)/$1/;

    my $waiting_time = 0;
    my $err = 1;
    while ($err != 0) {
        $err = system("netstat -lntp |grep -qE ':$api_port .*(lighttpd|jetnexusws)'");

        if ($err != 0) {
            sleep(1);
            $waiting_time++;
        if ($waiting_time == 1) {
        system("logger -p info -t '$SYSLOG_TAG' -- 'Waiting until ALB API is started'");
        }
        }

        if ($waiting_time > $timeout) {
            return(-1);
        }
    }
    system("logger -p info -t '$SYSLOG_TAG' -- 'ALB API has started'");

    return(1);
}



sub alb_api_login {
    my ($url, $user, $pass, $try_num) = @_;
    my $path = "$url/POST/32";
    my $request = "{\"$user\":\"$pass\"}";
    my $guid;

    my $max_tries = 6;

    # Sleep a while before retrying
    if (!defined($try_num)) {
        $try_num = 0;
    }
    if ($try_num == 1) {
        sleep(5);
    }
    elsif ($try_num == 2) {
        sleep(10);
    }
    elsif ($try_num == 3) {
        sleep(20);
    }
    elsif ($try_num == 4) {
        sleep(25);
    }
    elsif ($try_num == 5) {
        sleep(30);
    }
    elsif ($try_num == 6) {
        sleep(45);
    }
    $try_num++;

#    print("request:\ncurl -s -k -d '$request' -w \"\nHTTP_CODE=%{http_code}\n\" $path\n");

    my $response = `curl -s -k -d '$request' -w "\nHTTP_CODE=%{http_code}\n" $path`;
    my $err = $? >> 8;

    # DEBUG: print ALB API response - helpful to debug issues with ALB API
    print(STDERR "API response: '$response'\n");
    
    my @arr = split(/\n/, $response);
    if ($arr[0] =~ /^Method Not Allowed/) {
        error("ALB API error: '$arr[0]'.");
        return(undef());
    }
    my $http_code = pop(@arr);
    $http_code =~ s/HTTP_CODE=(\d+)/$1/;

    if (($err != 0) || ($http_code != 200)) {
        if ($try_num <= $max_tries) {
            error("Failed to connect to ALB API in alb_api_login(): $err - will retry, try number: $try_num.");
            $guid = alb_api_login($url, $user, $pass, $try_num);
        } else {
            error("Failed to connect to ALB API in alb_api_login(): $err - giving up.");
            $guid = undef();
        }
    }

    foreach my $l (@arr) {
        if ($l =~ s/.*"GUID":"(.*?)"/$1/) {
            $guid = $1;
            last;
        }
    }

#    print("response:\n$response\n\n");

    return($guid);
}



sub get_alb_sw_version {
    debug("=== In get_alb_sw_version\n");

    my ($albApiUrl, $guid, $url) = @_;
    my $path = "GET/24";
    my $res;

    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_alb_sw_version()", 1);
    }
    my $decoded = decode_json($json);

    if ($decoded->{'DevVer'} ne "") {
        $res = $decoded->{'DevVer'};
        # Strip HTML tags and extra spaces
        $res =~ s/<(?:[^>'"]*|(['"]).*?\1)*>//ig;
        $res =~ s/&nbsp;/ /ig;
        $res =~ s/Software Version\s*:\s*//ig;
        $res =~ s/\s+/ /g;
        $res =~ s/^\s+//;
        $res =~ s/\s+$//;
    } else {
        error("ALB API request for get software version failed: '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($res);
}



sub get_alb_name {
    debug("=== In get_alb_name\n");

    my ($albApiUrl, $guid) = @_;
    my $path = "GET/6";
    my $res;

    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_alb_name()", 1);
    }
    my $decoded = decode_json($json);

    debug("$json\n");
    
    if (defined($decoded->{'data'}) && defined($decoded->{'data'}->{'ServerRefField'})) {
        $res = $decoded->{'data'}->{'ServerRefField'};
    } else {
        error("ALB API request for get network page data failed in get_alb_name(): '" . $decoded->{'StatusText'} . "'", 1);
    }
        
    return($res);
}



# Set ALB name. Returns old ALB name on success.
sub set_alb_name {
    debug("=== In set_alb_name\n");

    my ($albApiUrl, $guid, $newAlbName) = @_;
    my $path = "GET/6";
    my $res;

    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in set_alb_name()", 1);
    }
    my $decoded = decode_json($json);

    debug("$json\n");
    
    if (defined($decoded->{'data'}) && defined($decoded->{'data'}->{'ServerRefField'})) {
        $res = $decoded->{'data'}->{'ServerRefField'};
    } else {
        error("ALB API request for get network page data failed in set_alb_name(): '" . $decoded->{'StatusText'} . "'", 1);
    }
    
    my $data;
    $data->{'ServerRefField'} = $newAlbName;
    $data->{'DNSServerField'} = $decoded->{'data'}->{'DNSServerField'};
    $data->{'DNSServerField2'} = $decoded->{'data'}->{'DNSServerField2'};
    $data->{'DefaultGateway'} = $decoded->{'data'}->{'DefaultGateway'};
    $data->{'DefaultGatewayIPv6'} = $decoded->{'data'}->{'DefaultGatewayIPv6'};
    $data->{'isValidationRequired'} = $decoded->{'data'}->{'isValidationRequired'};

    $path = "POST/6?iAction=3&iType=1";
    my $request = encode_json($data);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a VS in set_alb_name()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update ALB name failed in set_alb_name(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);
    
    
    return($res);
}



sub get_dns_servers {
    debug("=== In get_dns_servers\n");

    my ($albApiUrl, $guid) = @_;
    my $path = "GET/6";
    my @res;

    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_dns_servers()", 1);
    }
    my $decoded = decode_json($json);

    debug("$json\n");
    
    if (defined($decoded->{'data'}) && defined($decoded->{'data'}->{'DNSServerField'})) {
        push(@res, $decoded->{'data'}->{'DNSServerField'});
    } else {
        error("ALB API request for get network page data failed in get_dns_servers(): '" . $decoded->{'StatusText'} . "'", 1);
    }
    if (defined($decoded->{'data'}) && defined($decoded->{'data'}->{'DNSServerField2'})) {
        push(@res, $decoded->{'data'}->{'DNSServerField2'});
    } else {
        error("ALB API request for get network page data failed in get_dns_servers(): '" . $decoded->{'StatusText'} . "'", 1);
    }
        
    return(@res);
}



# Set DNS servers
sub set_dns_servers {
    debug("=== In set_dns_servers\n");

    my ($albApiUrl, $guid, $newDnsServer1, $newDnsServer2) = @_;
    my $path = "GET/6";

    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in set_dns_servers()", 1);
    }
    my $decoded = decode_json($json);

    debug("$json\n");
    
    if (!defined($decoded->{'data'}) || !defined($decoded->{'data'}->{'DNSServerField'})) {
        error("ALB API request for get network page data failed in get_dns_servers(): '" . $decoded->{'StatusText'} . "'", 1);
    }
    
    my $data;
    $data->{'ServerRefField'} = $decoded->{'data'}->{'ServerRefField'};
    $data->{'DNSServerField'} = $newDnsServer1;
    $data->{'DNSServerField2'} = $newDnsServer2;
    $data->{'DefaultGateway'} = $decoded->{'data'}->{'DefaultGateway'};
    $data->{'DefaultGatewayIPv6'} = $decoded->{'data'}->{'DefaultGatewayIPv6'};
    $data->{'isValidationRequired'} = $decoded->{'data'}->{'isValidationRequired'};

    $path = "POST/6?iAction=3&iType=1";
    my $request = encode_json($data);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a VS in set_dns_servers()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update DNS servers failed in set_dns_servers(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);
    
    return($decoded);
}



sub download_smartfile {
    debug("=== In download_smartfile\n");

    my ($albApiUrl, $guid, $url) = @_;
    my $smartfileName = basename($url);

    # Execute a GET call before calling POST
    my $path = "GET/49";
    my $res;

    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in download_smartfile()", 1);
    }

    $path = "POST/26?iAction=8&iType=1";
    my $request = "{\"URL\":\"$url\",\"Name\":\"$smartfileName\"}";

    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in download_smartfile()", 1);
    }

    my $decoded = decode_json($json);
    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} !~ 'Download started')) {
        if ($decoded->{'StatusText'} =~ 'App already exists') {
            return($decoded);
        } else {
            error("ALB API request for download smart-file failed: '" . $decoded->{'StatusText'} . "'", 1);
        }
    }

    my $totalSize;
    if (defined($decoded->{'TotalSize'})) {
        $totalSize = $decoded->{'TotalSize'};
        if (($totalSize eq '') || ($totalSize <= 0)) {
            error("Invalid smart-file size '$totalSize' while downloading $smartfileName\n$json\n", 1);
        }
    }
    if (($totalSize eq '') || ($totalSize <= 0)) {
        error("Invalid smart-file size '$totalSize' while downloading $smartfileName\n$json\n", 1);
    }

    debug("Started downloading $smartfileName of size $totalSize bytes\n");

    $path = "POST/26?iAction=9&iType=1";
    $request = "{\"URL\":\"$url\",\"Name\":\"$smartfileName\",\"TotalSize\":\"$totalSize\"}";
    my $completed = 0;
    while(!$completed) {
        $json = alb_api_post($guid, "$albApiUrl/$path", $request);
        if (!$json) {
            error("Failed to connect to ALB API in download_smartfile()", 1);
        }

        $decoded = decode_json($json);

        if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} =~ 'Download error')) {
            error("ALB API request for download smart-file failed: '" . $decoded->{'StatusText'} . "'", 1);
        }

        if (defined($decoded->{'DownloadedSize'})) {
            my $downloadedSize = $decoded->{'DownloadedSize'};
            if ($downloadedSize < $totalSize) {
                debug("Downloaded $downloadedSize of $totalSize bytes\n");
            }
        }

        if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} eq 'Download Completed')) {
            $completed = 1;
        } else {
            sleep(3);
        }
    }

    return($decoded);
}



sub get_smartfile_name {
    my ($albApiUrl, $guid, $appName) = @_;
    my $path = "GET/49?smartInfo=apps";
    my $res;

    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_smartfile_name()", 1);
    }
    my $decoded = decode_json($json);

    # Find a smart-file name by an app name
    if ($decoded->{'SmartFiles'}->{'Files'} ne "") {
        my @files = $decoded->{'SmartFiles'}->{'Files'};
        if (scalar(@files) > 0) {
            foreach my $file_arrayref (@files) {
                foreach my $file (@$file_arrayref) {
                    if ($file->{'Name'} eq $appName) {
                        $res = $file->{'File_Name'};
                        last;
                    }
                }
            }
        }
    }
    
    return($res);
}



sub get_addon_info { 
    debug("=== In get_addon_info\n");

    my ($albApiUrl, $guid, $smartfileName, $addonName) = @_;
    my $path = "GET/54";
    my $res;

    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_addon_info()", 1);
    }
    my $decoded = decode_json($json);

    debug($json);

    # Find a deployed add-on by its add-on name or smart-file name
    if (defined($decoded->{'AddOns'}->{'dataset'}->{'row'}) && ($decoded->{'AddOns'}->{'dataset'}->{'row'} ne "")) {
        my @addons = $decoded->{'AddOns'}->{'dataset'}->{'row'};
        if (scalar(@addons) > 0) {
            foreach my $addon_arrayref (@addons) {
                if (ref($addon_arrayref) eq "ARRAY") {
                    foreach my $addon (@$addon_arrayref) {
                        if (defined($addonName) && defined($smartfileName)) {
                            if (($addon->{'AppName'} eq $addonName) &&
                                ($addon->{'ParentImage'} eq $smartfileName)) {
                                $res = $addon;
                                last;
                            }
                        }
                        elsif (defined($addonName)) {
                            if ($addon->{'AppName'} eq $addonName) {
                                $res = $addon;
                                last;
                            }
                        } 
                        elsif (defined($smartfileName)) {
                            if ($addon->{'ParentImage'} eq $smartfileName) {
                                $res = $addon;
                                last;
                            }
                        }
                    }
                }
            }
        }
    }

    return($res);
}



sub deploy_smartfile {
    debug("=== In deploy_smartfile\n");

    my ($albApiUrl, $guid, $smartfileName) = @_;

    # Do a GET before POST
    my $addon = get_addon_info($albApiUrl, $guid, $smartfileName);

    my $path = "POST/26?iAction=10&iType=1";
    my $request = "{\"Name\":\"$smartfileName\"}";

    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in deploy_smartfile()", 1);
    }

    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request for deploy smart-file failed: '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



sub remove_smartfile {
    debug("=== In remove_smartfile\n");

    my ($albApiUrl, $guid, $smartfileName, $dockerImageName) = @_;

    # Do a GET before POST
    my $addon = get_addon_info($albApiUrl, $guid, $smartfileName, $dockerImageName);

    my $path = "POST/26?iAction=6&iType=1";
    my $request = "{\"File_Name\":\"$smartfileName\", \"DockerImageName\":\"$dockerImageName\"}";

    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in remove_smartfile()", 1);
    }

    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request for remove smart-file failed: '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



sub start_addon {
    debug("=== In start_addon\n");

    my ($albApiUrl, $guid, $dockerImage, $configId, $addonName, $externalIp, $externalPort) = @_;

    if (!defined($externalIp)) {
        $externalIp = '';    
    }
    if (!defined($externalPort)) {
        $externalPort = '';
    }

    my $path = "POST/54?iAction=3&iType=1";
    my $request = "{\"Repository\":\"$dockerImage\",\"AddOnName\":\"$addonName\",\"ExternalIPAddress\":\"$externalIp\",\"ExternalPort\":\"$externalPort\",\"ConfigID\":\"$configId\"}";
    my $res;

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in start_addon()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request for start add-on failed: '" . $decoded->{'StatusText'} . "'", 1);
    }

    my @addons = $decoded->{'AddOns'}->{'dataset'}->{'row'};
    if (scalar(@addons) > 0) {
        foreach my $addon_arrayref (@addons) {
            if (ref($addon_arrayref) eq "ARRAY") {
                foreach my $addon (@$addon_arrayref) {
                    if ($addon->{'id'} eq $configId) {
                        $res = $addon;
                        last;
                    }
                }
            }
        }
    }

    return($res);
}



sub update_addon {
    debug("=== In update_addon\n");

    my ($albApiUrl, $guid, $dockerImage, $configId, $addonName, $externalIp, $externalPort) = @_;

    if (!defined($externalIp)) {
        $externalIp = '';    
    }
    if (!defined($externalPort)) {
        $externalPort = '';
    }

    my $path = "POST/26?iAction=12&iType=1";
    my $request = "{\"Repository\":\"$dockerImage\",\"AddOnName\":\"$addonName\",\"ExternalIPAddress\":\"$externalIp\",\"ExternalPort\":\"$externalPort\",\"ConfigID\":\"$configId\"}";
    my $res;

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in update_addon()", 1);
    }
    my $decoded = decode_json($json);

    debug($json."\n");

    if (defined($decoded->{'StatusImage'}) && 
        ($decoded->{'StatusText'} ne 'Your changes have been applied') &&
        ($decoded->{'StatusText'} ne 'Download started, please wait.')) {
            error("ALB API request for update add-on failed: '" . $decoded->{'StatusText'} . "'", 1);
    }

    return(1);
}



sub stop_addon {
    debug("=== In stop_addon\n");

    my ($albApiUrl, $guid, $dockerImage, $configId, $addonName, $addonId) = @_;
    my $path = "POST/54?iAction=8&iType=2";
    my $request = "{\"Repository\":\"$dockerImage\",\"ConfigID\":\"$configId\",\"AddOnID\":\"$addonId\"}";
    my $res;

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in stop_addon()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request for stop add-on failed: '" . $decoded->{'StatusText'} . "'", 1);
    }

    my @addons = $decoded->{'AddOns'}->{'dataset'}->{'row'};
    if (scalar(@addons) > 0) {
        foreach my $addon_arrayref (@addons) {
            if (ref($addon_arrayref) eq "ARRAY") {
                foreach my $addon (@$addon_arrayref) {
                    if ($addon->{'id'} eq $configId) {
                        $res = $addon;
                        last;
                    }
                }
            }
        }
    }

    return($res);
}



sub pause_addon {
    debug("=== In pause_addon\n");

    my ($albApiUrl, $guid, $configId, $addonName, $addonId) = @_;
    my $path = "POST/54?iAction=7&iType=1";
    my $request = "{\"ConfigID\":\"$configId\",\"AddOnID\":\"$addonId\"}";
    my $res;

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in pause_addon()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request for pause add-on failed: '" . $decoded->{'StatusText'} . "'", 1);
    }

    my @addons = $decoded->{'AddOns'}->{'dataset'}->{'row'};
    if (scalar(@addons) > 0) {
        foreach my $addon_arrayref (@addons) {
            if (ref($addon_arrayref) eq "ARRAY") {
                foreach my $addon (@$addon_arrayref) {
                    if ($addon->{'id'} eq $configId) {
                        $res = $addon;
                        last;
                    }
                }
            }
        }
    }

    return($res);
}



sub resume_addon {
    debug("=== In resume_addon\n");

    my ($albApiUrl, $guid, $dockerImage, $addonName, $configId, $addonId, $externalIp, $externalPort) = @_;

    if (!defined($externalIp)) {
        $externalIp = '';    
    }
    if (!defined($externalPort)) {
        $externalPort = '';
    }

    my $path = "POST/54?iAction=7&iType=2";
    my $request = "{\"Repository\":\"$dockerImage\",\"AddOnName\":\"$addonName\",\"ExternalIPAddress\":\"$externalIp\",\"ExternalPort\":\"$externalPort\",\"ConfigID\":\"$configId\",\"AddOnID\":\"$addonId\"}";
    my $res;

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in resume_addon()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request for resume add-on failed: '" . $decoded->{'StatusText'} . "'", 1);
    }

    my @addons = $decoded->{'AddOns'}->{'dataset'}->{'row'};
    if (scalar(@addons) > 0) {
        foreach my $addon_arrayref (@addons) {
            if (ref($addon_arrayref) eq "ARRAY") {
                foreach my $addon (@$addon_arrayref) {
                    if ($addon->{'id'} eq $configId) {
                        $res = $addon;
                        last;
                    }
                }
            }
        }
    }

    return($res);
}



sub remove_addon {

    debug("=== In remove_addon\n");

    my ($albApiUrl, $guid, $configId, $addonId) = @_;
    my $path = "POST/54?iAction=8&iType=3";
    my $request = "{\"ConfigID\":\"$configId\",\"AddOnID\":\"$addonId\"}";
    my $res;

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in remove_addon()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request for remove add-on failed: '" . $decoded->{'StatusText'} . "'", 1);
    }

    my @addons = $decoded->{'AddOns'}->{'dataset'}->{'row'};
    if (scalar(@addons) > 0) {
        foreach my $addon_arrayref (@addons) {
            if (ref($addon_arrayref) eq "ARRAY") {
                foreach my $addon (@$addon_arrayref) {
                    if ($addon->{'id'} eq $configId) {
                        $res = $addon;
                        last;
                    }
                }
            }
        }
    }

    return($res);
}



sub restart_addon {
    debug("=== In restart_addon\n");

    my ($albApiUrl, $guid, $addon) = @_;

    $addon = stop_addon($albApiUrl, $guid, $addon->{'DockerImage'}, $addon->{'id'}, $addon->{'AddOnID'});
    debug("Addon Info:\n". encode_json($addon). "\n");

    $addon = start_addon($albApiUrl, $guid, $addon->{'DockerImage'}, $addon->{'id'}, $addon->{'AppName'}, $addon->{'ExternalIP'}, $addon->{'ExternalPort'});
    debug("Addon Info:\n". encode_json($addon). "\n");

    return($addon);
}



# Uploads Add-On config file from a file supplied as $configFileName
sub upload_addon_config {
    my ($albApiUrl, $guid, $addonId, $configFileName) = @_;

    if (! -r $configFileName) {
        error("Failed to read file '$configFileName' in upload_addon_config()", 1);
    }

    my $path = "POST/54?iAction=9&iType=1&ConfigID=$addonId&send=docker";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -F 'data=\@$configFileName' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", "-F data='\@$configFileName'");
    if (!$json) {
        error("Failed to connect to ALB API in upload_addon_config()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && 
        (($decoded->{'StatusText'} ne 'Your changes have been applied'))) {
        error("ALB API request to upload ALB config failed in upload_addon_config(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



# Configure WAF add-on for Azure WAF
sub configure_waf_addon {
    debug("=== In configure_waf_addon\n");

    my ($addonConfDir, $host) = @_;
    my $fileName = "$addonConfDir/etc/httpd/conf.d/99-waf.conf";
    my $url = "http://$host:8070/";
    my $found = 0;

# Modify $addonConfDir/etc/httpd/conf.d/99-waf.conf:
#-        ProxyPass              http://www.edgenexus.io/
#+        ProxyPass              http://192.168.4.5:8080/
#-        ProxyPassReverse       http://www.edgenexus.io/
#+        ProxyPassReverse       http://192.168.4.5:8080/

    open(FILE, $fileName) or
    error("Cannot open '$fileName' for reading.", 1);
    my @lines = <FILE>;
    close(FILE);

    foreach my $l (@lines) {
        $l =~ s/\n|\r$//;

        if ($l =~ /^(\s*ProxyPass\s+)\S+/) {
            $found++;
            $l =~ s/^(\s*ProxyPass\s+)\S+/$1$url/;
        }
        elsif ($l =~ /^(\s*ProxyPassReverse\s+)\S+/) {
            $found++;
            $l =~ s/^(\s*ProxyPassReverse\s+)\S+/$1$url/;
        }
    }

    if ($found > 0) {
        open(FILE, '>', $fileName) or
            error("Cannot open file $fileName for writing", 1);
        print FILE join("\n", @lines);
        close(FILE);
    }

    return($found);
}



# Get id of an option by its name from a combo set
sub get_combo_option_id {
    my ($combos, $comboName, $optionName, $not_found_ok) = @_;

    if (defined($combos) && defined($combos->{$comboName}) && defined($combos->{$comboName}->{'options'}) && 
        defined($combos->{$comboName}->{'options'}->{'option'}) && 
        (scalar(@{$combos->{$comboName}->{'options'}->{'option'}}) > 0)) {
        foreach my $option (@{$combos->{$comboName}->{'options'}->{'option'}}) {
            if ($option->{'value'} eq $optionName) {
                debug("get_combo_option_id: " . $comboName . ": " . $option->{'value'} . " -> " . $option->{'id'} ."\n");
                return($option->{'id'});
            }
        }
    }

    # Some options are allowed to have an arbitrary value, return $optionName in such case
    if ($not_found_ok) {
        return($optionName);
    } else {
        error("Requested combo option '$optionName' of '$comboName' not found in get_combo_option_id()", 1);
    }
}



sub get_vs_combo_options {
    debug("=== In get_vs_combo_options\n");

    my ($albApiUrl, $guid) = @_;
    my $path = "GET/29";
    my %res_tmp; my $res = \%res_tmp;

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_vs_combo_options()", 1);
    }
    my $decoded = decode_json($json);
    
    debug("$json\n");
    return($decoded);
}



sub get_vs_status {
    debug("=== In get_vs_status\n");

    my ($albApiUrl, $guid, $filter, $rs_num) = @_;
    my $path = "GET/31?req=refresh&FilterKeyword=$filter";
    my $res;

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_vs_status()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'dataset'}->{'ipService'}->{'sId'})) {
        # Data of a specific RS was requested
        if (defined($rs_num) && ($rs_num != 0)) {
            # RS numbering starts from 1 unlike numbering of array elements which starts from 0,
            # therefore we are decrementing $rs_num
            $rs_num--;
            my @data = @{$decoded->{'dataset'}->{'ipService'}->{'sId'}};
            if (defined($data[$rs_num])) {
                $res = $data[$rs_num];
            }
        } else {
            $res = $decoded->{'dataset'}->{'ipService'}->{'sId'};
        }
    }

    debug("$json\n");

    return($res);
}



# Find the first Virtual Service matching parameters: serviceName, ipAddr, port, serviceType, CSIPAddr, CSPort.
# $services input parameter must contain a Virtual Services JSON object returned by the ALB API.
# If any of the input parameters are empty, they are not checked while looking for a Virtual Service.
# If returnRS is true, then only the RS data are returned. Otherwise the complete VS data are returned.
# If returnRS is true and specified RS is not found, then an empty array is returned.
sub find_vs {
    debug("=== In find_vs\n");

    my ($albApiUrl, $guid, $services, $serviceName, $ipAddr, $subnetMask, $port, $serviceType, $CSIPAddr, $CSPort, $returnRS) = @_;
    my %res_tmp; my $res = \%res_tmp;

    # Find the Virtual Service
    if (defined($services->{'data'}->{'dataset'}->{'ipService'}) &&  
       ($services->{'data'}->{'dataset'}->{'ipService'} ne "")) {
    my @vips = @{$services->{'data'}->{'dataset'}->{'ipService'}};
    if (scalar(@vips) > 0) {
        foreach my $vss_ref (@vips) {
            foreach my $vs (@{$vss_ref}) {
            
                debug("VS:\n" . encode_json($vs) . "\n");
    
                my ($serviceNameCmp, $ipAddrCmp, $subnetMaskCmp, $portCmp, $serviceTypeCmp, $CSIPAddrCmp, $CSPortCmp) = 
                   ('', '', '', '', '', '', '');
                if (defined($serviceName) && ($serviceName ne '')) {
                    $serviceNameCmp = $vs->{'serviceName'};
                } else {
                    $serviceName = '';
                }
                if (defined($ipAddr) && ($ipAddr ne '')) {
                    $ipAddrCmp = $vs->{'ipAddr'};
                } else {
                    $ipAddr = '';
                }
                if (defined($subnetMask) && ($subnetMask ne '')) {
                    $subnetMaskCmp = $vs->{'subnetMask'};
                } else {
                    $subnetMask = '';
                }
                if (defined($port) && ($port ne '')) {
                    $portCmp = $vs->{'port'};
                } else {
                    $port = '';
                }
                if (defined($serviceType) && ($serviceType ne '')) {
                    $serviceTypeCmp = $vs->{'serviceType'};
                } else {
                    $serviceType = '';
                }
                if (!defined($CSIPAddr)) {
                    $CSIPAddr = '';
                }
                if (!defined($CSPort)) {
                    $CSPort = '';
                }

                if (($serviceNameCmp eq $serviceName) && 
                    ($ipAddrCmp eq $ipAddr) && ($subnetMaskCmp eq $subnetMask) && 
                    ($portCmp eq $port) && ($serviceTypeCmp eq $serviceType)) {

                    if (($CSIPAddr ne '') || ($CSPort ne '')) {
                        # Get Content Servers of a Virtual Service
                        my @css;
                        if (defined($vs->{'contentServer'}) && ($vs->{'contentServer'} ne "")) {
                            @css = $vs->{'contentServer'}->{'CServerId'};
                        }
                        if (scalar(@css) > 0) {
                            foreach my $cs_arref (@css) {  
                                if (scalar(@$cs_arref) > 0) {
                                foreach my $cs (@$cs_arref) {  
                                    if ($CSIPAddr ne '') {
                                        $CSIPAddrCmp = $cs->{'CSIPAddr'};
                                    }
                                    if ($CSPort ne '') {
                                        $CSPortCmp = $cs->{'CSPort'};
                                    }
                                    if (($CSIPAddrCmp eq $CSIPAddr) && ($CSPortCmp eq $CSPort)) {
                                        if (defined($returnRS) && $returnRS) {
                                            # Add VS data required for upating the RS
                                            $cs->{'editedInterface'} = $vs->{'InterfaceID'};
                                            $cs->{'editedChannel'} = $vs->{'ChannelID'};
                                            $cs->{'CheckChannelKey'} = $vs->{'ChannelKey'};
                                            $res = $cs;
                                        } else {
                                            $res = $vs;
                                        }
                                        last;
                                    }
                                }
                                }
                            }
                        }
                    } else {
                        if (defined($returnRS) && $returnRS) {
                            $res = ();
                        } else {
                            $res = $vs;
                        }
                        last;
                    }
                }
            }
        }
    }
    }

    return($res);
}



# Get the first Virtual Service matching parameters: serviceName, ipAddr, port, serviceType, CSIPAddr, CSPort.
# If any of the input parameters are empty, they are not checked while looking for a Virtual Service.
# If returnRS is true, then only the RS data are returned. Otherwise the complete VS data are returned.
# If returnRS is true and specified RS is not found, then an empty array is returned.
sub get_vs {
    debug("=== In get_vs\n");

    my ($albApiUrl, $guid, $serviceName, $ipAddr, $subnetMask, $port, $serviceType, $CSIPAddr, $CSPort, $returnRS) = @_;
    my $path = "GET/9";
    my %res_tmp; my $res = \%res_tmp;

    # Narrow down result set returned by API by applying a filter
    #
    # NOTE: VS filtering does not work with current API implementation,
    # API returns all VS on a VIP that matches the request.
    #
    # NOTE 2: filter keyword must be URL encoded, which is not done by 
    # the below code, hence it is commetned out.
    #if (defined($serviceName) && ($serviceName ne '')) {
    #    $path .= "?FilterKeyword=$serviceName&isChanged=true";
    #}
    #elsif (defined($ipAddr) && ($ipAddr ne '') && defined($port) && ($port ne '')) {
    #    $path .= "?FilterKeyword=$ipAddr:$port&isChanged=true";
    #}

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_vs()", 1);
    }
    my $decoded = decode_json($json);

    debug("$json\n");

    # Find the Virtual Service
    $res = find_vs($albApiUrl, $guid, $decoded, $serviceName, $ipAddr, $subnetMask, $port, $serviceType, $CSIPAddr, $CSPort, $returnRS);

    return($res);
}



# Update Virtual Service data
# If $update_what == 'service', main data (IP, mask, port, etc) of the VS are updated
# If $update_what == 'basic', basic tab data (monitoring, LB policy, etc) of the VS are updated
# If $update_what == 'advanced', advanced tab data of the VS are updated
# If $update_what == 'ssl-client-authentication', SSL CLient Authentication data of the VS are updated
sub update_vs {
    debug("=== In update_vs\n");

    my ($albApiUrl, $guid, $vs, $update_what) = @_;
    my $path;

    if ($update_what eq 'service') {
        $path = "POST/9?iAction=2&iType=1";
    }
    elsif ($update_what eq 'basic') {
        $path = "POST/9?iAction=2&iType=3";
    }
    elsif ($update_what eq 'advanced') {
        $path = "POST/9?iAction=2&iType=4";
    }
    elsif ($update_what eq 'ssl-client-authentication') {
        $path = "POST/9?iAction=2&iType=7";
    }
    elsif ($update_what eq 'load-balancing') {
        $path = "POST/9?iAction=2&iType=9";
    }
    else {
        error("Incorrect 'update_what' value in update_vs()", 1);
    }

    my $request = encode_json($vs);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a VS in update_vs()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        if (($decoded->{'StatusText'} =~ /RDP works better with Load Balancing Policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP will correct work with load balancing policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP will work correctly with load balancing policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP works better with load balancing policy RDP Cookie Persistence/) ||
            ($decoded->{'StatusText'} =~ /IP address \S+ is on the Add-Ons virtual network/) ||
            ($decoded->{'StatusText'} =~ /"TCP Connection" may be better monitored before "200OK"/)) {
            # Issue a warning message
            error("ALB API request to update a VS raised a warning in update_vs(): '" . $decoded->{'StatusText'} . "'", 0);
        } else {
            # Issue a fatal error
            error("ALB API request to update a VS failed in update_vs(): '" . $decoded->{'StatusText'} . "'", 1);
        }
    }

    debug("Result:\n". $json);

    return($decoded);
}



# Remove a Virtual Service
sub remove_vs {
    debug("=== In remove_vs\n");

    my ($albApiUrl, $guid, $vs) = @_;

    my $path = "POST/9?iAction=3&iType=4";
    my $request = encode_json($vs);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a VS in remove_vs()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        if (($decoded->{'StatusText'} =~ /RDP works better with Load Balancing Policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP will correct work with load balancing policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP will work correctly with load balancing policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP works better with load balancing policy RDP Cookie Persistence/) ||
            ($decoded->{'StatusText'} =~ /IP address \S+ is on the Add-Ons virtual network/) ||
            ($decoded->{'StatusText'} =~ /"TCP Connection" may be better monitored before "200OK"/)) {
            # Issue a warning message
            error("ALB API request to update a VS raised a warning in remove_vs(): '" . $decoded->{'StatusText'} . "'", 0);
        } else {
            # Issue a fatal error
            error("ALB API request to update a VS failed in remove_vs(): '" . $decoded->{'StatusText'} . "'", 1);
        }
    }

    debug("Result:\n". $json);

    return($decoded);
}



# Update Real Server data
sub update_rs {
    debug("=== In update_rs\n");

    my ($albApiUrl, $guid, $cs) = @_;

    # Update the Real Server with actual data
    my $path = "POST/9?iAction=2&iType=2";
    my $request = encode_json($cs);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a RS in update_rs()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        if (($decoded->{'StatusText'} =~ /RDP works better with Load Balancing Policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP will correct work with load balancing policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP will work correctly with load balancing policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP works better with load balancing policy RDP Cookie Persistence/) ||
            ($decoded->{'StatusText'} =~ /IP address \S+ is on the Add-Ons virtual network/) ||
            ($decoded->{'StatusText'} =~ /"TCP Connection" may be better monitored before "200OK"/)) {
            # Issue a warning message
            error("ALB API request to update a RS raised a warning in update_rs(): '" . $decoded->{'StatusText'} . "'", 0);
        } else {
            # Issue a fatal error
            error("ALB API request to update a RS failed in update_rs(): '" . $decoded->{'StatusText'} . "'", 1);
        }
    }

    debug("Result:\n". $json);

    return($decoded);
}



# Remove Real Server
sub remove_rs {
    debug("=== In remove_rs\n");

    my ($albApiUrl, $guid, $cs) = @_;

    # Remove the Real Server
    my $path = "POST/9?iAction=3&iType=5";
    my $request = encode_json($cs);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to remove a RS in remove_rs()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        if (($decoded->{'StatusText'} =~ /RDP works better with Load Balancing Policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP will correct work with load balancing policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP will work correctly with load balancing policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP works better with load balancing policy RDP Cookie Persistence/) ||
            ($decoded->{'StatusText'} =~ /IP address \S+ is on the Add-Ons virtual network/) ||
            ($decoded->{'StatusText'} =~ /"TCP Connection" may be better monitored before "200OK"/)) {
            # Issue a warning message
            error("ALB API request to remove a RS raised a warning in remove_rs(): '" . $decoded->{'StatusText'} . "'", 0);
        } else {
            # Issue a fatal error
            error("ALB API request to remove a RS failed in remove_rs(): '" . $decoded->{'StatusText'} . "'", 1);
        }
    }

    debug("Result:\n". $json);

    return($decoded);
}



# Get number of Virtual Services
sub get_vs_total_number {
    my $vs = $_[0];
    my $vs_num = 0;

    # Get number of existing Virtual Services
    if (defined($vs) && defined($vs->{'data'}) && defined($vs->{'data'}->{'dataset'}) &&
        defined($vs->{'data'}->{'dataset'}->{'ipService'})) {
        if ($vs->{'data'}->{'dataset'}->{'ipService'} ne '') {
            my @vips = @{$vs->{'data'}->{'dataset'}->{'ipService'}};
            if (scalar(@vips) > 0) {
                foreach my $vss_ref (@vips) {
                    foreach my $vs (@{$vss_ref}) {
                        $vs_num++;
                    }
                }
            }
        }
    }

    return($vs_num);
}



# Create a Virtual Service
sub create_vs {
    debug("=== In create_vs\n");

    my ($albApiUrl, $guid, $serviceName, $ipAddr, $subnetMask, $port, 
        $serviceType, $sslCertificate, $rss_ref) = @_;
    my %res_tmp; my $res = \%res_tmp;
    my $vs_num = 0;
    my $new_vs;


    # GET Virtual Services
    my $path = "GET/9";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in create_vs()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    # Get number of existing Virtual Services
    $vs_num = get_vs_total_number($decoded);
    debug("VS num = $vs_num\n");


    # First create an "empty" virtual service, afterwards update it with actual data
    debug("First create an \"empty\" virtual service\n");
    $path = "POST/9?iAction=3&iType=1";
    my $request = '{"editedInterface": "", "editedChannel": "", "CheckChannelKey": "", "CopyVIP": "0"}';

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to create a VS in create_vs()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        if (($decoded->{'StatusText'} =~ /RDP works better with Load Balancing Policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP will correct work with load balancing policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP will work correctly with load balancing policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP works better with load balancing policy RDP Cookie Persistence/) ||
            ($decoded->{'StatusText'} =~ /IP address \S+ is on the Add-Ons virtual network/) ||
            ($decoded->{'StatusText'} =~ /"TCP Connection" may be better monitored before "200OK"/)) {
            # Issue a warning message
            error("ALB API request to update a VS raised a warning in create_vs(): '" . $decoded->{'StatusText'} . "'", 0);
        } else {
            # Issue a fatal error
            error("ALB API request to update a VS failed in create_vs(): '" . $decoded->{'StatusText'} . "'", 1);
        }
    }

    debug("Result:\n". $json ."\n");


    # The $decoded object from the previous API request contains data of all Virtual Services.
    # Get data of the newly created "empty" Virtual Service data in $new_vs.
    $new_vs = find_vs($albApiUrl, $guid, $decoded, "", "", "", "", "");
    if (!defined($new_vs) or (scalar(keys(%{$new_vs})) < 1)) {
        error("Unable to find the created VS in create_vs()", 1);
    }

    # Update the virtual service with actual data
    debug("Update the virtual service with actual data\n");
    my $vs;
    $vs->{'CopyVIP'} = '0';
    $vs->{'editedInterface'} = $new_vs->{'InterfaceID'};
    $vs->{'editedChannel'} = $new_vs->{'ChannelID'};
    $vs->{'CheckChannelKey'} = $new_vs->{'ChannelKey'};
    $vs->{'serviceName'} = $serviceName;
    $vs->{'ipAddr'} = $ipAddr;
    $vs->{'subnetMask'} = $subnetMask;
    $vs->{'port'} = $port;
    $vs->{'serviceType'} = $serviceType;
    $vs->{'localPortEnabledChecked'} = 'true';
    debug("VS:\n" . encode_json($vs) . "\n");
    $decoded = update_vs($albApiUrl, $guid, $vs, 'service');


    # The $decoded object from the previous API request contains data of all Virtual Services.
    # Get data of the newly created Virtual Service data in $new_vs.
    $new_vs = find_vs($albApiUrl, $guid, $decoded, $serviceName, $ipAddr, $subnetMask, $port, $serviceType);
    if (!defined($new_vs) or (scalar(keys(%{$new_vs})) < 1)) {
        error("Unable to find the created VS in create_vs()", 1);
    }

    # Monitoring parameters definition is disabled to make VS creation faster
#    # Change Advanced Tab settings for the VS
#    $vs->{'monitoringInterval'} = '20';
#    $vs->{'monitoringTimeout'} = '5';
#    $vs->{'securityLog'} = 'On';
#    $vs->{'editedInterface'} = $new_vs->{'InterfaceID'};
#    $vs->{'editedChannel'} = $new_vs->{'ChannelID'};
#    $vs->{'connectivity'} = $new_vs->{'connectivity'};
#    $vs->{'ConnectionTimeout'} = $new_vs->{'ConnectionTimeout'};
#    $vs->{'InCount'} = $new_vs->{'InCount'};
#    $vs->{'OutCount'} = $new_vs->{'OutCount'};
#    $vs->{'sslResumption'} = $new_vs->{'sslResumption'};
#    $vs->{'sslRenegotiation'} = $new_vs->{'sslRenegotiation'};
#    $vs->{'SNIDefaultCertificateName'} = $new_vs->{'SNIDefaultCertificateName'};
#    $vs->{'CipherName'} = $new_vs->{'CipherName'};
#    $res = update_vs($albApiUrl, $guid, $vs, 'advanced');


    # Enable SSL for the VS
    if (defined($sslCertificate) && ($sslCertificate ne '')) {
        # The $decoded object from the previous API request contains data of all Virtual Services.
        # Get data of the newly created Virtual Service data in $new_vs.
        $new_vs = find_vs($albApiUrl, $guid, $decoded, $serviceName, $ipAddr, $subnetMask, $port, $serviceType);
        if (!defined($new_vs) or (scalar(keys(%{$new_vs})) < 1)) {
            error("Unable to find the created VS in create_vs()", 1);
        }
        $vs->{'editedInterface'} = $new_vs->{'InterfaceID'};
        $vs->{'editedChannel'} = $new_vs->{'ChannelID'};
        $vs->{'CheckChannelKey'} = $new_vs->{'ChannelKey'};
        $vs->{'CipherName'} = $new_vs->{'CipherName'};
        $vs->{'SNIDefaultCertificateName'} = $new_vs->{'SNIDefaultCertificateName'};
        $vs->{'sslCertificate'} = $sslCertificate;
        $vs->{'sslClientCertificate'} = $new_vs->{'sslClientCertificate'};
        $vs->{'sslRenegotiation'} = $new_vs->{'sslRenegotiation'};
        $vs->{'sslResumption'} = $new_vs->{'sslResumption'};
        enable_ssl_vs($albApiUrl, $guid, $vs);
    }


    # Create Real Servers defined in $rss_ref
    my @rss = @{$rss_ref};
    my $cId = 0;
    foreach my $rs_ref (@rss) {
        my %rs = %{$rs_ref};

        # The $decoded object from the previous API request contains data of all Virtual Services.
        # Get data of the newly created Virtual Service data in $new_vs.
        $new_vs = find_vs($albApiUrl, $guid, $decoded, $serviceName, $ipAddr, $subnetMask, $port, $serviceType);
        if (!defined($new_vs) or (scalar(keys(%{$new_vs})) < 1)) {
            error("Unable to find the created VS in create_vs()", 1);
        }

        # Get the newly created "empty" Real Server data in $empty_cs
        my $empty_cs;
        my @css;
        if (defined($new_vs->{'contentServer'}) && ($new_vs->{'contentServer'} ne "")) {
            @css = $new_vs->{'contentServer'}->{'CServerId'};
        }
        if (scalar(@css) > 0) {
            foreach my $cs_ref (@css) {  
                if (scalar(@{$cs_ref}) > 0) {
                    foreach my $tmp_cs (@{$cs_ref}) {
                        debug(">>> tmp_cs:\n" . encode_json($tmp_cs) . "\n");
                        if ($tmp_cs->{'cId'} == $cId) {
                            $empty_cs = $tmp_cs;
                            last;
                        }
                    }
                }
            }
        }

        # Fill in actual data for a CS
        my $cs;
        $cs->{'editedInterface'} = $new_vs->{'InterfaceID'};
        $cs->{'editedChannel'} = $new_vs->{'ChannelID'};
        $cs->{'serverKey'} = $empty_cs->{'serverKey'};
        $cs->{'cId'} = $empty_cs->{'cId'};
        $cs->{'CSActivity'} = "1";
        $cs->{'CSIPAddr'} = $rs{'addr'};
        $cs->{'CSPort'} = $rs{'port'};
        $cs->{'CSNotes'} = $rs{'notes'};
        $cs->{'ServerId'} = $rs{'ServerId'};
        if (!defined($rs{'weight'})) {
            $rs{'weight'} = "100";
        }
        $cs->{'WeightFactor'} = $rs{'weight'};
        $cId++;

        # The first empty CS (cId == 0) is created automatically when creating a new VS, 
        # update its data
        debug("Update the Real Server with actual data\n");
        debug("RS:\n" . encode_json($cs) . "\n");
        $decoded = update_rs($albApiUrl, $guid, $cs);

        # The first empty CS (cId == 0) is created automatically when creating a new VS.
        # The next empty CSs must be created explicitly:
        if ((scalar(@rss) > 1) && ($cId < scalar(@rss))) {
            debug("First create an \"empty\" Real Server\n");
            $path = "POST/9?iAction=3&iType=3";
            my $cs;
            $cs->{'editedInterface'} = $new_vs->{'InterfaceID'};
            $cs->{'editedChannel'} = $new_vs->{'ChannelID'};

            my $request = encode_json($cs);

            debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
            $json = alb_api_post($guid, "$albApiUrl/$path", $request);
            if (!$json) {
                error("Failed to connect to ALB API to create a RS in create_vs()", 1);
            }
            # The Virtual Service data will be obtained from this $decoded object when the next RS will be created
            $decoded = decode_json($json);

            if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
                if (($decoded->{'StatusText'} =~ /RDP works better with Load Balancing Policy RDP Cookie Persisten[cs]e/) ||
                    ($decoded->{'StatusText'} =~ /RDP will correct work with load balancing policy RDP Cookie Persisten[cs]e/) ||
                    ($decoded->{'StatusText'} =~ /RDP will work correctly with load balancing policy RDP Cookie Persisten[cs]e/) ||
                    ($decoded->{'StatusText'} =~ /RDP works better with load balancing policy RDP Cookie Persistence/) ||
                    ($decoded->{'StatusText'} =~ /IP address \S+ is on the Add-Ons virtual network/) ||
                    ($decoded->{'StatusText'} =~ /"TCP Connection" may be better monitored before "200OK"/)) {
                    # Issue a warning message
                    error("ALB API request to update a RS raised a warning in create_vs(): '" . $decoded->{'StatusText'} . "'", 0);
                } else {
                    # Issue a fatal error
                    error("ALB API request to update a RS failed in create_vs(): '" . $decoded->{'StatusText'} . "'", 1);
                }
            }
            
            debug("Create empty CS result:\n". $json ."\n");
        }
    }

    return($res);
}



# Copy a Virtual Service
sub copy_vs {
    debug("=== In copy_vs\n");

    my ($albApiUrl, $guid, $serviceName, $ipAddr, $subnetMask, $port, 
        $serviceType, $copyInterface, $copyChannel) = @_;
    my %res_tmp; my $res = \%res_tmp;
    my $vs_num = 0;

    if (!defined($serviceName) || ($serviceName eq '')) {
        error("Mandatory parameter serviceName was not supplied to copy_vs()", 1);
    }
    if (!defined($ipAddr) || ($ipAddr eq '')) {
        error("Mandatory parameter ipAddr was not supplied to copy_vs()", 1);
    }
    if (!defined($subnetMask) || ($subnetMask eq '')) {
        error("Mandatory parameter subnetMask was not supplied to copy_vs()", 1);
    }
    if (!defined($port) || ($port eq '')) {
        error("Mandatory parameter port was not supplied to copy_vs()", 1);
    }
    if (!defined($serviceType) || ($serviceType eq '')) {
        error("Mandatory parameter serviceType was not supplied to copy_vs()", 1);
    }


    # GET Virtual Services
    my $path = "GET/9";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in copy_vs()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    # Get number of existing Virtual Services
    $vs_num = get_vs_total_number($decoded);
    debug("VS num = $vs_num\n");

    # First create an "empty" virtual service, afterwards update it with actual data
    debug("First create an \"empty\" virtual service\n");
    $path = "POST/9?iAction=3&iType=1";
    my $request = '{"CopyVIP": "0"}';

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to create a VS in copy_vs()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to create a VS failed in copy_vs(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");


    # Store the newly created "empty" virtual service data in $empty_vs
    debug("Get the newly created \"empty\" virtual service in \$empty_vs\n");
    my $empty_vs;
    if ($decoded->{'data'}->{'dataset'}->{'ipService'} ne "") {
        my @vips = @{$decoded->{'data'}->{'dataset'}->{'ipService'}};
        if (scalar(@vips) > 0) {
            foreach my $vss_ref (@vips) {
                foreach my $tmp_vs (@{$vss_ref}) {
                    if ($tmp_vs->{'sId'} == $vs_num + 1) {
                        $empty_vs = $tmp_vs;
                        last;
                    }
                }
            }
        }
    }


    # Update the virtual service with actual data
    debug("Update the virtual service with actual data\n");
    my $vs;
    $vs->{'CopyVIP'} = '1';
    $vs->{'CopyInterface'} = $copyInterface;
    $vs->{'CopyChannel'} = $copyChannel;
    $vs->{'editedInterface'} = $empty_vs->{'InterfaceID'};
    $vs->{'editedChannel'} = $empty_vs->{'ChannelID'};
    $vs->{'CheckChannelKey'} = $empty_vs->{'ChannelKey'};
    if (defined($serviceName) && ($serviceName ne '')) {
        $vs->{'serviceName'} = $serviceName;
    } else {
        $vs->{'serviceName'} = $serviceName;
    }
    if (defined($ipAddr) && ($ipAddr ne '')) {
        $vs->{'ipAddr'} = $ipAddr;
    }
    if (defined($subnetMask) && ($subnetMask ne '')) {
        $vs->{'subnetMask'} = $subnetMask;
    }
    if (defined($port) && ($port ne '')) {
        $vs->{'port'} = $port;
    }
    if (defined($serviceType) && ($serviceType ne '')) {
        $vs->{'serviceType'} = $serviceType;
    }
    $vs->{'localPortEnabledChecked'} = 'true';
    $vs->{'primaryChecked'} = 'Passive';
    debug("VS:\n" . encode_json($vs) . "\n");
    $decoded = update_vs($albApiUrl, $guid, $vs, 'service');
    
    return($decoded);
}



# Enable SSL for a Virtual Service
sub enable_ssl_vs {
    my ($albApiUrl, $guid, $vs) = @_;

    # Update Basic Tab Information
    debug("Update Basic Tab Information\n");
    my $path = "POST/9?iAction=2&iType=6";
    my $request = encode_json($vs);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update basic tab information in enable_ssl_vs()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        if (($decoded->{'StatusText'} =~ /RDP works better with Load Balancing Policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP will correct work with load balancing policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP will work correctly with load balancing policy RDP Cookie Persisten[cs]e/) ||
            ($decoded->{'StatusText'} =~ /RDP works better with load balancing policy RDP Cookie Persistence/) ||
            ($decoded->{'StatusText'} =~ /IP address \S+ is on the Add-Ons virtual network/) ||
            ($decoded->{'StatusText'} =~ /"TCP Connection" may be better monitored before "200OK"/)) {
            # Issue a warning message
            error("ALB API request to update basic tab information raised a warning in enable_ssl_vs(): '" . $decoded->{'StatusText'} . "'", 0);
        } else {
            # Issue a fatal error
            error("ALB API request to update basic tab information failed in enable_ssl_vs(): '" . $decoded->{'StatusText'} . "'", 1);
        }
    }

    debug("Result:\n". $json ."\n");
}



# Remove all existing Virtual Services
sub remove_all_vs {
    my ($albApiUrl, $guid) = @_;
    my @vss;

    my $have_vs = 1;
    while ($have_vs) {
        # GET Virtual Services
        my $path = "GET/9";
        debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
        my $json = alb_api_get($guid, "$albApiUrl/$path");
        if (!$json) {
            error("Failed to connect to ALB API in remove_all_vs()", 1);
        }
        my $decoded = decode_json($json);
        debug("$json\n");
    

        if ($decoded->{'data'}->{'dataset'}->{'ipService'} ne "") {
            # Get InterfaceID and ChannelID of a first VS
            my @vips = @{$decoded->{'data'}->{'dataset'}->{'ipService'}};
            my $first_vs = $vips[0][0];
            my $del_vs = {'editedInterface' => $first_vs->{'InterfaceID'},
                          'editedChannel' => $first_vs->{'ChannelID'},
                          'CheckChannelKey' => $first_vs->{'ChannelKey'}};

            # Remove the first VS
            $path = "POST/9?iAction=3&iType=4";
            my $request = encode_json($del_vs);

            debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
            $json = alb_api_post($guid, "$albApiUrl/$path", $request);
            if (!$json) {
                error("Failed to connect to ALB API to update a VS in remove_all_vs()", 1);
            }
            $decoded = decode_json($json);

            if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
                error("ALB API request to remove a VS failed in remove_all_vs(): '" . $decoded->{'StatusText'} . "'", 1);
            }

            debug("Result:\n". $json);
        } else {
            $have_vs = 0;
        }
    }
}



# Get SSL certificate status
sub get_ssl_cert_status {
    my ($albApiUrl, $guid, $sslCertificateName) = @_;
    my $status;

    debug("Get SSL Certificate status\n");
    my $path = "GET/19";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_ssl_cert_status()", 1);
    }

    my $decoded = decode_json($json);
    debug("Result:\n". $json ."\n");

    if (defined($decoded->{'StatusImage'}) && 
        ($decoded->{'StatusText'} ne 'Your changes have been applied') &&
        ($decoded->{'StatusText'} ne 'get')
    ) {
        error("ALB API request to get SSL certificate status failed in get_ssl_cert_status(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    my $comboName = 'CertificateManageCombo';
    if (defined($decoded) && defined($decoded->{$comboName}) && defined($decoded->{$comboName}->{'options'}) &&
        defined($decoded->{$comboName}->{'options'}->{'option'}) && 
        (scalar(@{$decoded->{$comboName}->{'options'}->{'option'}}) > 0)) {
        foreach my $option (@{$decoded->{$comboName}->{'options'}->{'option'}}) {
            if ($option->{'id'} eq $sslCertificateName) {
                debug("get_ssl_cert_status: " . $comboName . ": " . $option->{'id'} . " -> " . $option->{'value'});
                $status = $option->{'value'};
                $status =~ s/$sslCertificateName\((.*?)\)/$1/;
                last;
            }
        }
    }

    return($status);
}



# Get SSL certificate details
sub get_ssl_cert_details {
    my ($albApiUrl, $guid, $sslCertificateName) = @_;
    my $res;

    # Have to make GET before POST
    my $path = "GET/19";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_ssl_cert_details()", 1);
    }

    my $options;
    $options->{'CertificateName'} = $sslCertificateName;
    $options->{'CetificateName'} = $sslCertificateName;

    debug("Get SSL Certificate details\n");
    $path = "POST/19?iAction=2&iType=1&show=cert";

    my $request = encode_json($options);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in get_ssl_cert_details()", 1);
    }
    my $decoded = decode_json($json);

    debug("Result:\n". $json ."\n");

    if (defined($decoded->{'StatusImage'}) && 
        ($decoded->{'StatusText'} ne 'Your changes have been applied') &&
        ($decoded->{'StatusText'} ne 'Certificate has been deleted.')
    ) {
        error("ALB API request to get SSL certificate details failed in get_ssl_cert_details(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    if (!defined($decoded->{'CertificateName'})) {
        error("ALB API request to get SSL certificate details failed in get_ssl_cert_details(): '" . $decoded->{'StatusText'} . "'", 1);
    } else {
        $res = $decoded;
    }

    return($res);
}



# Create SSL certificate or CSR
sub create_ssl_cert {
    my ($albApiUrl, $guid, $sslCertificateName, $domainName, $keyLength, $period, 
        $organizationUnit, $city, $county, $country, $is_csr) = @_;
    my $res;

    # Have to make GET before POST
    my $path = "GET/19";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in create_ssl_cert()", 1);
    }

    my $options;
    $options->{'SslCertificateNameText'} = $sslCertificateName;
    $options->{'SslOrganisationText'} = $domainName;
    $options->{'SslOrganisationUnitNameText'} = $organizationUnit;
    $options->{'SslCityText'} = $city;
    $options->{'SslCountyText'} = $county;
    $options->{'SslCountryText'} = $country;
    $options->{'SslDomainText'} = $domainName;
    $options->{'SslKeyLengthText'} = $keyLength;
    $options->{'SSLPeriod'} = $period;

    if (defined($is_csr) && $is_csr) {
        debug("Create SSL CSR\n");
        $path = "POST/19?iAction=1&iType=2&request=cert";
    } else {
        debug("Create SSL Certificate\n");
        $path = "POST/19?iAction=1&iType=1";
    }

    my $request = encode_json($options);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to create SSL certificate create_ssl_cert()", 1);
    }
    my $decoded = decode_json($json);

    debug("Result:\n". $json ."\n");

    if (defined($decoded->{'StatusImage'}) && 
        ($decoded->{'StatusText'} ne 'Your changes have been applied') &&
        ($decoded->{'StatusText'} ne 'Local certificate has been created')
    ) {
        error("ALB API request to create SSL certificate failed in create_ssl_cert(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    if (defined($is_csr) && $is_csr) {
        if (!defined($decoded->{'CertReqText'})) {
            error("ALB API request to create SSL CSR did not return CSR data in create_ssl_cert(): '" . $decoded->{'StatusText'} . "'", 1);
        }
        $res = $decoded->{'CertReqText'};
    }

    return($res);
}



# Install signed SSL certificate
sub install_signed_ssl_cert {
    my ($albApiUrl, $guid, $sslCertificateName, $signed) = @_;
    my $res;

    # Have to make GET before POST
    my $path = "GET/19";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in create_ssl_cert()", 1);
    }

    my $options;
    $options->{'CertificateName'} = $sslCertificateName;
    $options->{'CetificateName'} = $sslCertificateName;
    $options->{'PasteSignature'} = $signed;

    debug("Install signed SSL Certificate\n");
    $path = "POST/19?iAction=2&iType=2";

    my $request = encode_json($options);

    # Replace "\n" with new line characters in SSL certificate text after perl encode_json()
    $request =~ s/\\n/\n/g;

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in install_signed_ssl_cert()", 1);
    }
    my $decoded = decode_json($json);

    debug("Result:\n". $json ."\n");

    if (defined($decoded->{'StatusImage'}) && 
        ($decoded->{'StatusText'} ne 'Your changes have been applied') &&
        ($decoded->{'StatusText'} ne 'Certificate has been installed.')
    ) {
        error("ALB API request to install signed SSL certificate failed in install_signed_ssl_cert(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



# Install intermediate SSL certificate
sub install_intermediate_ssl_cert {
    my ($albApiUrl, $guid, $sslCertificateName, $intermediate) = @_;
    my $res;

    # Have to make GET before POST
    my $path = "GET/19";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in create_ssl_cert()", 1);
    }

    my $options;
    $options->{'CertificateName'} = $sslCertificateName;
    $options->{'CetificateName'} = $sslCertificateName;
    $options->{'PasteSignature'} = $intermediate;

    debug("Install intermediate SSL Certificate\n");
    $path = "POST/19?iAction=2&iType=3";

    my $request = encode_json($options);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in install_intermediate_ssl_cert()", 1);
    }
    my $decoded = decode_json($json);

    debug("Result:\n". $json ."\n");

    if (defined($decoded->{'StatusImage'}) && 
        ($decoded->{'StatusText'} ne 'Your changes have been applied') &&
        ($decoded->{'StatusText'} ne 'Certificate intermediate installed successfully')
    ) {
        error("ALB API request to install intermediate SSL certificate failed in install_intermediate_ssl_cert(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



# Renew SSL certificate
# Self-signed certificates are renewed by ALB itself, no CSR is returned.
# For the other kinds of certificates (incluing imported) a CSR is returned,
# and the certificate status is changed to Pending-Renewal.
sub renew_ssl_cert {
    my ($albApiUrl, $guid, $sslCertificateName, $paste) = @_;
    my $res;

    # Have to make GET before POST
    my $path = "GET/19";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in renew_ssl_cert()", 1);
    }

    my $options;
    $options->{'CertificateName'} = $sslCertificateName;
    $options->{'CetificateName'} = $sslCertificateName;
    $options->{'PasteSignature'} = $paste;

    debug("Renew SSL Certificate\n");
    $path = "POST/19?iAction=2&iType=5&renew=cert";

    my $request = encode_json($options);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in renew_ssl_cert()", 1);
    }
    my $decoded = decode_json($json);

    debug("Result:\n". $json ."\n");

    # Renewing a non-self-signed certificate
    if (defined($decoded->{'Key'})) {
        return($decoded->{'Key'});
    }
    # Renewing a self-signed certificate
    if (defined($decoded->{'StatusImage'}) &&
        ($decoded->{'StatusText'} ne 'Your changes have been applied') &&
        ($decoded->{'StatusText'} ne 'Local certificate has been renewed')
    ) {
        error("ALB API request to renew SSL certificate did not return CSR data in renew_ssl_cert(): '" . $decoded->{'StatusText'} . "'", 1);
    }
}



# Sign client certificate
sub sign_client_cert {
    my ($albApiUrl, $guid, $CACert, $ClientCert) = @_;

    # Have to make GET before POST
    my $path = "GET/19";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in sign_client_cert()", 1);
    }

    my $options;
    $options->{'CACert'} = $CACert;
    $options->{'ClientCert'} = $ClientCert;

    debug("Sign client SSL certificate\n");
    $path = "POST/19?iAction=8&iType=1";

    my $request = encode_json($options);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in sign_client_cert()", 1);
    }
    my $decoded = decode_json($json);

    debug("Result:\n". $json ."\n");

    if (defined($decoded->{'StatusImage'}) && 
        ($decoded->{'StatusText'} ne 'Your changes have been applied') &&
        ($decoded->{'StatusText'} ne 'Certificates have been successfully signed')
    ) {
        error("ALB API request to remove SSL certificate failed in sign_client_cert(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



# Remove SSL certificate
sub remove_ssl_cert {
    my ($albApiUrl, $guid, $sslCertificateName) = @_;

    # Have to make GET before POST
    my $path = "GET/19";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in remove_ssl_cert()", 1);
    }

    my $options;
    $options->{'CertificateName'} = $sslCertificateName;
    $options->{'CetificateName'} = $sslCertificateName;

    debug("Remove SSL Certificate\n");
    $path = "POST/19?iAction=2&iType=4";

    my $request = encode_json($options);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in remove_ssl_cert()", 1);
    }
    my $decoded = decode_json($json);

    debug("Result:\n". $json ."\n");

    if (defined($decoded->{'StatusImage'}) && 
        ($decoded->{'StatusText'} ne 'Your changes have been applied') &&
        ($decoded->{'StatusText'} ne 'Certificate has been deleted.')
    ) {
        error("ALB API request to remove SSL certificate failed in remove_ssl_cert(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



# Export SSL certificate
sub export_ssl_cert {
    my ($albApiUrl, $guid, $sslCertificateName, $password) = @_;
    my $res;

    my $path = "GET/19?download=sslexport&iAction=4&name=$sslCertificateName&pas=$password";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    $res = alb_api_get($guid, "$albApiUrl/$path");
    if (!$res) {
        error("Failed to connect to ALB API in export_ssl_cert()", 1);
    }

    return($res);
}



# Import SSL certificate
sub import_ssl_cert {
    my ($albApiUrl, $guid, $sslCertificateName, $sslCertificatePassword, $fileName) = @_;

    # Have to make GET before POST
    my $path = "GET/19";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in import_ssl_cert()", 1);
    }

    debug("Import SSL Certificate\n");
    $path = "POST/19?send=sslimport&iAction=3&iType=1";

    my $request = "-F 'SslCertificatesImportCertificateNameText=$sslCertificateName' ".
                  "-F 'SslCertificatesImportPasswordText=$sslCertificatePassword' ".
                  "-F 'SslCertificatesImportUploadText=\@$fileName'";

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" $request \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in import_ssl_cert()", 1);
    }
    my $decoded = decode_json($json);

    debug("Result:\n". $json ."\n");

    if (defined($decoded->{'StatusImage'}) && 
        ($decoded->{'StatusText'} ne 'Your changes have been applied') &&
        ($decoded->{'StatusText'} ne 'Certificate has been successfully imported')
    ) {
        error("ALB API request to import SSL certificate failed in import_ssl_cert(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



# Get a list of flightPATHs applied to a Virtual Service matching the parameters: serviceName, ipAddr, port, serviceType.
# If any of the input parameters are empty, they are not checked while looking for a Virtual Service.
sub get_vs_fps {
    debug("=== In get_vs_fps\n");

    my ($albApiUrl, $guid, $serviceName, $ipAddr, $subnetMask, $port, $serviceType) = @_;
    my $path = "GET/9";
    my @res_tmp; my $res = \@res_tmp;

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_vs_fps()", 1);
    }
    my $decoded = decode_json($json);

    debug("$json\n");

    # Find the Virtual Service
    my $vs = get_vs($albApiUrl, $guid, $serviceName, $ipAddr, $subnetMask, $port, $serviceType);
    if (!defined($vs) || !defined($vs->{'InterfaceID'})) {
        error("Virtual service '$serviceName' not found in get_vs_fps()", 1);
    }
    
    debug("The VS:" . encode_json($vs) . "\n");

    # Make a list of flightPATHs applied to the VS
    foreach my $fp (@{$vs->{'flightPath'}->{'flightPathId'}}) {
        if ($fp->{'flightPathSelected'} > 0) {
                push(@res_tmp, $fp);
                debug("Found FP: ". encode_json($fp) ."\n");
        }
    }

    return($res);
}



# Manage flightPATHs of a Virtual Service matching the parameters: serviceName, ipAddr, port, serviceType.
# If any of the input parameters are empty, they are not checked while looking for a Virtual Service.
# Allowed $actions are: apply, unapply, moveup, movedown.
sub manage_vs_fps {
    debug("=== In manage_vs_fps\n");

    my ($albApiUrl, $guid, $action, $serviceName, $ipAddr, $subnetMask, $port, $serviceType, $fps_ref) = @_;
    my %res_tmp; my $res = \%res_tmp;
    my @fps = @{$fps_ref};

    # Find the Virtual Service
    my $vs = get_vs($albApiUrl, $guid, $serviceName, $ipAddr, $subnetMask, $port, $serviceType);
    if (!defined($vs) || !defined($vs->{'InterfaceID'})) {
        error("Virtual service '$serviceName' not found in manage_vs_fps()", 1);
    }

    debug("The VS:" . encode_json($vs) . "\n");

    # Make up a list of flightPATHs to be applied in the following form:
    # [
    #   {
    #      "editedInterface":"0", "editedChannel":"0", "CheckChannelKey":"1.1",
    #      "flightPathName": "A1 SQL injection form", 
    #      "flightPathDropName":"", "flightPathDropId":"","position":""
    #   },...
    # ]
    my @request_arr;
    foreach my $fpName (@fps) {
        my $obj;
        $obj->{'editedInterface'} = $vs->{'InterfaceID'};
        $obj->{'editedChannel'} = $vs->{'ChannelID'};
        $obj->{'CheckChannelKey'} = $vs->{'ChannelKey'};
        $obj->{'flightPathName'} = $fpName;
        $obj->{'flightPathDropName'} = '';
        $obj->{'flightPathDropId'} = '';
        push(@request_arr, $obj);
    }

    my $path;
    if ($action eq 'apply') {
        $path = "POST/9?iAction=4&iType=1";
    } elsif ($action eq 'unapply') {
        $path = "POST/9?iAction=4&iType=2";
    } elsif ($action eq 'moveup') {
        $path = "POST/9?iAction=4&iType=3";
    } elsif ($action eq 'movedown') {
        $path = "POST/9?iAction=4&iType=4";
        # When moving flightPATHs down they must be passed in reverse order
        @request_arr = reverse(@request_arr);
    } else {
        error("Incorrect action '$action' supplied to manage_vs_fps()", 1);
    }

    # Electron supports a list of flightPATHs for apply/unapply actions, while DM supports 
    # only a single flightPATH. Therefore we make up a list JSON object in case if 
    # @request_arr contains multiple flightPATHs, otherwise we make up a non-list JSON 
    # object with a single flightPATH. Caller of this function is responsible for proper 
    # usage according to ALB SW version.
    my $request;
    if (scalar(@request_arr) > 1) {
        $request = encode_json(\@request_arr);
    } else {
        $request = encode_json($request_arr[0]);
    }

    # Apply/unapply/move flightPATHs
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    AE::log debug => "JSON reply (action is $action): `%s`", $json;

    if (!$json) {
        error("Failed to connect to ALB API to apply FPs to a VS in manage_vs_fps()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) { 
        if ($decoded->{'StatusText'} =~ /Terminal flightPATH rule .*? can prevent later rules from running./) {
            # Issue a warning message
            error("ALB API request to $action FPs raised a warning in manage_vs_fps(): '" . $decoded->{'StatusText'} . "'", 0);
        } else {
            # Issue a fatal error
            error("ALB API request to $action FPs failed in manage_vs_fps(): '" . $decoded->{'StatusText'} . "'", 1);
        }
    }

    debug("Result:\n". $json);

    return($decoded);
}

# Manage flightPATHs of a Virtual Service matching the parameters: InterfaceID, ChannelID, ChannelKey
# Allowed $actions are: apply, unapply, moveup, movedown.
sub manage_vs_fps_by_ids {
    debug("=== In manage_vs_fps_by_ids\n");

    my ($albApiUrl, $guid, $action, $InterfaceID, $ChannelID, $ChannelKey, $fps_ref) = @_;
    my %res_tmp; my $res = \%res_tmp;
    my @fps = @{$fps_ref};

    # Make up a list of flightPATHs to be applied in the following form:
    # [
    #   {
    #      "editedInterface":"0", "editedChannel":"0", "CheckChannelKey":"1.1",
    #      "flightPathName": "A1 SQL injection form", 
    #      "flightPathDropName":"", "flightPathDropId":"","position":""
    #   },...
    # ]
    my @request_arr;
    foreach my $el (@fps) {
        my $obj;
        # Important: Stringify values.
        $obj->{'editedInterface'} = "" . $InterfaceID;
        $obj->{'editedChannel'}   = "" . $ChannelID;

        if (ref $el eq 'HASH') {
            # merge hashes (e.g. keys: flightPathDragId, flightPathDropId, etc.)
            for my $k (sort keys %$el) {
                $obj->{$k} = "" . $el->{$k};
            }
        }
        else {
            my $fpName = $el;
            $obj->{'CheckChannelKey'} = "" . $ChannelKey;
            $obj->{'flightPathName'} = $fpName;
            $obj->{'flightPathDropName'} = '';
            $obj->{'flightPathDropId'} = '';
        }

        push(@request_arr, $obj);
    }

    my $path;
    if ($action eq 'apply') {
        $path = 'POST/9?iAction=4&iType=1';
    } elsif ($action eq 'unapply') {
        $path = 'POST/9?iAction=4&iType=2';
    } elsif ($action eq 'moveup') {
        $path = 'POST/9?iAction=4&iType=3';
    } elsif ($action eq 'movedown') {
        $path = 'POST/9?iAction=4&iType=4';
        # When moving flightPATHs down they must be passed in reverse order
        @request_arr = reverse(@request_arr);
    } elsif ($action eq 'drag-n-drop') {
        $path = 'POST/9?iAction=4&iType=5';
    } else {
        error("Incorrect action '$action' supplied to manage_vs_fps()", 1);
    }

    # Electron supports a list of flightPATHs for apply/unapply actions, while DM supports 
    # only a single flightPATH. Therefore we make up a list JSON object in case if 
    # @request_arr contains multiple flightPATHs, otherwise we make up a non-list JSON 
    # object with a single flightPATH. Caller of this function is responsible for proper 
    # usage according to ALB SW version.
    my $request;
    if (scalar(@request_arr) > 1) {
        $request = encode_json(\@request_arr);
    } else {
        $request = encode_json($request_arr[0]);
    }

    # Apply/unapply/move flightPATHs
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    AE::log debug => "JSON reply (action is $action): `%s`", $json;

    if (!$json) {
        error("Failed to connect to ALB API to apply FPs to a VS in manage_vs_fps()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) { 
        if ($decoded->{'StatusText'} =~ /Terminal flightPATH rule .*? can prevent later rules from running./) {
            # Issue a warning message
            error("ALB API request to $action FPs raised a warning in manage_vs_fps(): '" . $decoded->{'StatusText'} . "'", 0);
        } else {
            # Issue a fatal error
            error("ALB API request to $action FPs failed in manage_vs_fps(): '" . $decoded->{'StatusText'} . "'", 1);
        }
    }

    debug("Result:\n". $json);

    return($decoded);
}

# Get a first flightPATH matching parameters: id, name, desc, inUse.
# If any of the input parameters are empty, they are not checked while looking for a flightPATH.
sub get_fp {
    debug("=== In get_fp\n");

    my ($albApiUrl, $guid, $id, $name, $desc, $inUse) = @_;
    my $path = "GET/11";
    my %res_tmp; my $res = \%res_tmp;
    
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_fp()", 1);
    }
    my $decoded = decode_json($json);
            
    debug("$json\n");
            
    # Find a flightPATH by its name
    if (defined($decoded->{'dataset'}->{'row'}) &&
       ($decoded->{'dataset'}->{'row'} ne "")) {
        my @fps = @{$decoded->{'dataset'}->{'row'}};
        if (scalar(@fps) > 0) {
            foreach my $fp (@fps) {
                debug("FP:\n" . encode_json($fp) . "\n");
            
                my ($idCmp, $nameCmp, $descCmp, $inUseCmp) = 
                   ('', '', '', '');
                if (defined($id) && ($id ne '')) {
                    $idCmp = $fp->{'fId'};
                } else {
                    $id = '';
                }
                if (defined($name) && ($name ne '')) {
                    $nameCmp = $fp->{'flightPathName'};
                } else {
                    $name = '';
                }
                if (defined($desc) && ($desc ne '')) {
                    $descCmp = $fp->{'flightPathDesc'};
                } else {
                    $desc = '';
                }
                if (defined($inUse) && ($inUse ne '')) {
                    $inUseCmp = $fp->{'flightPathInUse'};
                } else {
                    $inUse = '';
                }

                if (($idCmp eq $id) && ($nameCmp eq $name) &&
                    ($descCmp eq $desc) && ($inUseCmp eq $inUse)) {
                    $res = $fp;
                    last;
                }
            }
        }
    }
    return($res);
}



# Update flightPATH data
sub update_fp {
    debug("=== In update_fp\n");

    my ($albApiUrl, $guid, $fp) = @_;
    my $path = "POST/11?iAction=2&iType=1";

    my $request = encode_json($fp);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a FP in update_fp()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update a FP failed in update_fp(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);

    return($decoded);
}



# Create a flightPATH
sub create_fp {
    debug("=== In create_fp\n");

    my ($albApiUrl, $guid, $fpName, $fpDesc) = @_;
    my %res_tmp; my $res = \%res_tmp;
    my $fp_num = 0;

    # GET flightPATHs
    my $path = "GET/11";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in create_fp()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    # Get number of existing flightPATHs
    if (defined($decoded->{'dataset'}->{'row'}) &&
        ($decoded->{'dataset'}->{'row'} ne "")) {
        my @fps = @{$decoded->{'dataset'}->{'row'}};
        if (scalar(@fps) > 0) {
            foreach my $fp (@fps) {
                $fp_num++;
            }
        }
    }
    debug("FP num = $fp_num\n");

    # First create an "empty" flightPATH, afterwards update it with actual data
    debug("First create an \"empty\" flightPATH\n");
    $path = "POST/11?iAction=1&iType=1";
    my $request = '{}';

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to create a FP in create_fp()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to create a FP failed in create_fp(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");


    # Store the newly created "empty" flightPATH data in $empty_fp
    debug("Get the newly created \"empty\" flightPATH in \$empty_fp\n");
    my $empty_fp;
    if (defined($decoded->{'dataset'}->{'row'}) &&
        ($decoded->{'dataset'}->{'row'} ne "")) {
        my @fps = @{$decoded->{'dataset'}->{'row'}};
        if (scalar(@fps) > 0) {
            foreach my $tmp_fp (@fps) {
                if ($tmp_fp->{'fId'} == $fp_num + 1) {
                    $empty_fp = $tmp_fp;
                    last;
                }
            }
        }
    }


    # Update the flightPATH with actual data
    debug("Update the flightPATH with actual data\n");
    my $fp;
    $fp->{'fId'} = $empty_fp->{'fId'};
    $fp->{'flightPathName'} = $fpName;
    $fp->{'flightPathDesc'} = $fpDesc;
    debug("FP:\n" . encode_json($fp) . "\n");
    $decoded = update_fp($albApiUrl, $guid, $fp);

    return($decoded);
}



sub remove_fp {
    debug("=== In remove_fp\n");

    my ($albApiUrl, $guid, $fpId, $fpName) = @_;
    my $fp;

    # GET flightPATHs
    if (defined($fpId) && ($fpId ne "")) {
        $fp = get_fp($albApiUrl, $guid, $fpId);
    }
    elsif (defined($fpName) && ($fpName ne "")) {
        $fp = get_fp($albApiUrl, $guid, '', $fpName);
    }
    else {
        error("Neither flightPATH id, nor name specified in remove_fp()", 1);
    }

    if (!defined($fp->{'fId'})) {
        error("Requested flightPATH '$fpName' not found in remove_fp()", 1);
    }

    debug("FP: " . encode_json($fp) . "\n");

    # Remove the flightPATH
    my $path = "POST/11?iAction=3&iType=1";
    my $del_fp = {'fId' => $fp->{'fId'}};
    my $request = encode_json($del_fp);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    AE::log debug => "JSON reply (remove_fp): `%s`", $json;
    if (!$json) {
        error("Failed to connect to ALB API to remove a FP in remove_fp()", 1);
    }
    my $decoded = decode_json($json);

    debug("Result:\n". $json ."\n");

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to remove a FP failed in remove_fp(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



# Get id to value mappings of flightPATH conditions, actions, etc
sub get_fp_combo_options {
    debug("=== In get_fp_combo_options\n");

    my ($albApiUrl, $guid) = @_;
    my $path = "GET/12";
    my %res_tmp; my $res = \%res_tmp;

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_fp_combo_options()", 1);
    }
    my $decoded = decode_json($json);

    debug("$json\n");
    return($decoded);
}



# Create a flightPATH condition
sub create_fp_condition {
    debug("=== In create_fp_condition\n");

    my ($albApiUrl, $guid, $fpId, $fpName, $condition, $match, $sense, $check, $value) = @_;
    my $fp;

    if (!defined($condition)) {
        $condition = '';
    }
    if (!defined($match)) {
        $match = '';
    }
    if (!defined($sense)) {
        $sense = '';
    }
    if (!defined($check)) {
        $check = '';
    }

    # GET flightPATHs
    if (defined($fpId) && ($fpId ne "")) {
        $fp = get_fp($albApiUrl, $guid, $fpId);
    }
    elsif (defined($fpName) && ($fpName ne "")) {
        $fp = get_fp($albApiUrl, $guid, '', $fpName);
    }
    else {
        error("Neither flightPATH id, nor name specified in create_fp_condition()", 1);
    }

    if (!defined($fp->{'fId'})) {
        error("Requested flightPATH '$fpName' not found in create_fp_condition()", 1);
    }

    debug("fpId: " . $fp->{'fId'} . "\n");

    # First create an "empty" flightPATH condition, afterwards update it with actual data
    debug("First create an \"empty\" flightPATH condition\n");
    my $path = "POST/11?iAction=4&iType=1";
    my $request = encode_json({'fId' => $fp->{'fId'}});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to create a flightPATH condition in create_fp_condition()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to create a FP failed in create_fp_condition(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");

    # Get index of the flightPATH condition being created
    my $cId;
    if (defined($decoded->{'dataset'}->{'row'}) &&
        ($decoded->{'dataset'}->{'row'} ne "")) {
        my @fps = @{$decoded->{'dataset'}->{'row'}};
        if (scalar(@fps) > 0) {
            foreach my $tmp_fp (@fps) {
                if ($tmp_fp->{'fId'} == $fp->{'fId'}) {
                    # $cId = 'conditions' array length minus 1
                    $cId = scalar(@{$tmp_fp->{'conditions'}->{'conditionId'}});
                    $cId--;
                    last;
                }
            }
        }
    }
    if (!defined($cId) || ($cId < 0)) {
        error("Failed to get new condition ID in create_fp_condition()", 1);
    }
    debug("cId: $cId\n");

    # Get id to value mappings of flightPATH options
    my ($combos, $conditionId, $matchId, $senseId, $checkId);
    if (($condition ne '') || ($match ne '') || ($sense ne '') || ($check ne '')) {
        $combos = get_fp_combo_options($albApiUrl, $guid);
    }
    if ($condition ne '') {
        $conditionId = get_combo_option_id($combos, 'conditionCombo', $condition, 1);
    }
    if ($match ne '') {
        $matchId = get_combo_option_id($combos, 'ConValueCombo', $match, 1);
    }
    if ($sense ne '') {
        $senseId = get_combo_option_id($combos, 'SenseCombo', $sense);
    }
    if ($check ne '') {
        $checkId = get_combo_option_id($combos, 'CheckCombo', $check);
    }

    # Update the flightPATH condition with actual data

    debug("Update the flightPATH condition with actual data\n");

    my $cond;
    $cond->{'fId'} = $fp->{'fId'};
    $cond->{'cId'} = $cId;
    $cond->{'condition'} = $conditionId;
    $cond->{'match'} = $matchId;
    $cond->{'sense'} = $senseId;
    $cond->{'check'} = $checkId;
    $cond->{'condValue'} = $value;

    $path = "POST/11?iAction=5&iType=1";
    $request = encode_json($cond);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a flightPATH condition in update_fp_condition()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update a FP failed in update_fp_condition(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);
    return($decoded);
}



# Update flightPATH condition for a flightPATH
sub update_fp_condition {
    debug("=== In update_fp_condition\n");

    my ($albApiUrl, $guid, $fpId, $fpName,
        $conditionOld, $matchOld, $senseOld, $checkOld, $valueOld,
        $condition, $match, $sense, $check, $value,
       ) = @_;
    my $fp;

    if (!defined($conditionOld)) {
        $conditionOld = '';
    }
    if (!defined($matchOld)) {
        $matchOld = '';
    }
    if (!defined($senseOld)) {
        $senseOld = '';
    }
    if (!defined($checkOld)) {
        $checkOld = '';
    }
    if (!defined($condition)) {
        $condition = '';
    }
    if (!defined($match)) {
        $match = '';
    }
    if (!defined($sense)) {
        $sense = '';
    }
    if (!defined($check)) {
        $check = '';
    }

    # GET flightPATHs
    if (defined($fpId) && ($fpId ne "")) {
        $fp = get_fp($albApiUrl, $guid, $fpId);
    }
    elsif (defined($fpName) && ($fpName ne "")) {
        $fp = get_fp($albApiUrl, $guid, '', $fpName);
    }
    else {
        error("Neither flightPATH id, nor name specified in update_fp_condition()", 1);
    }
    
    if (!defined($fp->{'fId'})) {
        error("Requested flightPATH '$fpName' not found in update_fp_condition()", 1);
    }
    debug("fpId: " . $fp->{'fId'} . "\n");

    # Get index of the flightPATH condition being updated
    my $cId = -1;
    foreach my $cond (@{$fp->{'conditions'}->{'conditionId'}}) {
        if ( ($cond->{'condition'} eq $conditionOld) &&
             ($cond->{'match'} eq $matchOld) &&
             ($cond->{'sense'} eq $senseOld) &&
             ($cond->{'check'} eq $checkOld) && 
             ($cond->{'condValue'} eq $valueOld) ) {
            $cId = $cond->{'cId'};
            last;
        }
    }
    if (!defined($cId) || ($cId < 0)) {
        error("Requested flightPATH condition not found in update_fp_condition()", 1);
    }
    debug("cId: $cId\n");

    # Get id to value mappings of flightPATH options
    my ($combos, $conditionId, $matchId, $senseId, $checkId);
    $combos = get_fp_combo_options($albApiUrl, $guid);
    if ($condition ne '') {
        $conditionId = get_combo_option_id($combos, 'conditionCombo', $condition, 1);
    }
    if ($match ne '') {
        $matchId = get_combo_option_id($combos, 'ConValueCombo', $match, 1);
    }
    if ($sense ne '') {
        $senseId = get_combo_option_id($combos, 'SenseCombo', $sense);
    }
    if ($check ne '') {
        $checkId = get_combo_option_id($combos, 'CheckCombo', $check);
    }

    # Update the flightPATH condition with new data
    debug("Update the flightPATH condition with actual data\n");
    my $cond;
    $cond->{'fId'} = $fp->{'fId'};
    $cond->{'cId'} = $cId;
    $cond->{'condition'} = $conditionId;
    $cond->{'match'} = $matchId;
    $cond->{'sense'} = $senseId;
    $cond->{'check'} = $checkId;
    $cond->{'condValue'} = $value;

    my $path = "POST/11?iAction=5&iType=1";
    my $request = encode_json($cond);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a flightPATH condition in update_fp_condition()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update a FP failed in update_fp_condition(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);

    return($decoded);
}



# Remove a flightPATH condition
sub remove_fp_condition {
    debug("=== In remove_fp_condition\n");

    my ($albApiUrl, $guid, $fpId, $fpName, $condition, $match, $sense, $check, $value) = @_;
    my $fp;

    # GET flightPATHs
    if (defined($fpId) && ($fpId ne "")) {
        $fp = get_fp($albApiUrl, $guid, $fpId);
    }
    elsif (defined($fpName) && ($fpName ne "")) {
        $fp = get_fp($albApiUrl, $guid, '', $fpName);
    }
    else {
        error("Neither flightPATH id, nor name specified in remove_fp_condition()", 1);
    }

    if (!defined($fp->{'fId'})) {
        error("Requested flightPATH '$fpName' not found in remove_fp_condition()", 1);
    }

    debug("fpId: " . $fp->{'fId'} . "\n");

    # Get index of the flightPATH condition being removed
    my $cId = -1;
    foreach my $cond (@{$fp->{'conditions'}->{'conditionId'}}) {
        if ( ($cond->{'condition'} eq $condition) &&
             ($cond->{'match'} eq $match) &&
             ($cond->{'sense'} eq $sense) &&
             ($cond->{'check'} eq $check) && 
             ($cond->{'condValue'} eq $value) ) {
            $cId = $cond->{'cId'};
            last;
        }
    }
    if (!defined($cId) || ($cId < 0)) {
        error("Requested flightPATH condition not found in remove_fp_condition()", 1);
    }
    debug("cId: $cId\n");

    my $path = "POST/11?iAction=6&iType=1";
    my $request = encode_json({'fId' => $fp->{'fId'}, 'cId' => $cId});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a flightPATH condition in remove_fp_condition()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update a FP failed in remove_fp_condition(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);

    return($decoded);
}



# Create a flightPATH evaluation
sub create_fp_evaluation {
    debug("=== In create_fp_evaluation\n");

    my ($albApiUrl, $guid, $fpId, $fpName, $variable, $source, $detail, $value) = @_;
    my $fp;

    if (!defined($variable)) {
        $variable = '';
    }
    if (!defined($source)) {
        $source = '';
    }
    if (!defined($detail)) {
        $detail = '';
    }
    if (!defined($value)) {
        $value = '';
    }

    # GET flightPATHs
    if (defined($fpId) && ($fpId ne "")) {
        $fp = get_fp($albApiUrl, $guid, $fpId);
    }
    elsif (defined($fpName) && ($fpName ne "")) {
        $fp = get_fp($albApiUrl, $guid, '', $fpName);
    }
    else {
        error("Neither flightPATH id, nor name specified in create_fp_evaluation()", 1);
    }
    if (!defined($fp->{'fId'})) {
        error("Requested flightPATH '$fpName' not found in create_fp_evaluation()", 1);
    }
    debug("fpId: " . $fp->{'fId'} . "\n");

    # First create an "empty" flightPATH evaluation, afterwards update it with actual data
    debug("First create an \"empty\" flightPATH evaluation\n");
    my $path = "POST/11?iAction=7&iType=1";
    my $request = encode_json({'fId' => $fp->{'fId'}});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to create a flightPATH evaluation in create_fp_evaluation()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to create a FP failed in create_fp_evaluation(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");

    # Get index of the flightPATH evaluation being created
    my $vId;
    if (defined($decoded->{'dataset'}->{'row'}) &&
        ($decoded->{'dataset'}->{'row'} ne "")) {
        my @fps = @{$decoded->{'dataset'}->{'row'}};
        if (scalar(@fps) > 0) {
            foreach my $tmp_fp (@fps) {
                if ($tmp_fp->{'fId'} == $fp->{'fId'}) {
                    # $vId = 'values' array length minus 1
                    $vId = scalar(@{$tmp_fp->{'values'}->{'valuesId'}});
                    $vId--;
                    last;
                }
            }
        }
    }
    if (!defined($vId) || ($vId < 0)) {
        error("Requested flightPATH evaluation not found in create_fp_evaluation()", 1);
    }
    debug("vId: $vId\n");

    # Get id to value mappings of flightPATH options
    my ($combos, $sourceId, $detailId, $valueId);
    if (($source ne '') || ($detail ne '') || ($value ne '')) {
        $combos = get_fp_combo_options($albApiUrl, $guid);
    }
    if ($source ne '') {
        $sourceId = get_combo_option_id($combos, 'SourceCombo', $source);
    }
    if ($detail ne '') {
        $detailId = get_combo_option_id($combos, 'ConValueCombo', $detail, 1);
    }

    # Update the flightPATH evaluation with actual data

    debug("Update the flightPATH evaluation with actual data\n");

    my $eval;
    $eval->{'fId'} = $fp->{'fId'};
    $eval->{'vId'} = $vId;
    $eval->{'variable'} = $variable;
    $eval->{'source'} = $sourceId;
    $eval->{'detail'} = $detailId;
    $eval->{'valValue'} = $value;

    $path = "POST/11?iAction=8&iType=1";
    $request = encode_json($eval);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a flightPATH evaluation in update_fp_evaluation()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update a FP failed in update_fp_evaluation(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);
    return($decoded);
}



# Update flightPATH evaluation for a flightPATH ID $fId and evaluation ID $vId
sub update_fp_evaluation {
    debug("=== In update_fp_evaluation\n");

    my ($albApiUrl, $guid, $fpId, $fpName,
        $variableOld, $sourceOld, $detailOld, $valueOld,
        $variable, $source, $detail, $value) = @_;
    my $fp;

    if (!defined($variableOld)) {
        $variableOld = '';
    }
    if (!defined($sourceOld)) {
        $sourceOld = '';
    }
    if (!defined($detailOld)) {
        $detailOld = '';
    }
    if (!defined($valueOld)) {
        $valueOld = '';
    }
    if (!defined($variable)) {
        $variable = '';
    }
    if (!defined($source)) {
        $source = '';
    }
    if (!defined($detail)) {
        $detail = '';
    }
    if (!defined($value)) {
        $value = '';
    }

    # GET flightPATHs
    if (defined($fpId) && ($fpId ne "")) {
        $fp = get_fp($albApiUrl, $guid, $fpId);
    }
    elsif (defined($fpName) && ($fpName ne "")) {
        $fp = get_fp($albApiUrl, $guid, '', $fpName);
    }
    else {
        error("Neither flightPATH id, nor name specified in update_fp_evaluation()", 1);
    }
    if (!defined($fp->{'fId'})) {
        error("Requested flightPATH '$fpName' not found in update_fp_evaluation()", 1);
    }
    debug("fpId: " . $fp->{'fId'} . "\n");

    # Get index of the flightPATH evaluation being updated
    my $vId = -1;
    foreach my $eval (@{$fp->{'values'}->{'valuesId'}}) {
        if ( ($eval->{'variable'} eq $variableOld) &&
             ($eval->{'source'} eq $sourceOld) &&
             ($eval->{'detail'} eq $detailOld) && 
             ($eval->{'valValue'} eq $valueOld) ) {
            $vId = $eval->{'vId'};
            last;
        }
    }
    if (!defined($vId) || ($vId < 0)) {
        error("Requested flightPATH evaluation not found in update_fp_evaluation()", 1);
    }
    debug("vId: $vId\n");

    # Get id to value mappings of flightPATH options
    my ($combos, $sourceId, $detailId, $valueId);
    if (($source ne '') || ($detail ne '') || ($value ne '')) {
        $combos = get_fp_combo_options($albApiUrl, $guid);
    }
    if ($source ne '') {
        $sourceId = get_combo_option_id($combos, 'SourceCombo', $source);
    }
    if ($detail ne '') {
        $detailId = get_combo_option_id($combos, 'ConValueCombo', $detail, 1);
    }

    # Update the flightPATH evaluation with actual data
    debug("Update the flightPATH evaluation with actual data\n");
    my $eval;
    $eval->{'fId'} = $fp->{'fId'};
    $eval->{'vId'} = $vId;
    $eval->{'variable'} = $variable;
    $eval->{'source'} = $sourceId;
    $eval->{'detail'} = $detailId;
    $eval->{'valValue'} = $value;

    my $path = "POST/11?iAction=8&iType=1";
    my $request = encode_json($eval);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a flightPATH evaluation in update_fp_evaluation()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update a FP failed in update_fp_evaluation(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);

    return($decoded);
}



# Remove a flightPATH evaluation
sub remove_fp_evaluation {
    debug("=== In remove_fp_evaluation\n");

    my ($albApiUrl, $guid, $fpId, $fpName, $variable, $source, $detail, $value) = @_;
    my $fp;

    # GET flightPATHs
    if (defined($fpId) && ($fpId ne "")) {
        $fp = get_fp($albApiUrl, $guid, $fpId);
    }
    elsif (defined($fpName) && ($fpName ne "")) {
        $fp = get_fp($albApiUrl, $guid, '', $fpName);
    }
    else {
        error("Neither flightPATH id, nor name specified in remove_fp_evaluation()", 1);
    }

    if (!defined($fp->{'fId'})) {
        error("Requested flightPATH '$fpName' not found in remove_fp_evaluation()", 1);
    }

    debug("fpId: " . $fp->{'fId'} . "\n");

    # Get index of the flightPATH evaluation being removed
    my $vId = -1;
    foreach my $eval (@{$fp->{'values'}->{'valuesId'}}) {
        if ( ($eval->{'variable'} eq $variable) &&
             ($eval->{'source'} eq $source) &&
             ($eval->{'detail'} eq $detail) && 
             ($eval->{'valValue'} eq $value) ) {
            $vId = $eval->{'vId'};
            last;
        }
    }
    if (!defined($vId) || ($vId < 0)) {
        error("Requested flightPATH evaluation not found in remove_fp_evaluation()", 1);
    }
    debug("vId: $vId\n");

    my $path = "POST/11?iAction=9&iType=1";
    my $request = encode_json({'fId' => $fp->{'fId'}, 'cId' => $vId});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a flightPATH evaluation in remove_fp_evaluation()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update a FP failed in remove_fp_evaluation(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);

    return($decoded);
}



# Create a flightPATH action
sub create_fp_action {
    debug("=== In create_fp_action\n");

    my ($albApiUrl, $guid, $fpId, $fpName, $action, $target, $data) = @_;
    my $fp;

    if (!defined($action)) {
        $action = '';
    }
    if (!defined($target)) {
        $target = '';
    }
    if (!defined($data)) {
        $data = '';
    }

    # GET flightPATHs
    if (defined($fpId) && ($fpId ne "")) {
        $fp = get_fp($albApiUrl, $guid, $fpId);
    }
    elsif (defined($fpName) && ($fpName ne "")) {
        $fp = get_fp($albApiUrl, $guid, '', $fpName);
    }
    else {
        error("Neither flightPATH id, nor name specified in create_fp_action()", 1);
    }

    if (!defined($fp->{'fId'})) {
        error("Requested flightPATH '$fpName' not found in create_fp_action()", 1);
    }

    debug("fpId: " . $fp->{'fId'} . "\n");

    # First create an "empty" flightPATH action, afterwards update it with actual data
    debug("First create an \"empty\" flightPATH action\n");
    my $path = "POST/11?iAction=10&iType=1";
    my $request = encode_json({'fId' => $fp->{'fId'}});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to create a flightPATH action in create_fp_action()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to create a FP failed in create_fp_action(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");

    # Get index of the flightPATH action being created
    my $aId;
    if (defined($decoded->{'dataset'}->{'row'}) &&
        ($decoded->{'dataset'}->{'row'} ne "")) {
        my @fps = @{$decoded->{'dataset'}->{'row'}};
        if (scalar(@fps) > 0) {
            foreach my $tmp_fp (@fps) {
                if ($tmp_fp->{'fId'} == $fp->{'fId'}) {
                    # $aId = 'actions' array length minus 1
                    $aId = scalar(@{$tmp_fp->{'actions'}->{'actionId'}});
                    $aId--;
                    last;
                }
            }
        }
    }
    if (!defined($aId) || ($aId < 0)) {
        error("Requested flightPATH action not found ID in create_fp_action()", 1);
    }
    debug("aId: $aId\n");

    # Get id to data mappings of flightPATH options
    my ($combos, $actionId, $targetId, $dataId);
    if (($action ne '') || ($target ne '') || ($data ne '')) {
        $combos = get_fp_combo_options($albApiUrl, $guid);
    }
    if ($action ne '') {
        $actionId = get_combo_option_id($combos, 'ActionCombo', $action);
    }

    # Update the flightPATH action with actual data

    debug("Update the flightPATH action with actual data\n");

    my $act;
    $act->{'fId'} = $fp->{'fId'};
    $act->{'aId'} = $aId;
    $act->{'action'} = $actionId;
    $act->{'target'} = $target;
    $act->{'data'} = $data;

    $path = "POST/11?iAction=11&iType=1";
    $request = encode_json($act);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a flightPATH action in update_fp_action()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update a FP failed in update_fp_action(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);
    return($decoded);
}



# Update flightPATH action for a flightPATH ID $fId and action ID $aId
sub update_fp_action {
    debug("=== In update_fp_action\n");

    my ($albApiUrl, $guid, $fpId, $fpName, 
        $actionOld, $targetOld, $dataOld,
        $action, $target, $data) = @_;
    my $fp;

    if (!defined($action)) {
        $action = '';
    }
    if (!defined($target)) {
        $target = '';
    }
    if (!defined($data)) {
        $data = '';
    }
    if (!defined($actionOld)) {
        $actionOld = '';
    }
    if (!defined($targetOld)) {
        $targetOld = '';
    }
    if (!defined($dataOld)) {
        $dataOld = '';
    }

    # GET flightPATHs
    if (defined($fpId) && ($fpId ne "")) {
        $fp = get_fp($albApiUrl, $guid, $fpId);
    }
    elsif (defined($fpName) && ($fpName ne "")) {
        $fp = get_fp($albApiUrl, $guid, '', $fpName);
    }
    else {
        error("Neither flightPATH id, nor name specified in update_fp_action()", 1);
    }
    if (!defined($fp->{'fId'})) {
        error("Requested flightPATH '$fpName' not found in update_fp_action()", 1);
    }
    debug("fpId: " . $fp->{'fId'} . "\n");

    # Get index of the flightPATH action being updated
    my $aId = -1;
    foreach my $act (@{$fp->{'actions'}->{'actionId'}}) {
        if ( ($act->{'action'} eq $actionOld) &&
             ($act->{'target'} eq $targetOld) && 
             ($act->{'data'} eq $dataOld) ) {
            $aId = $act->{'aId'};
            last;
        }
    }
    if (!defined($aId) || ($aId < 0)) {
        error("Requested flightPATH action not found in update_fp_action()", 1);
    }
    debug("aId: $aId\n");

    # Get id to data mappings of flightPATH options
    my ($combos, $actionId, $targetId, $dataId);
    if (($action ne '') || ($target ne '') || ($data ne '')) {
        $combos = get_fp_combo_options($albApiUrl, $guid);
    }
    if ($action ne '') {
        $actionId = get_combo_option_id($combos, 'ActionCombo', $action);
    }

    # Update the flightPATH action with actual data
    debug("Update the flightPATH action with actual data\n");
    my $act;
    $act->{'fId'} = $fp->{'fId'};
    $act->{'aId'} = $aId;
    $act->{'action'} = $actionId;
    $act->{'target'} = $target;
    $act->{'data'} = $data;

    my $path = "POST/11?iAction=11&iType=1";
    my $request = encode_json($act);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a flightPATH action in update_fp_action()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update a FP failed in update_fp_action(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);

    return($decoded);
}



# Remove a flightPATH action
sub remove_fp_action {
    debug("=== In remove_fp_action\n");

    my ($albApiUrl, $guid, $fpId, $fpName, $action, $target, $data) = @_;
    my $fp;

    # GET flightPATHs
    if (defined($fpId) && ($fpId ne "")) {
        $fp = get_fp($albApiUrl, $guid, $fpId);
    }
    elsif (defined($fpName) && ($fpName ne "")) {
        $fp = get_fp($albApiUrl, $guid, '', $fpName);
    }
    else {
        error("Neither flightPATH id, nor name specified in remove_fp_action()", 1);
    }

    if (!defined($fp->{'fId'})) {
        error("Requested flightPATH '$fpName' not found in remove_fp_action()", 1);
    }

    debug("fpId: " . $fp->{'fId'} . "\n");

    # Get index of the flightPATH action being removed
    my $aId = -1;
    foreach my $act (@{$fp->{'actions'}->{'actionId'}}) {
        if ( ($act->{'action'} eq $action) &&
             ($act->{'target'} eq $target) && 
             ($act->{'data'} eq $data) ) {
            $aId = $act->{'aId'};
            last;
        }
    }
    if (!defined($aId) || ($aId < 0)) {
        error("Requested flightPATH action not found in remove_fp_action()", 1);
    }
    debug("aId: $aId\n");

    my $path = "POST/11?iAction=12&iType=1";
    my $request = encode_json({'fId' => $fp->{'fId'}, 'aId' => $aId});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a flightPATH action in remove_fp_action()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update a FP failed in remove_fp_action(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);

    return($decoded);
}



# Returns ID of a widget specified by the widget's name
sub get_widget_id {
    debug("=== In get_widget_id\n");

    my ($albApiUrl, $guid, $widgetName) = @_;
    my $res;

    # GET widgets
    my $path = "GET/51";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_widget_id()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    if (defined($decoded->{'ConfiguredWidgetsComboStore'}) && 
        defined($decoded->{'ConfiguredWidgetsComboStore'}->{'options'}) &&
        defined($decoded->{'ConfiguredWidgetsComboStore'}->{'options'}->{'option'})) {
        foreach my $widget (@{$decoded->{'ConfiguredWidgetsComboStore'}->{'options'}->{'option'}}) {
            if ($widget->{'value'} eq $widgetName) {
                $res = $widget->{'id'};
                last;
            }
        }
    }

    return($res);
}



sub create_event_widget {
    debug("=== In create_event_widget\n");

    my ($albApiUrl, $guid, $widgetName, $widgetFilter) = @_;

    # GET widgets
    my $path = "GET/51";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in create_event_widget()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    # Create widget
    $path = "POST/48?iAction=1&iType=1";
    my $request = encode_json({'Section_Name' => 'Event', 'DashboardEvent_Name' => $widgetName, 
                               'DashboardEvent_Filter' => $widgetFilter});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to create a widget in create_event_widget()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to create a widget failed in create_event_widget(): '" . $decoded->{'StatusText'} . "'", 1);
    }
            
    debug("Result:\n". $json);
    
    return($decoded);
}


#Section_Name: "IPService"
#IPService_Name: "Traffic1"
#IPService_Type: "VS"
#IPService_Columns: "Average Bytes in,Maximum Bytes in,Average Bytes out,Maximum Bytes out"
#IPService_Period: "hour"
#IPService_VSRS: "192.168.3.245:80; 192.168.3.245:84"
sub create_traffic_widget {
    debug("=== In create_traffic_widget\n");

    my ($albApiUrl, $guid, $widgetName, $widgetType, $widgetColumns, $widgetPeriod, $widgetVSRS) = @_;

    # GET widgets
    my $path = "GET/51";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in create_traffic_widget()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    # Create widget
    $path = "POST/48?iAction=2&iType=1";
    my $request = encode_json({'Section_Name' => 'IPService', 'IPService_Name' => $widgetName, 
                               'IPService_Type' => $widgetType, 'IPService_Columns' => $widgetColumns, 
                               'IPService_Period' => $widgetPeriod, 'IPService_VSRS' => $widgetVSRS});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to create a widget in create_traffic_widget()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to create a widget failed in create_traffic_widget(): '" . $decoded->{'StatusText'} . "'", 1);
    }
            
    debug("Result:\n". $json);
    
    return($decoded);
}



sub create_status_widget {
    debug("=== In create_status_widget\n");

    my ($albApiUrl, $guid, $widgetName, $widgetFilter, $widgetLayout) = @_;

    if (!defined($widgetLayout) || ($widgetLayout eq '')) {
        $widgetLayout = "33,30,122,150,45,67,63,30,150,94,51,100,57,100,46,100";
    }

    # GET widgets
    my $path = "GET/51";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in create_status_widget()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    # Create widget
    $path = "POST/48?iAction=3&iType=1";
    my $request = encode_json({'Section_Name' => 'IPStatus', 'IPStatus_Name' => $widgetName, 
                               'IPStatus_IP' => $widgetFilter, 'IPStatus_Layout' => $widgetLayout});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to create a widget in create_status_widget()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to create a widget failed in create_status_widget(): '" . $decoded->{'StatusText'} . "'", 1);
    }
            
    debug("Result:\n". $json);
    
    return($decoded);
}



# Create a system graph widget with CPU, memory, disk usage graphs
# System_Type: "true,true,false"
sub create_system_widget {
    debug("=== In create_system_widget\n");

    my ($albApiUrl, $guid, $widgetName, $widgetType) = @_;

    # GET widgets
    my $path = "GET/51";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in create_system_widget()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    # Create widget
    $path = "POST/48?iAction=4&iType=1";
    my $request = encode_json({'Section_Name' => 'System', 'System_Name' => $widgetName, 
                               'System_Type' => $widgetType});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to create a widget in create_system_widget()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to create a widget failed in create_system_widget(): '" . $decoded->{'StatusText'} . "'", 1);
    }
            
    debug("Result:\n". $json);
    
    return($decoded);
}



sub create_interface_widget {
    debug("=== In create_interface_widget\n");

    my ($albApiUrl, $guid, $widgetName) = @_;

    # GET widgets
    my $path = "GET/51";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in create_interface_widget()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    # Create widget
    $path = "POST/48?iAction=4&iType=2";
    my $request = encode_json({'Section_Name' => 'Interface', 'Interface_Name' => $widgetName});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to create a widget in create_interface_widget()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to create a widget failed in create_interface_widget(): '" . $decoded->{'StatusText'} . "'", 1);
    }
            
    debug("Result:\n". $json);
    
    return($decoded);
}



sub remove_widget {
    debug("=== In remove_widget\n");

    my ($albApiUrl, $guid, $widgetSection, $widgetName) = @_;

    # GET widgets
    my $path = "GET/51";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in remove_widget()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    # Create widget
    $path = "POST/48?iAction=10&iType=1";
    my $request = encode_json({'Remove_Section_Name' => $widgetSection .'-'. $widgetName});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to create a widget in remove_widget()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to create a widget failed in remove_widget(): '" . $decoded->{'StatusText'} . "'", 1);
    }
            
    debug("Result:\n". $json);
    
    return($decoded);
}



sub get_widget_data_vs {
    $DEBUG = 1;
    debug("=== In get_widget_data_vs\n");

    my ($albApiUrl, $guid, $widgetSection, $widgetName, $ip, $port, $column) = @_;
    my $res;

    my $widgetNameUrl = $widgetName;
    $widgetNameUrl =~ s/ /%20/g;

    # Get widget data
    my $path = "GET/48?EditWidget=true&WidgetName=$widgetSection-$widgetNameUrl";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_widget_data_vs()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    # Find requested data
    if (defined($decoded->{$widgetName}) && defined($decoded->{$widgetName}->{'dataset'}) && 
        defined($decoded->{$widgetName}->{'dataset'}->{'VSRS'}) && 
        ($decoded->{$widgetName}->{'dataset'}->{'VSRS'} ne '')) {
        foreach my $vsrs (@{$decoded->{$widgetName}->{'dataset'}->{'VSRS'}}) {
            if (defined($vsrs->{'ipPort'}) && ($vsrs->{'ipPort'} eq "$ip:$port") &&
                defined($vsrs->{'column'}) && ($vsrs->{'column'} ne '')) {
                foreach my $col (@{$vsrs->{'column'}}) {
                    if ($col->{'name'} eq $column) {
                        if (defined($col->{'data'})) {
                            $res = $col->{'data'};
                        }
                        last;
                    }
                }
            }
        }
    }
    $DEBUG = 0;
    return($res);
}



sub get_widget_data_rs {
    debug("=== In get_widget_data_rs\n");

    my ($albApiUrl, $guid, $widgetSection, $widgetName, $ip, $port, $rs_addr, $rs_port, $column) = @_;
    my $res;

    my $widgetNameUrl = $widgetName;
    $widgetNameUrl =~ s/ /%20/g;

    # Get widget data
    my $path = "GET/48?EditWidget=true&WidgetName=$widgetSection-$widgetNameUrl";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_widget_data_rs()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    # Find requested data
    if (defined($decoded->{$widgetName}) && defined($decoded->{$widgetName}->{'dataset'}) && 
        defined($decoded->{$widgetName}->{'dataset'}->{'VSRS'}) && 
        ($decoded->{$widgetName}->{'dataset'}->{'VSRS'}) ne '') {
        foreach my $vsrs (@{$decoded->{$widgetName}->{'dataset'}->{'VSRS'}}) {
            if (defined($vsrs->{'ipPort'}) && ($vsrs->{'ipPort'} eq "$ip:$port") &&
                defined($vsrs->{'RS'})) {
                foreach my $rs (@{$vsrs->{'RS'}}) {
                    if (defined($rs->{'ipPort'}) && ($rs->{'ipPort'} eq "$rs_addr:$rs_port") &&
                        defined($rs->{'column'}) && ($rs->{'column'} ne '')) {
                        foreach my $col (@{$rs->{'column'}}) {
                            if ($col->{'name'} eq $column) {
                                if (defined($col->{'data'})) {
                                    $res = $col->{'data'};
                                }
                                last;
                            }
                        }
                    }
                }
            }
        }
    }

    return($res);
}



sub get_widget_data_system {
    debug("=== In get_widget_data_system\n");

    my ($albApiUrl, $guid, $widgetSection, $widgetName, $column) = @_;
    my $res;

    my $widgetNameUrl = $widgetName;
    $widgetNameUrl =~ s/ /%20/g;

    # Get widget data
    my $path = "GET/48?EditWidget=true&WidgetName=$widgetSection-$widgetNameUrl";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_widget_data_system()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    # Find requested data
    if (defined($decoded->{$widgetName}) && defined($decoded->{$widgetName}->{'systemData'}) && 
        ($decoded->{$widgetName}->{'systemData'} ne '')) {
        foreach my $col (@{$decoded->{$widgetName}->{'systemData'}}) {
            if (defined($col->{'name'}) && ($col->{'name'} eq $column)) {
                if (defined($col->{'data'})) {
                    $res = $col->{'data'};
                }
                last;
            }
        }
    }

    return($res);
}
        
    
    
# Get id to value mappings of Authentication client and server methods, forms, login formats, etc
sub get_authentication_combo_options {
    debug("=== In get_authentication_combo_options\n");

    my ($albApiUrl, $guid) = @_;
    my $path = "GET/40";
    my %res_tmp; my $res = \%res_tmp;

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_authentication_combo_options()", 1);
    }
    my $decoded = decode_json($json);

    debug("$json\n");
    return($decoded);
}



sub get_authentication_server_id {
    debug("=== In get_authentication_server_id\n");

    my ($albApiUrl, $guid, $combos, $name) = @_;
    my $res = '';

    if (defined($combos->{'PreAuthServerGrid'}) && defined($combos->{'PreAuthServerGrid'}->{'dataset'}) &&
        defined($combos->{'PreAuthServerGrid'}->{'dataset'}->{'row'}) && 
        ($combos->{'PreAuthServerGrid'}->{'dataset'}->{'row'} ne '')) {
        foreach my $server (@{$combos->{'PreAuthServerGrid'}->{'dataset'}->{'row'}}) {
            if ($server->{'Name'} eq $name) {
                $res = $server->{'id'};
                last;
            }
        }
    }

    debug("Authentication server id: '$res'\n");

    return($res);
}



sub create_authentication_server {
    debug("=== In creat_authentication_server\n");

    my ($albApiUrl, $guid, $name, $description, $authMethod, $domain, $address, $port, 
        $searchCondition, $searchBase, $searchUser, $loginFormat, $passphrase, $deadTime) = @_;
    my $res;

    # Get authenticationd data
    my $auth_combos = get_authentication_combo_options($albApiUrl, $guid);

    # GET authentication server ID
    my $id = get_authentication_server_id($albApiUrl, $guid, $auth_combos, $name);
    if (defined($id) && ($id ne '')) {
        error("Authentication server '$name' already exists in create_authentication_server()", 1);
    }

    # GET authentication method and login format IDs
    my $auth_method_id = get_combo_option_id($auth_combos, 'AuthMethodCombo', $authMethod);
    my $login_format_id = get_combo_option_id($auth_combos, 'LoginFormatListString', $loginFormat);

    # Create authentication server
    my $path = "POST/38?iAction=1&iType=1";
    my $request = encode_json({'Name' => $name, 'Description' => $description, 'AuthMethod' => $auth_method_id, 
        'Domain' => $domain, 'Address' => $address, 'Port' => $port, 
        'SearchCondition' => $searchCondition, 'Searchcondition' => $searchCondition, 'SearchBase' => $searchBase, 
        'SearchUser' => $searchUser, 'LoginFormat' => $login_format_id, 'Passphrase' => $passphrase, 
        'DeadTime' => $deadTime});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in create_authentication_server()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to create a server faild in create_authentication_server(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);

    return($decoded);
}



sub remove_authentication_server {
    debug("=== In creat_authentication_server\n");

    my ($albApiUrl, $guid, $name) = @_;
    my $res;

    # Get authenticationd data
    my $auth_combos = get_authentication_combo_options($albApiUrl, $guid);

    # GET authentication server ID
    my $id = get_authentication_server_id($albApiUrl, $guid, $auth_combos, $name);
    if (!defined($id) || ($id eq '')) {
        error("Authentication server '$name' does not exist in remove_authentication_server()", 1);
    }

    # Remove authentication server
    my $path = "POST/38?iAction=1&iType=3";
    my $request = encode_json({'id' => $id});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in remove_authentication_server()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to remove a server failed in remove_authentication_server(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);

    return($decoded);
}



sub get_authentication_rule_id {
    debug("=== In get_authentication_rule_id\n");

    my ($albApiUrl, $guid, $combos, $name) = @_;
    my $res = '';

    if (defined($combos->{'PreAuthRuleGrid'}) && defined($combos->{'PreAuthRuleGrid'}->{'dataset'}) &&
        defined($combos->{'PreAuthRuleGrid'}->{'dataset'}->{'row'}) &&
        ($combos->{'PreAuthRuleGrid'}->{'dataset'}->{'row'} ne '')) {
        foreach my $rule (@{$combos->{'PreAuthRuleGrid'}->{'dataset'}->{'row'}}) {
            if ($rule->{'Name'} eq $name) {
                $res = $rule->{'id'};
                last;
            }
        }
    }
        
    debug("Authentication rule id: '$res'\n");
        
    return($res);
}



sub create_authentication_rule {
    debug("=== In creat_authentication_rule\n");

    my ($albApiUrl, $guid, $name, $description, $rootDomain, $authServerName, 
        $clientAuthMethod, $serverAuthMethod, $authFormName, $message, $timeout) = @_;
    my $res;

    # Get authenticationd data
    my $auth_combos = get_authentication_combo_options($albApiUrl, $guid);

    # GET authentication rule ID
    my $id = get_authentication_rule_id($albApiUrl, $guid, $auth_combos, $name);
    if (defined($id) && ($id ne '')) {
        error("Authentication rule '$name' already exists in create_authentication_rule()", 1);
    }

    # GET authentication server ID
    my $server_id = get_authentication_server_id($albApiUrl, $guid, $auth_combos, $authServerName);
    if (!defined($server_id) && ($server_id ne '')) {
        error("Authentication server '$authServerName' not found in create_authentication_rule()", 1);
    }

    # GET authentication form ID
    my $form_id;
    if (defined($authFormName) && ($authFormName ne '')) {
        $form_id = get_combo_option_id($auth_combos, 'AuthFormsCombo', $authFormName);
    }

    # GET client and server authentication method IDs
    my $client_auth_method_id = get_combo_option_id($auth_combos, 'ClientAuthMethodsCombo', $clientAuthMethod);
    my $server_auth_method_id = get_combo_option_id($auth_combos, 'ServerAuthMethodsCombo', $serverAuthMethod);

    # Create authentication rule
    my $path = "POST/38?iAction=2&iType=1";
    my $request = encode_json({'Name' => $name, 'Description' => $description, 
        'RootDomain' => $rootDomain, 'AuthServer' => $server_id, 
        'ClientAuthMethod' => $client_auth_method_id, 'ServerAuthMethod' => $server_auth_method_id,
        'AuthForm' => $form_id, 'Message' => $message, 'Timeout' => $timeout});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in create_authentication_rule()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to create a rule faild in create_authentication_rule(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);

    return($decoded);
}



sub remove_authentication_rule {
    debug("=== In creat_authentication_rule\n");

    my ($albApiUrl, $guid, $name) = @_;
    my $res;

    # Get authenticationd data
    my $auth_combos = get_authentication_combo_options($albApiUrl, $guid);

    # GET authentication rule ID
    my $id = get_authentication_rule_id($albApiUrl, $guid, $auth_combos, $name);
    if (!defined($id) || ($id eq '')) {
        error("Authentication rule '$name' does not exist in remove_authentication_rule()", 1);
    }

    # Remove authentication rule
    my $path = "POST/38?iAction=2&iType=3";
    my $request = encode_json({'id' => $id});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in remove_authentication_rule()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to remove a rule failed in remove_authentication_rule(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);

    return($decoded);
}



# Cluster: get details
sub get_cluster_details {
    debug("=== In get_cluster_details\n");

    my ($albApiUrl, $guid) = @_;

    # Get cluster details
    my $path = "GET/30";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_cluster_details()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    return($decoded);
}



# Cluster: total number of cluster members
sub get_cluster_member_count {
    debug("=== In get_cluster_member_count\n");

    my ($albApiUrl, $guid, $alb_ip_address) = @_;
    my $count = 0;

    # GET cluster details
    my $cluster = get_cluster_details($albApiUrl, $guid);

    if (defined($cluster->{'Members'}) && defined($cluster->{'Members'}->{'dataset'}) &&
        ($cluster->{'Members'}->{'dataset'} ne '') &&
        (scalar($cluster->{'Members'}->{'dataset'}) > 0)) {
        foreach my $member (@{$cluster->{'Members'}->{'dataset'}}) {
            if (defined($member->{'clustermember'})) {
                $count++;
            }
        }
    }

    return($count);
}



# Cluster: Get cluster member name by its IP
sub get_cluster_member_name {
    debug("=== In get_cluster_member_name\n");

    my ($albApiUrl, $guid, $alb_ip_address) = @_;

    # GET cluster details
    my $cluster = get_cluster_details($albApiUrl, $guid);

    if (defined($cluster->{'Members'}) && defined($cluster->{'Members'}->{'dataset'}) &&
        ($cluster->{'Members'}->{'dataset'} ne '') &&
        (scalar($cluster->{'Members'}->{'dataset'}) > 0)) {
        foreach my $member (@{$cluster->{'Members'}->{'dataset'}}) {
            if (defined($member->{'clustermember'})) {
                if ($member->{'clustermember'} =~ /^$alb_ip_address .*/) {
                    my $name = $member->{'clustermember'};
                    $name =~ s/^$alb_ip_address\s+//;
                    return($name);
                }
            }
        }
    }

    return(-1);
}



# Cluster: Get status (Online, Offline, etc) of a cluster member 
# specified by its IP address ($alb_ip_address)
sub get_cluster_member_status {
    debug("=== In get_cluster_member_status\n");

    my ($albApiUrl, $guid, $alb_ip_address) = @_;

    # GET cluster details
    my $cluster = get_cluster_details($albApiUrl, $guid);

    if (defined($cluster->{'Members'}) && defined($cluster->{'Members'}->{'dataset'}) &&
        ($cluster->{'Members'}->{'dataset'} ne '') &&
        (scalar($cluster->{'Members'}->{'dataset'}) > 0)) {
        foreach my $member (@{$cluster->{'Members'}->{'dataset'}}) {
            if (defined($member->{'clustermember'})) {
                if ($member->{'clustermember'} =~ /^$alb_ip_address .*/) {
                    return($member->{'channelStatusReason'});
                }
            }
        }
    }

    return(-1);
}



# Cluster: check if an ALB $alb_ip_address is a cluster member and return its priority
sub get_cluster_member_priority {
    debug("=== In get_cluster_member_priority\n");
    my ($albApiUrl, $guid, $alb_ip_address) = @_;

    # GET cluster details
    my $cluster = get_cluster_details($albApiUrl, $guid);

    if (defined($cluster->{'Members'}) && defined($cluster->{'Members'}->{'dataset'}) &&
        ($cluster->{'Members'}->{'dataset'} ne '') &&
        (scalar($cluster->{'Members'}->{'dataset'}) > 0)) {
        foreach my $member (@{$cluster->{'Members'}->{'dataset'}}) {
            if (defined($member->{'clustermember'})) {
                if ($member->{'clustermember'} =~ /^$alb_ip_address .*/) {
                    return($member->{'id'});
                }
            }
        }
    }

    return(-1);
}



# Cluster: check if an ALB $alb_ip_address is an unclaimed device and return its priority
sub get_cluster_unclaimed_priority {
    debug("=== In get_cluster_unclaimed_priority\n");

    my ($albApiUrl, $guid, $alb_ip_address) = @_;

    # GET cluster details
    my $cluster = get_cluster_details($albApiUrl, $guid);

    if (defined($cluster->{'UnPartenered'}) && defined($cluster->{'UnPartenered'}->{'dataset'}) &&
        ($cluster->{'UnPartenered'}->{'dataset'} ne '') &&
        (scalar($cluster->{'UnPartenered'}->{'dataset'}) > 0)) {
        foreach my $unpartnered (@{$cluster->{'UnPartenered'}->{'dataset'}}) {
            if (defined($unpartnered->{'unclaimeddevices'})) {
                if ($unpartnered->{'unclaimeddevices'} =~ /^$alb_ip_address .*/) {
                    return($unpartnered->{'id'});
                }
            }
        }
    }

    return(-1);
}



# Cluster: get role
sub get_cluster_role {
    debug("=== In get_cluster_role\n");

    my ($albApiUrl, $guid) = @_;

    # GET cluster details
    my $cluster = get_cluster_details($albApiUrl, $guid);

    if (defined($cluster->{'clusterState'})) {
        if ($cluster->{'clusterState'} eq '1') {
            return('Cluster');
        }
        elsif ($cluster->{'clusterState'} eq '2') {
            return('Manual');
        }
        elsif ($cluster->{'clusterState'} eq '3') {
            return('Stand-alone');
        }
        else {
            return($cluster->{'clusterState'});
        }
    }
    else {
        return(undef);
    }
}



# Cluster: set role
sub set_cluster_role {
    debug("=== In set_cluster_role\n");

    my ($albApiUrl, $guid, $role) = @_;

    # GET cluster details
    my $cluster = get_cluster_details($albApiUrl, $guid);

    my $role_id;
    if ($role eq 'Cluster') {
        $role_id = '1';
    }
    elsif ($role eq 'Manual') {
        $role_id = '2';
    }
    elsif ($role eq 'Stand-alone') {
        $role_id = '3';
    }    

    # Set cluster role
    my $path = "POST/30?iAction=1&iType=2";
    my $request = encode_json({'ClusterState' => $role_id});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in set_cluster_role()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to move ALB from unclaimed to cluster failed in set_cluster_role(): '" . $decoded->{'StatusText'} . "'", 1);
    }
    debug("Result:\n". $json ."\n");

    return($decoded);
}



# Cluster: add ALB to cluster
sub cluster_add_alb {
    debug("=== In cluster_add_alb\n");

    my ($albApiUrl, $guid, $alb_ip_address) = @_;

    # GET cluster details
    my $cluster = get_cluster_details($albApiUrl, $guid);

    # Move the ALB from unclaimed to cluster
    my $path = "POST/30?iAction=2&iType=4";
    my $request = encode_json({'ipAddr' => $alb_ip_address});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in cluster_add_alb()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to move ALB from unclaimed to cluster failed in cluster_add_alb(): '" . $decoded->{'StatusText'} . "'", 1);
    }
    debug("Result:\n". $json ."\n");

    return($decoded);
}



# Cluster: remove ALB from cluster
sub cluster_remove_alb {
    debug("=== In cluster_remove_alb\n");

    my ($albApiUrl, $guid, $alb_ip_address) = @_;

    # GET cluster details
    my $cluster = get_cluster_details($albApiUrl, $guid);

    # Move the ALB from cluster to unclaimed
    my $path = "POST/30?iAction=2&iType=3";
    my $request = encode_json({'ipAddr' => $alb_ip_address});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in cluster_remove_alb()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to move ALB from cluster to unclaimed failed in cluster_remove_alb(): '" . $decoded->{'StatusText'} . "'", 1);
    }
    debug("Result:\n". $json ."\n");

    return($decoded);
}



# Cluster: move cluster member priority up
sub cluster_move_priority_up {
    debug("=== In cluster_move_priority_up\n");

    my ($albApiUrl, $guid, $alb_ip_address) = @_;

    # GET ALB cluster priority
    my $priority_old = get_cluster_member_priority($albApiUrl, $guid, $alb_ip_address);

    # Move the ALB cluster priority up
    my $path = "POST/30?iAction=2&iType=1";
    my $request = encode_json({'ipAddr' => $alb_ip_address});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in cluster_move_priority_up()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to move ALB from unclaimed to cluster failed in cluster_move_priority_up(): '" . $decoded->{'StatusText'} . "'", 1);
    }
    debug("Result:\n". $json ."\n");

    # Check ALB cluster priority
    my $priority_new = get_cluster_member_priority($albApiUrl, $guid, $alb_ip_address);
    if (($priority_new == $priority_old - 1) || ($priority_new == 1)) {
        return($priority_new);
    } else {
        error("Failed to move ALB cluster priority up: old priority: $priority_old, new priority: $priority_new\n", 1);
    }
}



# Cluster: move cluster member priority down
sub cluster_move_priority_down {
    debug("=== In cluster_move_priority_down\n");

    my ($albApiUrl, $guid, $alb_ip_address) = @_;

    # GET ALB cluster priority
    my $priority_old = get_cluster_member_priority($albApiUrl, $guid, $alb_ip_address);

    # Move the ALB cluster priority down
    my $path = "POST/30?iAction=2&iType=2";
    my $request = encode_json({'ipAddr' => $alb_ip_address});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in cluster_move_priority_down()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to move ALB from unclaimed to cluster failed in cluster_move_priority_down(): '" . $decoded->{'StatusText'} . "'", 1);
    }
    debug("Result:\n". $json ."\n");

    # Check ALB cluster priority
    my $cluster_member_num = get_cluster_member_count($albApiUrl, $guid);
    my $priority_new = get_cluster_member_priority($albApiUrl, $guid, $alb_ip_address);
    if (($priority_new == $priority_old + 1) || ($priority_new == $cluster_member_num)) {
        return($priority_new);
    } else {
        error("Failed to move ALB cluster priority down: old priority: $priority_old, new priority: $priority_new\n", 1);
    }
}



# Cluster: get failover latency
sub get_cluster_failover_latency {
    debug("=== In get_cluster_failover_latency\n");

    my ($albApiUrl, $guid) = @_;

    # GET cluster details
    my $cluster = get_cluster_details($albApiUrl, $guid);

    if (defined($cluster->{'Failover'})) {
        return($cluster->{'Failover'});
    } else {
        return(undef);
    }
}



# Cluster: set failover latency
sub set_cluster_failover_latency {
    debug("=== In set_cluster_failover_latency\n");

    my ($albApiUrl, $guid, $latency) = @_;

    # GET cluster details
    my $cluster = get_cluster_details($albApiUrl, $guid);

    # Update cluster failover latency
    my $path = "POST/30?iAction=1&iType=1";
    my $request = encode_json({'FailOvertimer' => $latency});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in set_cluster_failover_latency()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request failed in set_cluster_failover_latency(): '" . $decoded->{'StatusText'});
    }
    debug("Result:\n". $json ."\n");

    return($decoded);
}



# Users: get details of all users
sub get_all_users {
    debug("=== In get_all_users\n");

    my ($albApiUrl, $guid) = @_;

    # Get user details
    my $path = "GET/33";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_all_users()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    return($decoded);
}


sub get_user {
    debug("=== In get_user\n");

    my ($albApiUrl, $guid, $user_name) = @_;

    my $users = get_all_users($albApiUrl, $guid);

    if (defined($users->{'Members'}) && defined($users->{'Members'}->{'dataset'}) &&
        ($users->{'Members'}->{'dataset'} ne '') &&
        (scalar($users->{'Members'}->{'dataset'}) > 0)) {
        foreach my $user (@{$users->{'Members'}->{'dataset'}}) {
            if (defined($user->{'UserName'})) {
                if ($user->{'UserName'} eq $user_name) {
                    return($user);
                }
            }
        }
    }
}



# Users: create a user
sub create_user {
    debug("=== In create_user\n");

    my ($albApiUrl, $guid, $user_name, $password, 
        $is_api, $is_addon, $is_admin, $is_guir, $is_guiw, $is_ssh) = @_;

    # GET user details
    my $users = get_all_users($albApiUrl, $guid);

    # Create user
    my $path = "POST/33?iAction=1&iType=1";
    my $request = encode_json({'UserName' => $user_name, 'NewPassword' => $password, 'OldPassword' => '', 
        'isAPI' => $is_api, 'isAddOn' => $is_addon, 'isAdmin' => $is_admin, 
        'isGUIR' => $is_guir, 'isGUIW' => $is_guiw, 'isSSH' => $is_ssh});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in create_user()\n", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request failed in create_user(): '" . $decoded->{'StatusText'} . "'", 1);
    }
    debug("Result:\n". $json ."\n");

    return($decoded);
}



# Users: update user password
sub update_user_password {
    debug("=== In update_user_password\n");

    my ($albApiUrl, $guid, $user_name, $old_password, $password) = @_;

    # GET user details
    my $users = get_all_users($albApiUrl, $guid);

    my $user;
    if (defined($users) && defined($users->{'Members'}) && defined($users->{'Members'}->{'dataset'}) &&
        (scalar($users->{'Members'}->{'dataset'} > 0))) {
        foreach my $row (@{$users->{'Members'}->{'dataset'}}) {
            if ($row->{'UserName'} eq $user_name) {
                $user = $row;
                last;
            }
        }
    }
    if (!$user) {
        error("ALB user '$user_name' not found in update_user_password()\n", 1);
    }

    # Update user
    my $path = "POST/33?iAction=1&iType=2";
    my $request = encode_json({'UserName' => $user_name, 'NewPassword' => $password, 'OldPassword' => $old_password, 
        'isAPI' => $user->{'isAPI'}, 'isAddOn' => $user->{'isAddOn'}, 'isAdmin' => $user->{'isAdmin'}, 
        'isGUIR' => $user->{'isGUIR'}, 'isGUIW' => $user->{'isGUIW'}, 'isSSH' => $user->{'isSSH'}});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in update_user_password()\n", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request failed in update_user_password(): '" . $decoded->{'StatusText'} . "'", 1);
    }
    debug("Result:\n". $json ."\n");

    return($decoded);
}



# Users: remove a user
sub remove_user {
    debug("=== In remove_user\n");

    my ($albApiUrl, $guid, $user_name) = @_;

    # GET user details
    my $users = get_all_users($albApiUrl, $guid);

    # Create user
    my $path = "POST/33?iAction=1&iType=3";
    my $request = encode_json({'UserName' => $user_name});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in remove_user\n()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request failed in remove_user(): '" . $decoded->{'StatusText'} . "'", 1);
    }
    debug("Result:\n". $json ."\n");

    return($decoded);
}



# Get id to value mappings of Real Server monitoring methods
sub get_monitor_combo_options {
    debug("=== In get_monitor_combo_options\n");

    my ($albApiUrl, $guid) = @_;
    my $path = "GET/13";
    my %res_tmp; my $res = \%res_tmp;

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_monitor_combo_options()", 1);
    }
    my $decoded = decode_json($json);
    
    debug("$json\n");
    return($decoded);
}



# Get a first Real Server monitor matching parameters: id, name, desc.
# If any of the input parameters are empty, they are not checked while looking for a Real Server monitor.
sub get_monitor {
    debug("=== In get_monitor\n");

    my ($albApiUrl, $guid, $id, $name, $description) = @_;
    my $path = "GET/13";
    my %res_tmp; my $res = \%res_tmp;
    
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_monitor()", 1);
    }
    my $decoded = decode_json($json);
            
    debug("$json\n");
            
    # Find a Real Server monitor by its name
    if (defined($decoded->{'ConfigMonitoringGrid'}->{'dataset'}->{'row'}) &&
       ($decoded->{'ConfigMonitoringGrid'}->{'dataset'}->{'row'} ne "")) {
        my @monitors = @{$decoded->{'ConfigMonitoringGrid'}->{'dataset'}->{'row'}};
        if (scalar(@monitors) > 0) {
            foreach my $monitor (@monitors) {
                debug("Real Server monitor:\n" . encode_json($monitor) . "\n");
            
                my ($idCmp, $nameCmp, $descriptionCmp) = ('', '', '', '');
                if (defined($id) && ($id ne '')) {
                    $idCmp = $monitor->{'id'};
                } else {
                    $id = '';
                }
                if (defined($name) && ($name ne '')) {
                    $nameCmp = $monitor->{'name'};
                } else {
                    $name = '';
                }
                if (defined($description) && ($description ne '')) {
                    $descriptionCmp = $monitor->{'description'};
                } else {
                    $description = '';
                }

                if (($idCmp eq $id) && ($nameCmp eq $name) &&
                    ($descriptionCmp eq $description)) {
                    $res = $monitor;
                    last;
                }
            }
        }
    }
    return($res);
}



# Update Real Server monitor data
sub update_monitor {
    debug("=== In update_monitor\n");

    my ($albApiUrl, $guid, $monitor) = @_;
    my $path = "POST/13?iAction=2&iType=1";

    my $request = encode_json($monitor);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a Real Server monitor in update_monitor()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update a Real Server monitor failed in update_monitor(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);

    return($decoded);
}



# Create a Real Server monitor
sub create_monitor {
    debug("=== In create_monitor\n");

    my ($albApiUrl, $guid, $name, $description, $method, $url, $content, 
        $username, $password, $threshold) = @_;
    my %res_tmp; my $res = \%res_tmp;
    my $monitor_num = 0;

    # GET Real Server monitors
    my $path = "GET/13";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in create_monitor()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    # Get number of existing Real Server monitors
    if (defined($decoded->{'ConfigMonitoringGrid'}->{'dataset'}->{'row'}) &&
        ($decoded->{'ConfigMonitoringGrid'}->{'dataset'}->{'row'} ne "")) {
        my @monitors = @{$decoded->{'ConfigMonitoringGrid'}->{'dataset'}->{'row'}};
        if (scalar(@monitors) > 0) {
            foreach my $monitor (@monitors) {
                $monitor_num++;
            }
        }
    }
    debug("Real Server monitor num = $monitor_num\n");

    # First create an "empty" Real Server monitor, afterwards update it with actual data
    debug("First create an \"empty\" Real Server monitor\n");
    $path = "POST/13?iAction=1&iType=1";
    my $request = '{}';

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to create a Real Server monitor in create_monitor()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to create a Real Server monitor failed in create_monitor(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");


    # Store the newly created "empty" Real Server monitor data in $empty_monitor
    debug("Get the newly created \"empty\" Real Server monitor in \$empty_monitor\n");
    my $empty_monitor;
    if (defined($decoded->{'ConfigMonitoringGrid'}->{'dataset'}->{'row'}) &&
        ($decoded->{'ConfigMonitoringGrid'}->{'dataset'}->{'row'} ne "")) {
        my @monitors = @{$decoded->{'ConfigMonitoringGrid'}->{'dataset'}->{'row'}};
        if (scalar(@monitors) > 0) {
            foreach my $tmp_monitor (@monitors) {
                if ($tmp_monitor->{'id'} == $monitor_num + 1) {
                    $empty_monitor = $tmp_monitor;
                    last;
                }
            }
        }
    }

    # Get id to value mappings of Real Server monitoring methods
    my $combos = get_monitor_combo_options($albApiUrl, $guid);
    my $method_id = get_combo_option_id($combos, 'MethodCombo', $method);
    if ((!defined($method_id)) || ($method_id eq '')) {
        error("Failed to get Real Server monitoring method ID for '$method'", 1);
    }

    # Update the Real Server monitor with actual data
    debug("Update the Real Server monitor with actual data\n");
    my $monitor;
    $monitor->{'id'} = $empty_monitor->{'id'};
    $monitor->{'name'} = $name;
    $monitor->{'description'} = $description;
    $monitor->{'type'} = $method_id;
    $monitor->{'url'} = $url;
    $monitor->{'content'} = $content;
    $monitor->{'Username'} = $username;
    $monitor->{'Password'} = $password;
    $monitor->{'Threshold'} = $threshold;
    my @mon_arr = ($monitor);
    debug("Real Server monitor:\n" . encode_json($monitor) . "\n");
    $decoded = update_monitor($albApiUrl, $guid, \@mon_arr);

    return($decoded);
}



sub remove_monitor {
    debug("=== In remove_monitor\n");

    my ($albApiUrl, $guid, $id, $name) = @_;
    my $monitor;

    # GET Real Server monitor
    if (defined($id) && ($id ne "")) {
        $monitor = get_monitor($albApiUrl, $guid, $id);
    }
    elsif (defined($name) && ($name ne "")) {
        $monitor = get_monitor($albApiUrl, $guid, '', $name);
    }
    else {
        error("Neither Real Server monitor id, nor name specified in remove_monitor()", 1);
    }

    if (!defined($monitor->{'id'})) {
        error("Requested Real Server monitor '$name' not found in remove_monitor()", 1);
    }

    debug("Real Server monitor: " . encode_json($monitor) . "\n");

    # Remove the Real Server monitor
    my $path = "POST/13?iAction=3&iType=1";
    my $del_monitor = {'id' => $monitor->{'id'}};
    my $request = encode_json($del_monitor);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to remove a Real Server monitor in remove_monitor()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to remove a Real Server monitor failed in remove_monitor(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");

    return($decoded);
}



# Upload a custom monitor script named $monitorName from a file supplied as $fileName
sub upload_custom_monitor_script {
    my ($albApiUrl, $guid, $monitorName, $fileName) = @_;

    if (! -r $fileName) {
        error("Failed to read file '$fileName' in upload_custom_monitor_script()", 1);
    }

    # GET before POST
    get_monitor_combo_options($albApiUrl, $guid);

    my $path = "POST/13?iAction=5&send=csm";
    # Note, there is a typo in REST API parameter name: UploadMointorName
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -F 'file=\@$fileName' -F UploadMointorName='$monitorName' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", "-F file='\@$fileName' -F UploadMointorName='$monitorName'");
    if (!$json) {
        error("Failed to connect to ALB API in upload_custom_monitor_script()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && 
        (($decoded->{'StatusText'} ne 'Your changes have been applied'))) {
        error("ALB API request to upload ALB config failed in upload_custom_monitor_script(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



sub remove_custom_monitor_script {
    debug("=== In remove_custom_monitor_script\n");

    my ($albApiUrl, $guid, $scriptId, $scriptName) = @_;

    if ((!defined($scriptId) || ($scriptId eq "")) && (defined($scriptName) && ($scriptName ne ""))) {
        # Get id to value mappings of custom monitor scripts
        my $combos = get_monitor_combo_options($albApiUrl, $guid);
        $scriptId = get_combo_option_id($combos, 'MethodCombo', $scriptName);
    }
    else {
        error("Neither custom monitor script id, nor name specified in remove_custom_monitor_script()", 1);
    }

    if ((!defined($scriptId)) || ($scriptId eq '')) {
        error("Failed to get custom monitor script ID for '$scriptName'", 1);
    }

    debug("Custom monitor script ID: $scriptId\n");

    # Remove the custom monitor script 
    my $path = "POST/13?iAction=4";
    my $del_script = {'CustomMonitor' => $scriptId};
    my $request = encode_json($del_script);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to remove a custom monitor script in remove_custom_monitor_script()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to remove a Real Server monitor failed in remove_custom_monitor_script(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");

    return($decoded);
}



sub get_cache_combo_options {
    debug("=== In get_cache_combo_options\n");

    my ($albApiUrl, $guid) = @_;
    my $path = "GET/18";
    my %res_tmp; my $res = \%res_tmp;

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_cache_combo_options()", 1);
    }
    my $decoded = decode_json($json);
    
    debug("$json\n");
    return($decoded);
}



# Get a first cache host matching parameters: id, name, rule.
# If any of the input parameters are empty, they are not checked while looking for a cache host.
sub get_cache_host {
    debug("=== In get_cache_host\n");

    my ($albApiUrl, $guid, $id, $name, $rule) = @_;
    my $path = "GET/18";
    my %res_tmp; my $res = \%res_tmp;
    
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_cache_host()", 1);
    }
    my $decoded = decode_json($json);
            
    debug("$json\n");
            
    # Find a cache host by its name
    if (defined($decoded->{'CacheDomainGrid'}->{'dataset'}->{'row'}) &&
       ($decoded->{'CacheDomainGrid'}->{'dataset'}->{'row'} ne "")) {
        my @hosts = @{$decoded->{'CacheDomainGrid'}->{'dataset'}->{'row'}};
        if (scalar(@hosts) > 0) {
            foreach my $host (@hosts) {
                debug("Cache host:\n" . encode_json($host) . "\n");
            
                my ($idCmp, $nameCmp, $ruleCmp) = ('', '', '', '');
                if (defined($id) && ($id ne '')) {
                    $idCmp = $host->{'id'};
                } else {
                    $id = '';
                }
                if (defined($name) && ($name ne '')) {
                    $nameCmp = $host->{'name'};
                } else {
                    $name = '';
                }
                if (defined($rule) && ($rule ne '')) {
                    $ruleCmp = $host->{'rule'};
                } else {
                    $rule = '';
                }

                if (($idCmp eq $id) && ($nameCmp eq $name) &&
                    ($ruleCmp eq $rule)) {
                    $res = $host;
                    last;
                }
            }
        }
    }
    return($res);
}



# Update cache host data
sub update_cache_host {
    debug("=== In update_cache_host\n");

    my ($albApiUrl, $guid, $monitor) = @_;
    my $path = "POST/18?iAction=2&iType=3";

    my $request = encode_json($monitor);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a cache host in update_cache_host()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update a cache host failed in update_cache_host(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);

    return($decoded);
}



# Create a cache host
sub create_cache_host {
    debug("=== In create_cache_host\n");
    my ($albApiUrl, $guid, $name, $rule) = @_;
    my %res_tmp; my $res = \%res_tmp;
    my $cache_host_num = 0;

    # GET cache hosts
    my $path = "GET/18";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in create_cache_host()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");


    # First create an "empty" cache host, afterwards update it with actual data
    debug("First create an \"empty\" cache host\n");
    $path = "POST/18?iAction=2&iType=1";
    my $request = '[{"vButtonFlag": "1"}]';

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to create a cache host in create_cache_host()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to create a cache host failed in create_cache_host(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");


    # Store the newly created "empty" cache host data in $empty_cache_host
    debug("Get the newly created \"empty\" cache host in \$empty_cache_host\n");
    my $empty_cache_host;
    if (defined($decoded->{'CacheDomainGrid'}->{'dataset'}->{'row'}) &&
        ($decoded->{'CacheDomainGrid'}->{'dataset'}->{'row'} ne "")) {
        my @cache_hosts = @{$decoded->{'CacheDomainGrid'}->{'dataset'}->{'row'}};
        if (scalar(@cache_hosts) > 0) {
            foreach my $tmp_cache_host (@cache_hosts) {
                # Note: this REST API method is different from the others:
                # new item created always gets ID==0, existing item IDs are incremented.
                if ($tmp_cache_host->{'name'} eq '*new*') {
                    $empty_cache_host = $tmp_cache_host;
                    last;
                }
            }
        }
    }

    if (!defined($empty_cache_host->{'id'})) {
        error("Failed to create \"empty\" cache host", 1);
    }

    # Get id to value mappings of cache rules
    my $combos = get_cache_combo_options($albApiUrl, $guid);
    my $rule_id = get_combo_option_id($combos, 'CacheDomainCombo', $rule);
    if ((!defined($rule_id)) || ($rule_id eq '')) {
        error("Failed to get cache rule ID for '$rule'", 1);
    }

    # Update the cache host with actual data
    debug("Update the cache host with actual data\n");
    my $cache_host;
    $cache_host->{'id'} = $empty_cache_host->{'id'};
    $cache_host->{'name'} = $name;
    $cache_host->{'rule'} = $rule_id;
    my @cache_host_arr = ($cache_host);
    debug("Cache host:\n" . encode_json($cache_host) . "\n");
    $decoded = update_cache_host($albApiUrl, $guid, \@cache_host_arr);

    return($decoded);
}



sub remove_cache_host {
    debug("=== In remove_cache_host\n");

    my ($albApiUrl, $guid, $id, $name) = @_;
    my $cache_host;

    # GET cache host
    if (defined($id) && ($id ne "")) {
        $cache_host = get_cache_host($albApiUrl, $guid, $id);
    }
    elsif (defined($name) && ($name ne "")) {
        $cache_host = get_cache_host($albApiUrl, $guid, '', $name);
    }
    else {
        error("Neither cache host id, nor name specified in remove_cache_host()", 1);
    }

    if (!defined($cache_host->{'id'})) {
        error("Requested cache host '$name' not found in remove_cache_host()", 1);
    }

    debug("Cache host: " . encode_json($cache_host) . "\n");

    # Remove the cache host
    my $path = "POST/18?iAction=2&iType=2";
    my $del_cache_host = {'id' => $cache_host->{'id'}};
    my $request = encode_json($del_cache_host);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to remove a cache host in remove_cache_host()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to remove a cache host failed in remove_cache_host(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");

    return($decoded);
}



# Get a first Load Balancing Policiy matching parameters: type, id, name, desc, IPAddress.
# If any of the input parameters are empty, they are not checked while looking for a Load Balancing Policiy.
sub get_lbp {
    debug("=== In get_lbp\n");

    my ($albApiUrl, $guid, $type, $id, $name, $desc, $IPAddress) = @_;
    my $path = "api/load-balance";
    my %res_tmp; my $res = \%res_tmp;

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_lbp()", 1);
    }
    my $decoded = decode_json($json);
            
    debug("$json\n");
            
    # Find a Load Balancing Policiy by its name
    if (defined($decoded->{'data'}) &&
       ($decoded->{'data'} ne "")) {
        my @lbps = @{$decoded->{'data'}};
        if (scalar(@lbps) > 0) {
            foreach my $lbp (@lbps) {
                debug("LBP:\n" . encode_json($lbp) . "\n");
            
                my ($idCmp, $nameCmp, $typeCmp, $descCmp, $IPAddressCmp) = 
                   ('', '', '', '', '');
                if (defined($id) && ($id ne '')) {
                    $idCmp = $lbp->{'Id'};
                } else {
                    $id = '';
                }
                if (defined($name) && ($name ne '')) {
                    $nameCmp = $lbp->{'PolicyName'};
                } else {
                    $name = '';
                }
                if (defined($type) && ($type ne '')) {
                    $typeCmp = $lbp->{'Type'};
                } else {
                    $type = '';
                }
                if (defined($desc) && ($desc ne '')) {
                    $descCmp = $lbp->{'Description'};
                } else {
                    $desc = '';
                }
                if (defined($IPAddress) && ($IPAddress ne '')) {
                    $IPAddressCmp = $lbp->{'IPAddress'};
                } else {
                    $IPAddress = '';
                }

                if (($idCmp eq $id) && ($nameCmp eq $name) && ($typeCmp =~ /$type/i) &&
                    ($descCmp eq $desc) && ($IPAddressCmp eq $IPAddress)) {
                    $res = $lbp;
                    last;
                }
            }
        }
    }
    return($res);
}



# Update Load Balancing Policiy data
sub update_lbp {
    debug("=== In update_lbp\n");

    my ($albApiUrl, $guid, $type, $lbp) = @_;
    my $path = "api/load-balance/policy/update";

    my $request = encode_json($lbp);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a LBP in update_lbp()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update a LBP failed in update_lbp(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);

    return($decoded);
}



# Create a Load Balancing Policiy
sub create_lbp {
    debug("=== In create_lbp\n");

    my ($albApiUrl, $guid, $name, $desc) = @_;
    my %res_tmp; my $res = \%res_tmp;
    my $lbp_num = 0;

    # GET Load Balancing Policies
    my $path = "api/load-balance";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in create_lbp()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    # Get number of existing Load Balancing Policies
    if (defined($decoded->{'data'}) &&
        ($decoded->{'data'} ne "")) {
        my @lbps = @{$decoded->{'data'}};
        if (scalar(@lbps) > 0) {
            foreach my $lbp (@lbps) {
                $lbp_num++;
            }
        }
    }
    debug("LBP num = $lbp_num\n");

    # First create an "empty" Load Balancing Policy, afterwards update it with actual data
    debug("First create an \"empty\" Load Balancing Policy\n");
    $path = "api/load-balance/policy/add";
    my $request = '{}';

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to create a LBP in create_lbp()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to create a LBP failed in create_lbp(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");


    # If $name or $desc input paramters were spcified, updated LBP with this data
    if ((defined($name) && ($name ne '')) || (defined($desc) && ($desc ne ''))) {
        # Store the newly created "empty" Load Balancing Policy data in $empty_lbp
        debug("Get the newly created \"empty\" Load Balancing Policy in \$empty_lbp\n");
        my $empty_lbp;
        if (defined($decoded->{'data'}) &&
            ($decoded->{'data'} ne "")) {
            my @lbps = @{$decoded->{'data'}};
            if (scalar(@lbps) > 0) {
                foreach my $tmp_lbp (@lbps) {
                    if ($tmp_lbp->{'Id'} == $lbp_num + 1) {
                        $empty_lbp = $tmp_lbp;
                        last;
                    }
                }
            }
        }

        # Update the Load Balancing Policy with actual data
        debug("Update the Load Balancing Policy with actual data\n");
        my $lbp;
        $lbp->{'Id'} = $empty_lbp->{'Id'};
        if (defined($name) && ($name ne '')) {
            $lbp->{'PolicyName'} = $name;
        } else {
            $lbp->{'PolicyName'} = $empty_lbp->{'PolicyName'};
        }
        if (defined($desc) && ($desc ne '')) {
            $lbp->{'Description'} = $desc;
        } else {
            $lbp->{'Description'} = $empty_lbp->{'Description'};
        }
        debug("LBP:\n" . encode_json($lbp) . "\n");
        $decoded = update_lbp($albApiUrl, $guid, 'custom', $lbp);
    }

    return($decoded);
}



sub copy_lbp {
    debug("=== In copy_lbp\n");

    my ($albApiUrl, $guid, $type, $id, $name) = @_;
    my $lbp;

    # GET Load Balancing Policies
    if (defined($id) && ($id ne "")) {
        $lbp = get_lbp($albApiUrl, $guid, $type, $id);
        if (!defined($lbp->{'Id'})) {
            error("Requested Load Balancing Policy '$id' not found in copy_lbp($type, $id, $name)", 1);
        }
    }
    elsif (defined($name) && ($name ne "")) {
        $lbp = get_lbp($albApiUrl, $guid, $type, '', $name);
        if (!defined($lbp->{'Id'})) {
            error("Requested Load Balancing Policy '$name' not found in copy_lbp($type, $id, $name)", 1);
        }
    }
    else {
        error("Neither Load Balancing Policy id, nor name specified in copy_lbp($type, $id, $name)", 1);
    }


    debug("LBP: " . encode_json($lbp) . "\n");

    # Copy the Load Balancing Policiy
    my $path = "api/load-balance/$type/copy";
    my $copy_json = {'Id' => $lbp->{'Id'}};
    my $request = encode_json($copy_json);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to copy a LBP in copy_lbp()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to copy a LBP failed in copy_lbp(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");

    return($decoded);
}



sub remove_lbp {
    debug("=== In remove_lbp\n");

    my ($albApiUrl, $guid, $id, $name) = @_;
    my $lbp;

    # GET Load Balancing Policies
    if (defined($id) && ($id ne "")) {
        $lbp = get_lbp($albApiUrl, $guid, 'custom', $id);
        if (!defined($lbp->{'Id'})) {
            error("Requested Load Balancing Policy '$id' not found in remove_lbp()", 1);
        }
    }
    elsif (defined($name) && ($name ne "")) {
        $lbp = get_lbp($albApiUrl, $guid, 'custom', '', $name);
        if (!defined($lbp->{'Id'})) {
            error("Requested Load Balancing Policy '$name' not found in remove_lbp()", 1);
        }
    }
    else {
        error("Neither Load Balancing Policy id, nor name specified in remove_lbp()", 1);
    }


    debug("LBP: " . encode_json($lbp) . "\n");

    # Remove the Load Balancing Policiy
    my $path = "api/load-balance/custom/remove";
    my $del_lbp = {'Id' => $lbp->{'Id'}};
    my $request = encode_json($del_lbp);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to remove a LBP in remove_lbp()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to remove a LBP failed in remove_lbp(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");

    return($decoded);
}



# Get Security page data
sub get_security_page_data {
    debug("=== In get_security_page_data\n");

    my ($albApiUrl, $guid) = @_;
    my $path = "GET/15";
    
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_security_page_data()", 1);
    }
    my $decoded = decode_json($json);
            
    debug("$json\n");

    return($decoded);
}



# Security: enable/disable SSH server
sub security_configure_ssh {
    debug("=== In security_configure_ssh\n");

    my ($albApiUrl, $guid, $new_state) = @_;

    # GET Security page data
    my $security = get_security_page_data($albApiUrl, $guid);

    debug("Security data: " . encode_json($security) . "\n");

    # Configure SSH server state
    my $path = "POST/15?iAction=1&iType=2";
    my $request = encode_json({'SSH' => $new_state});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to configure SSH server failed in security_configure_ssh()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to configure SSH server failed in security_configure_ssh(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");

    return($decoded);
}



sub get_protocol_page_data {
    debug("=== In get_protocol_page_data\n");

    my ($albApiUrl, $guid) = @_;
    my $path = "GET/25";
    my %res_tmp; my $res = \%res_tmp;

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_protocol_page_data()", 1);
    }
    my $decoded = decode_json($json);
    
    debug("$json\n");
    return($decoded);
}



sub set_global_compression_exclusions {
    debug("In set_global_compression_exclusions\n");

    # Issue a GET before POST
    my ($albApiUrl, $guid, $exclusions) = @_;
    my $path = "GET/25";
    
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in set_global_compression_exclusions()", 1);
    }
    my $decoded = decode_json($json);

    # Send POST request            
    $path = "POST/25?iAction=3&iType=1";
    my $request = encode_json({'CurrentExclusions' => $exclusions});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to set compression exclusions in set_global_compression_exclusions()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to set compression exclusions failed in set_global_compression_exclusions(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");

    return($decoded);
}



sub power_restart {
    debug("In power_restart\n");

    # Issue a GET before POST
    my ($albApiUrl, $guid) = @_;
    my $path = "GET/24";
    
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in set_global_compression_exclusions()", 1);
    }
    my $decoded = decode_json($json);

    # Send POST request            
    $path = "POST/24?iAction=5&iType=1";
    my $request = encode_json({'test' => 'test'});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API power_restart()", 1);
    }
    $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && (($decoded->{'StatusText'} ne 'Your changes have been applied') &&
        ($decoded->{'StatusText'} ne 'Service restart requested. Please wait.'))) {
        error("ALB API request to restart ALB failed in power_restart(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");

    return($decoded);
}



sub power_reboot {
    debug("In power_reboot\n");

    # Issue a GET before POST
    my ($albApiUrl, $guid) = @_;
    my $path = "GET/24";
    
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in set_global_compression_exclusions()", 1);
    }
    my $decoded = decode_json($json);

    # Send POST request            
    $path = "POST/24?iAction=5&iType=2";
    my $request = encode_json({'test' => 'test'});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API power_reboot()", 1);
    }
    $decoded = decode_json($json);

    # TODO: Looks like API does not return anything and just reboots immediately.
    # Ask for a fix and update the result check.
    if (defined($decoded->{'StatusImage'}) && (($decoded->{'StatusText'} ne 'Your changes have been applied') &&
        ($decoded->{'StatusText'} ne 'Reboot requested. Please wait.'))) {
        error("ALB API request to reboot ALB failed in power_reboot(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");

    return($decoded);
}



# Send Ping request
sub send_ping {
    debug("=== In send_ping\n");

    # Issue a GET before POST
    my ($albApiUrl, $guid, $ipAddress) = @_;
    my $path = "GET/24";
    
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in send_ping()", 1);
    }
    my $decoded = decode_json($json);

    # Send ping request            
    $path = "POST/24?iAction=5&iType=4";
    my $request = encode_json({'ipAddress' => $ipAddress});

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to send ping request failed in send_ping()", 1);
    }
    $decoded = decode_json($json);

    debug("Result:\n". $json ."\n");

    if (defined($decoded->{'PingTempfile'})) {
        return($decoded->{'PingTempfile'});
    } else {
        error("ALB API request to send ping request failed in send_ping(): '" . $decoded->{'StatusText'} . "'", 1);
    }
}



# Start packet capture
sub start_capture {
    debug("=== In start_capture\n");

    # Do a GET before POST
    my ($albApiUrl, $guid, $adapter, $packets, $duration) = @_;
    my $path = "GET/23";
    
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in start_capture()", 1);
    }
    my $decoded = decode_json($json);
    debug("Result:\n". $json ."\n");


    # Send a request to start a capture
    my $obj;
    $obj->{'Adapter'} = $adapter;
    $obj->{'Packets'} = $packets;
    $obj->{'Duration'} = $duration;
    $obj->{'CaptureHidden'} = '';
    $obj->{'CaptureAddress'} = '';

    $path = "POST/23?iAction=4&iType=1";
    my $request = encode_json($obj);
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to start capture failed in start_capture()", 1);
    }
    $decoded = decode_json($json);
    debug("Result:\n". $json ."\n");

    if (!defined($decoded->{'CaptureLeft'})) {
        error("ALB API request to start a capture failed in start_capture(): '" . $decoded->{'StatusText'} . "'", 1);
    }


    # Do a GET again (looking stupid, but it is required to make it work)
    $path = "GET/23";
    
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in start_capture()", 1);
    }
    $decoded = decode_json($json);
    debug("Result:\n". $json ."\n");


    # Wait until capture is completed
    my $completed = 0;
    while(!$completed) {
        $path = "GET/23?duration=$duration&packets=$packets&adapter=$adapter&download=capture&preDownloadCheck=yes";
        debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
        $json = alb_api_get($guid, "$albApiUrl/$path");
        if (!$json) {
            error("Failed to connect to ALB API in start_capture()", 1);
        }
        $decoded = decode_json($json);
        debug("Result:\n". $json ."\n");

        if (defined($decoded->{'CaptureLeft'}) && ($decoded->{'CaptureLeft'} > 0)) {
            print("Sleep ".$decoded->{'CaptureLeft'}."\n");
            sleep($decoded->{'CaptureLeft'});
        } elsif (defined($decoded->{'DownloadStatus'}) && ($decoded->{'DownloadStatus'} eq "success")) {
            $completed = 1;
        } else {
            sleep(1);
        }
    }

    # Download the capture
    $path = "GET/23?duration=$duration&packets=$packets&adapter=$adapter&download=capture";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $capture = alb_api_get($guid, "$albApiUrl/$path");
    if (!$capture) {
        error("Failed to download a capture in start_capture()", 1);
    }

    return($capture);
}



# Download support files
sub download_support_files {
    debug("=== In download_support_files\n");

    # Do a GET before POST
    my ($albApiUrl, $guid, $days) = @_;
    my $path = "GET/1";
    
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in download_support_files()", 1);
    }
    my $decoded = decode_json($json);
    debug("Result:\n". $json ."\n");


    # Send a request to download support files
    my $obj;
    $obj->{'Days'} = $days;

    $path = "POST/53?iAction=6&iType=1";
    my $request = encode_json($obj);
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to download support files in download_support_files()", 1);
    }
    $decoded = decode_json($json);
    debug("Result:\n". $json ."\n");

    if (!defined($decoded->{'StatusText'}) || ($decoded->{'StatusText'} ne 'success')) {
        error("ALB API request to download support files failed in download_support_files(): '" . $decoded->{'StatusText'} . "'", 1);
    }


    # Wait until support archieve is being prepared
    my $filename = '';
    while(!$filename) {
        $path = "GET/21?download=support&pid=";
        debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
        $json = alb_api_get($guid, "$albApiUrl/$path");
        if (!$json) {
            error("Failed to connect to ALB API in download_support_files()", 1);
        }
        $decoded = decode_json($json);
        debug("Result:\n". $json ."\n");

        if (defined($decoded->{'DownloadStatus'}) && ($decoded->{'DownloadStatus'} ne '')) {
            $filename = $decoded->{'DownloadStatus'};
        } else {
            debug("Wait 1 second\n");
            sleep(1);
        }
    }


    # Download support archieve
    $path = "GET/21?download=support&pid=&req=download&filename=$filename";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $data = alb_api_get($guid, "$albApiUrl/$path");
    if (!$data) {
        error("Failed to download support files in download_support_files()", 1);
    }

    return($filename, \$data);
}



# Start a troubleshooting trace
sub start_trace {
    debug("=== In start_trace\n");

    my ($albApiUrl, $guid, 
        $nodes, $traceConnections, $traceCache, $traceData, $tracePath, 
        $loadBalancing, $serverMonitor, $monitoringFault, 
        $autoStopTime, $autoStopRecords, $purpose) = @_;

    # Do a GET before POST
    my $path = "GET/58";
    
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in start_trace()", 1);
    }
    my $decoded = decode_json($json);
    debug("Result:\n". $json ."\n");

    if (!defined($nodes) || ($nodes eq '')) {
        $nodes = "Your IP";
    }
    if (!defined($traceConnections) || ($traceConnections eq '')) {
        $traceConnections = "0";
    }
    if (!defined($traceCache) || ($traceCache eq '')) {
        $traceCache = "0";
    }
    if (!defined($traceData) || ($traceData eq '')) {
        $traceData = "0";
    }
    if (!defined($tracePath) || ($tracePath eq '')) {
        $tracePath = "No flightPATH trace";
    }
    if (!defined($loadBalancing) || ($loadBalancing eq '')) {
        $loadBalancing = "0";
    }
    if (!defined($serverMonitor) || ($serverMonitor eq '')) {
        $serverMonitor = "0";
    }
    if (!defined($monitoringFault) || ($monitoringFault eq '')) {
        $monitoringFault = "0";
    }
    if (!defined($autoStopTime) || ($autoStopTime eq '')) {
        $autoStopTime = "00|01|00";
    }
    if (!defined($autoStopRecords) || ($autoStopRecords eq '')) {
        $autoStopRecords = "1000000";
    }
    if (!defined($purpose) || ($purpose eq '')) {
        $purpose = "";
    }


    # Send a request to start a trace
    my $obj;
    $obj->{'Start'} = "true"; 
    $obj->{'Nodes'} = $nodes; 
    $obj->{'TraceConnections'} = $traceConnections;
    $obj->{'TraceCache'} = $traceCache; 
    $obj->{'TraceData'} = $traceData; 
    $obj->{'TracePath'} = $tracePath; 
    $obj->{'LoadBalancing'} = $loadBalancing; 
    $obj->{'ServerMonitor'} = $serverMonitor; 
    $obj->{'MonitoringFault'} = $monitoringFault; 
    $obj->{'AutoStopTime'} = $autoStopTime; 
    $obj->{'AutoStopRecords'} = $autoStopRecords; 
    $obj->{'Purpose'} = $purpose; 

    $path = "POST/58?iAction=1&iType=1";
    my $request = encode_json($obj);
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to start trace failed in start_trace()", 1);
    }
    $decoded = decode_json($json);
    debug("Result:\n". $json ."\n");

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to start a trace failed in start_trace(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



# Returns downloaded troubleshooting trace file
sub download_trace {
    my ($albApiUrl, $guid) = @_;
    my $path = "GET/58?download=trace";
    
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $trace = alb_api_get($guid, "$albApiUrl/$path");
    if (!$trace) {
        error("Failed to download troubleshooting trace in download_trace()", 1);
    }

    debug("Trace:\n$trace\n");
            
    return($trace);
}



# Returns downloaded ALB config file (jetnexus.conf)
sub download_alb_config {
    my ($albApiUrl, $guid) = @_;
    my $path = "GET/26?download=conf";
    
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $config = alb_api_get($guid, "$albApiUrl/$path");
    if (!$config) {
        error("Failed to download ALB config in download_alb_config()", 1);
    }

    debug("Config:\n$config");
            
    return($config);
}



# Uploads ALB config file from a file supplied as $configFileName
sub upload_alb_config {
    my ($albApiUrl, $guid, $configFileName) = @_;

    if (! -r $configFileName) {
        error("Failed to read file '$configFileName' in upload_alb_config()", 1);
    }

    # This is a fake GET request before POST for avoiding the 'Another user has made changes' issue
    my $path = "GET/28";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in upload_alb_config()", 1);
    }

    $path = "POST/26?iAction=1&iType=1&send=conf";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -F 'data=\@$configFileName' \"$albApiUrl/$path\"\n");
    $json = alb_api_post($guid, "$albApiUrl/$path", "-F data='\@$configFileName'");
    if (!$json) {
        error("Failed to connect to ALB API in upload_alb_config()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && 
        (($decoded->{'StatusText'} ne 'Configuration updated successfully') &&
        ($decoded->{'StatusText'} ne 'Filetype=config'))) {
        error("ALB API request to upload ALB config failed in upload_alb_config(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($json);
}



# Update GUI port and certificate
sub update_gui_port_and_cert {
    my ($albApiUrl, $guid, $securePort, $certificate) = @_;

    # Have to make GET before POST
    my $security = get_security_page_data($albApiUrl, $guid);

    my $port = $security->{'SCP_PortGUI3'};
    if (!defined($securePort) || ($securePort eq '')) {
        $securePort = $security->{'SCP_SecurePortGUI3'};
    }
    if (!defined($certificate) || ($certificate eq '')) {
        $certificate = $security->{'SCP_CertificateGUI3'};
    }

    my $options;
    $options->{'SCP_ChangeAccepted'} = '1';
    $options->{'SCP_PortGUI3'} = $port;
    $options->{'SCP_SecurePortGUI3'} = $securePort;
    $options->{'SCP_CertificateGUI3'} = $certificate;

    debug("Update GUI port and certificate\n");
    my $path = "POST/15?iAction=1&iType=5";

    my $request = encode_json($options);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in update_gui_port_and_cert()", 1);
    }
    my $decoded = decode_json($json);

    debug("Result:\n". $json ."\n");

    if (defined($decoded->{'StatusImage'}) && 
        ($decoded->{'StatusText'} ne 'Your changes have been applied') &&
        ($decoded->{'StatusText'} ne 'Certificate has been deleted.')
    ) {
        error("ALB API request to update GUI port and certificate failed in update_gui_port_and_cert(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



sub get_network_adapter_data {
    my ($albApiUrl, $guid) = @_;

    my $path = "GET/1";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_network_adapter_data()", 1);
    }

    debug("Result:\n". $json);

    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'get')) {
        error("ALB API request to get network adapter data failed in get_network_adapter_data(): '" . 
            $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



sub update_network_adapter {
    my ($albApiUrl, $guid, $id, $ethName, $address, $mask, $gateway, $desc, $ethVlan, $rpFilter, $webconsoleChecked, $restEnabled, $rsGateway, $defaultGateway) = @_;

    # GET network adapters data
    my $data = get_network_adapter_data($albApiUrl, $guid);

    # Determine id of network interface $ethtype
    my $ethtype;
    if (defined($data) && defined($data->{'AdapterListString'}) && 
        defined($data->{'AdapterListString'}->{'options'}) &&
        defined($data->{'AdapterListString'}->{'options'}->{'option'}) && 
        (scalar($data->{'AdapterListString'}->{'options'}->{'option'}) > 0)) {
        foreach my $adapter (@{$data->{'AdapterListString'}->{'options'}->{'option'}}) {
            if ($adapter->{'value'} eq $ethName) {
                $ethtype = $adapter->{'id'};
                last;
            }
        }
    }
    if (!defined($ethtype) || ($ethtype eq '')) {
        error("Failed to determine ID of network interface '$ethName' in update_network_adapter()", 1);
    }

    my $options;
    $options->{'id'} = "$id";
    $options->{'ethtype'} = "$ethtype";
    $options->{'address'} = "$address";
    $options->{'mask'} = "$mask";
    $options->{'gateway'} = "$gateway";
    $options->{'desc'} = "$desc";
    $options->{'ethVlan'} = "$ethVlan";
    $options->{'RpFilter'} = "$rpFilter";
    $options->{'webconsoleChecked'} = "$webconsoleChecked";
    $options->{'RestEnabled'} = "$restEnabled";
    if (defined($rsGateway) && ($rsGateway eq 'true')) {
        $options->{'ethFunction'} = "rsgate";
    }
    if (defined($defaultGateway) && ($defaultGateway eq 'true')) {
        $options->{'defaultGateway'} = "true";
    }

    debug("Update network adapter data\n");
    my $path = "POST/1?iAction=4&iType=1";

    my $request = encode_json($options);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in update_network_adapter()", 1);
    }
    my $decoded = decode_json($json);

    debug("Result:\n". $json ."\n");

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update GUI port and certificate failed in update_network_adapter(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



sub create_network_address {
    my ($albApiUrl, $guid, $ethName, $address, $mask, $gateway, $desc, $ethVlan, $rpFilter, $webconsoleChecked, $restEnabled, $rsGateway, $defaultGateway) = @_;

    # GET network adapters data
    my $data = get_network_adapter_data($albApiUrl, $guid);

    # Get number of existing network addresses
    my $address_num = 1;
    if (defined($data) && defined($data->{'ApplianceGrid'}) && defined($data->{'ApplianceGrid'}->{'dataset'}) &&
        defined($data->{'ApplianceGrid'}->{'dataset'}->{'row'}) &&
        (($data->{'ApplianceGrid'}->{'dataset'}->{'row'}) ne '')) {
        my @addresses = @{$data->{'ApplianceGrid'}->{'dataset'}->{'row'}};
        $address_num = scalar(@addresses) + 1;
    }

    my $res = update_network_adapter($albApiUrl, $guid, $address_num, $ethName, $address, $mask, $gateway, $desc, $ethVlan, $rpFilter, $webconsoleChecked, $restEnabled, $rsGateway, $defaultGateway);

    return($res);
}



sub update_network_address {
    my ($albApiUrl, $guid, $ethName, $address, $mask, $gateway, $desc, $ethVlan, $rpFilter, $webconsoleChecked, $restEnabled) = @_;

    # GET network adapters data
    my $data = get_network_adapter_data($albApiUrl, $guid);

    # Get id of the network address to be updated
    my $address_num;
    if (defined($data) && defined($data->{'ApplianceGrid'}) && defined($data->{'ApplianceGrid'}->{'dataset'}) &&
        defined($data->{'ApplianceGrid'}->{'dataset'}->{'row'}) &&
        (($data->{'ApplianceGrid'}->{'dataset'}->{'row'}) ne '')) {
        my @addresses = @{$data->{'ApplianceGrid'}->{'dataset'}->{'row'}};
        foreach my $row (@addresses) {
            if (($row->{'ethtype'} eq $ethName) && 
                ($row->{'address'} eq $address) && ($row->{'mask'} eq $mask)) {
                $address_num = $row->{'id'};
                debug("Network address id: $address_num");
                last; 
            }
        }
    }

    if (!defined($address_num) || ($address_num eq '')) {
        error("Network address '$address/$mask' on network interface '$ethName' not found in update_network_address()", 1);
    }

    my $res = update_network_adapter($albApiUrl, $guid, $address_num, $ethName, $address, $mask, $gateway, $desc, $ethVlan, $rpFilter, $webconsoleChecked, $restEnabled);

    return($res);
}



sub remove_network_address {
    my ($albApiUrl, $guid, $ethName, $address, $mask) = @_;

    # GET network adapters data
    my $data = get_network_adapter_data($albApiUrl, $guid);

    # Get id of the network address to be removed
    my $address_num;
    if (defined($data) && defined($data->{'ApplianceGrid'}) && defined($data->{'ApplianceGrid'}->{'dataset'}) &&
        defined($data->{'ApplianceGrid'}->{'dataset'}->{'row'}) &&
        (($data->{'ApplianceGrid'}->{'dataset'}->{'row'}) ne '')) {
        my @addresses = @{$data->{'ApplianceGrid'}->{'dataset'}->{'row'}};
        foreach my $row (@addresses) {
            if (($row->{'ethtype'} eq $ethName) && 
                ($row->{'address'} eq $address) && ($row->{'mask'} eq $mask)) {
                $address_num = $row->{'id'};
                debug("Network address id: $address_num");
                last; 
            }
        }
    }

    if (!defined($address_num) || ($address_num eq '')) {
        error("Network address '$address/$mask' on network interface '$ethName' not found in remove_network_address()", 1);
    }

    my $options;
    $options->{'id'} = "$address_num";

    debug("Remove network address\n");
    my $path = "POST/1?iAction=2&iType=1";

    my $request = encode_json($options);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in remove_network_address()", 1);
    }
    my $decoded = decode_json($json);

    debug("Result:\n". $json ."\n");

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update GUI port and certificate failed in remove_network_address(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



sub get_logging_config {
    debug("=== In get_logging_config\n");

    my ($albApiUrl, $guid) = @_;
    my $path = "GET/16";

    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_logging_config()", 1);
    }
    my $decoded = decode_json($json);

    debug("$json\n");
    
    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied') &&
        ($decoded->{'StatusText'} ne 'get')) {
        error("ALB API request for get logging page data failed in get_logging_config(): '" . $decoded->{'StatusText'} . "'", 1);
    }
        
    return($decoded);
}



sub update_remote_syslog_server {
    debug("=== In update_remote_syslog_server\n");

    my ($albApiUrl, $guid, 
        $RsysServer1enabled, $RsysLog1IP, $RsysLog1PROTOCOL, $RsysServerPort1, 
        $RsysServer2enabled, $RsysLog2IP, $RsysLog2PROTOCOL, $RsysServerPort2) = @_;

    my $get = get_logging_config($albApiUrl, $guid);
    my $data;

    if (defined($RsysServer1enabled) && ($RsysServer1enabled ne '')) {
        $data->{'RsysServer1enabled'} = "$RsysServer1enabled";
    }
    if (defined($RsysLog1IP) && ($RsysLog1IP ne '')) {
        $data->{'RsysLog1IP'} = $RsysLog1IP;
    }
    if (defined($RsysLog1PROTOCOL) && ($RsysLog1PROTOCOL ne '')) {    
        $data->{'RsysLog1PROTOCOL'} = $RsysLog1PROTOCOL;
    }
    if (defined($RsysServerPort1) && ($RsysServerPort1 ne '')) {
        $data->{'RsysServerPort1'} = "$RsysServerPort1";
    }

    if (defined($RsysServer2enabled) && ($RsysServer2enabled ne '')) {
        $data->{'RsysServer2enabled'} = "$RsysServer2enabled";
    }
    if (defined($RsysLog2IP) && ($RsysLog2IP ne '')) {
        $data->{'RsysLog2IP'} = $RsysLog2IP;
    }
    if (defined($RsysLog2PROTOCOL) && ($RsysLog2PROTOCOL ne '')) {
        $data->{'RsysLog2PROTOCOL'} = $RsysLog2PROTOCOL;
    }
    if (defined($RsysServerPort2) && ($RsysServerPort2 ne '')) {
        $data->{'RsysServerPort2'} = "$RsysServerPort2";
    }

    my $path = "POST/16?iAction=3&iType=1";
    my $request = encode_json($data);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a VS in update_remote_syslog_server()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update remote syslog server failed in update_remote_syslog_server(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);
    
    return($decoded);
}



sub update_remote_log_storage {
    debug("=== In update_remote_log_storage\n");

    my ($albApiUrl, $guid, 
        $RemoteLogStorage, $RemoteLogIP, $RemoteLogShare, 
        $RemoteLogDir, $RemoteLogUser, $RemoteLogPassword) = @_;

    my $get = get_logging_config($albApiUrl, $guid);
    my $data;

    if (defined($RemoteLogStorage) && ($RemoteLogStorage ne '')) {
        $data->{'RemoteLogStorage'} = "$RemoteLogStorage";
    } else {
        $data->{'RemoteLogStorage'} = "0";
    }
    if (defined($RemoteLogIP) && ($RemoteLogIP ne '')) {
        $data->{'RemoteLogIP'} = $RemoteLogIP;
    } else {
        $data->{'RemoteLogIP'} = "";
    }
    if (defined($RemoteLogShare) && ($RemoteLogShare ne '')) {
        $data->{'RemoteLogShare'} = $RemoteLogShare;
    } else {
        $data->{'RemoteLogShare'} = "";
    }
    if (defined($RemoteLogDir) && ($RemoteLogDir ne '')) {
        $data->{'RemoteLogDir'} = $RemoteLogDir;
    } else {
        $data->{'RemoteLogDir'} = "";
    }
    if (defined($RemoteLogUser) && ($RemoteLogUser ne '')) {
        $data->{'RemoteLogUser'} = $RemoteLogUser;
    } else {
        $data->{'RemoteLogUser'} = "";
    }
    if (defined($RemoteLogPassword) && ($RemoteLogPassword ne '')) {
        $data->{'RemoteLogPassword'} = $RemoteLogPassword;
    } else {
        $data->{'RemoteLogPassword'} = "";
    }

    my $path = "POST/16?iAction=2&iType=1";
    my $request = encode_json($data);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a VS in update_remote_log_storage()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update remote log storage failed in update_remote_log_storage(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);
    
    return($decoded);
}



# Get SNMP page data
sub get_snmp_data {
    debug("=== In get_snmp_data\n");

    my ($albApiUrl, $guid) = @_;
    my $path = "GET/22";
    
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_snmp_data()", 1);
    }
    my $decoded = decode_json($json);
            
    debug("$json\n");

    return($decoded);
}



# Security: enable/disable SNMP server
sub configure_snmp {
    debug("=== In configure_snmp\n");

    my ($albApiUrl, $guid, 
        $SNMPV1V2Checked, $SNMPCommunityString, 
        $SNMPV3Checked, $oldPassPhrase, $newPassPhrase, 
        $SNMPLocation, $SNMPContact) = @_;

    # GET SNMP page data
    my $snmp = get_snmp_data($albApiUrl, $guid);

    debug("SNMP data: " . encode_json($snmp) . "\n");

    my $obj;
    if (defined($SNMPV1V2Checked) && ($SNMPV1V2Checked ne '')) {
        $obj->{'SNMPV1V2Checked'} = $SNMPV1V2Checked;
    } else {
        $obj->{'SNMPV1V2Checked'} = $snmp->{'SNMPV1V2Checked'};
    }
    if (defined($SNMPCommunityString) && ($SNMPCommunityString ne '')) {
        $obj->{'SNMPCommunityString'} = $SNMPCommunityString;
    } else {
        $obj->{'SNMPCommunityString'} = $snmp->{'SNMPCommunityString'};
    }
    if (defined($SNMPV3Checked) && ($SNMPV3Checked ne '')) {
        $obj->{'SNMPV3Checked'} = $SNMPV3Checked;
    } else {
        $obj->{'SNMPV3Checked'} = $snmp->{'SNMPV3Checked'};
    }
    if (defined($oldPassPhrase) && ($oldPassPhrase ne '')) {
        $obj->{'oldPassPhrase'} = $oldPassPhrase;
    } else {
        $obj->{'oldPassPhrase'} = '';
    }
    if (defined($newPassPhrase) && ($newPassPhrase ne '')) {
        $obj->{'newPassPhrase'} = $newPassPhrase;
        $obj->{'confirmNewPassPhrase'} = $newPassPhrase;
    } else {
        $obj->{'newPassPhrase'} = '';
        $obj->{'confirmNewPassPhrase'} = '';
    }
    if (defined($SNMPLocation) && ($SNMPLocation ne '')) {
        $obj->{'SNMPLocation'} = $SNMPLocation;
    } else {
        $obj->{'SNMPLocation'} = $snmp->{'SNMPLocation'};
    }
    if (defined($SNMPContact) && ($SNMPContact ne '')) {
        $obj->{'SNMPContact'} = $SNMPContact;
    } else {
        $obj->{'SNMPContact'} = $snmp->{'SNMPContact'};
    }

    # Configure SNMP server
    my $path = "POST/22?iAction=3&iType=1";
    my $request = encode_json($obj);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to configure SNMP server failed in configure_snmp()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to configure SNMP server failed in configure_snmp(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");

    return($decoded);
}



sub get_protocol_settings {
    my ($albApiUrl, $guid) = @_;

    my $path = "GET/25";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_protocol_settings()", 1);
    }

    debug("Result:\n". $json);

    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'get')) {
        error("ALB API request to get network adapter data failed in get_protocol_settings(): '" . 
            $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



# Update SameSite protocol settings
sub update_protocol_settings_samesite {
    my ($albApiUrl, $guid, $sameSite, $secure, $httpOnly) = @_;

    # GET protocol settings
    my $data = get_protocol_settings($albApiUrl, $guid);

    my $options;
    $options->{'SameSite'} = "$sameSite";
    $options->{'Secure'} = "$secure";
    $options->{'HttpOnly'} = "$httpOnly";

    debug("Update SameSite protocol settings\n");
    my $path = "POST/25?iAction=6&iType=1";

    my $request = encode_json($options);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API in update_protocol_settings_samesite()", 1);
    }
    my $decoded = decode_json($json);

    debug("Result:\n". $json ."\n");

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update SameSite protocol settings failed in update_protocol_settings_samesite(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    return($decoded);
}



# Get a first SNAT rule matching the parameters.
# If any of the input parameters are empty, they are not checked while looking for a SNAT rule.
sub get_snat_rule {
    debug("=== In get_snat_rule\n");

    my ($albApiUrl, $guid, $id, $interface, $sourceIp, $sourcePort,
        $destinationIp, $destinationPort, $protocol, 
        $snatToIp, $snatToPort, $notes) = @_;
    my $path = "GET/6";
    my %res_tmp; my $res = \%res_tmp;
    
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in get_snat_rule()", 1);
    }
    my $decoded = decode_json($json);
            
    debug("$json\n");
            
    # Find a SNAT rule
    if (defined($decoded->{'SNATGrid'}->{'dataset'}->{'row'}) &&
       ($decoded->{'SNATGrid'}->{'dataset'}->{'row'} ne "")) {
        my @rules = @{$decoded->{'SNATGrid'}->{'dataset'}->{'row'}};
        if (scalar(@rules) > 0) {
            foreach my $rule (@rules) {
                debug("SNAT rules:\n" . encode_json($rule) . "\n");
            
                my ($idCmp, $interfaceCmp, $sourceIpCmp, $sourcePortCmp,
                    $destinationIpCmp, $destinationPortCmp, $protocolCmp,
                    $snatToIpCmp, $snatToPortCmp, $notesCmp) = ('', '', '', '', '', '', '', '', '', '');
                if (defined($id) && ($id ne '')) {
                    $idCmp = $rule->{'id'};
                } else {
                    $id = '';
                }
                if (defined($interface)) {
                    $interfaceCmp = $rule->{'interface'};
                } else {
                    $interface = '';
                }
                if (defined($sourceIp)) {
                    $sourceIpCmp = $rule->{'sourceip'};
                } else {
                    $sourceIp = '';
                }
                if (defined($sourcePort)) {
                    $sourcePortCmp = $rule->{'sourceport'};
                } else {
                    $sourcePort = '';
                }
                if (defined($destinationIp)) {
                    $destinationIpCmp = $rule->{'destinationip'};
                } else {
                    $destinationIp = '';
                }
                if (defined($destinationPort)) {
                    $destinationPortCmp = $rule->{'destinationport'};
                } else {
                    $destinationPort = '';
                }
                if (defined($protocol)) {
                    $protocolCmp = $rule->{'protocol'};
                } else {
                    $protocol = '';
                }
                if (defined($snatToIp)) {
                    $snatToIpCmp = $rule->{'snattoip'};
                } else {
                    $snatToIp = '';
                }
                if (defined($snatToPort)) {
                    $snatToPortCmp = $rule->{'snattoport'};
                } else {
                    $snatToPort = '';
                }
                if (defined($notes)) {
                    $notesCmp = $rule->{'notes'};
                } else {
                    $notes = '';
                }

                if (($idCmp eq $id) && ($interfaceCmp eq $interface) && ($sourceIpCmp eq $sourceIp) &&
                    ($sourcePortCmp eq $sourcePort) && ($destinationIpCmp eq $destinationIp) && 
                    ($destinationPortCmp eq $destinationPort) && ($protocolCmp eq $protocol) && 
                    ($snatToIpCmp eq $snatToIp) && ($snatToPortCmp eq $snatToPort) && ($notesCmp eq $notes)) {
                    $res = $rule;
                    last;
                }
            }
        }
    }
    return($res);
}



# Update SNAT rule data
sub update_snat_rule {
    debug("=== In update_snat_rule\n");

    my ($albApiUrl, $guid, $rule) = @_;
    my $path;

    if (defined($rule->{'id'}) && ($rule->{'id'} ne '')) {
        # Update SNAT rule
        $path = "POST/6?iAction=5&iType=1";
    } else {
        # Create SNAT rule
        $path = "POST/6?iAction=7&iType=1";
    }

    my $request = encode_json($rule);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to update a SNAT rule in update_snat_rule()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to update a SNAT rule failed in update_snat_rule(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json);

    return($decoded);
}



# Create a SNAT rule
sub create_snat_rule {
    debug("=== In create_snat_rule\n");

    my ($albApiUrl, $guid, $interface, $sourceIp, $sourcePort,
        $destinationIp, $destinationPort, $protocol, 
        $snatToIp, $snatToPort, $notes) = @_;
    my %res_tmp; my $res = \%res_tmp;

    # GET SNAT rules
    my $path = "GET/6";
    debug("curl -s -k -H \"Cookie: GUID=$guid;\" \"$albApiUrl/$path\"\n");
    my $json = alb_api_get($guid, "$albApiUrl/$path");
    if (!$json) {
        error("Failed to connect to ALB API in create_snat_rule()", 1);
    }
    my $decoded = decode_json($json);
    debug("$json\n");

    # Set the SNAT rule data
    debug("Create a SNAT rule\n");
    my $rule;
    $rule->{'id'} = '';
    if (defined($interface)) {
        $rule->{'interface'} = $interface;
    } else {
        $rule->{'interface'} = '';
    }
    if (defined($sourceIp)) {
        $rule->{'sourceip'} = $sourceIp;
    } else {
        $rule->{'sourceip'} = '';
    }
    if (defined($sourcePort)) {
        $rule->{'sourceport'} = $sourcePort;
    } else {
        $rule->{'sourceport'} = '';
    }
    if (defined($destinationIp)) {
        $rule->{'destinationip'} = $destinationIp;
    } else {
        $rule->{'destinationip'} = '';
    }
    if (defined($destinationPort)) {
        $rule->{'destinationport'} = $destinationPort;
    } else {
        $rule->{'destinationport'} = '';
    }
    if (defined($protocol)) {
        $rule->{'protocol'} = $protocol;
    } else {
        $rule->{'protocol'} = '';
    }
    if (defined($snatToIp)) {
        $rule->{'snattoip'} = $snatToIp;
    } else {
        $rule->{'snattoip'} = '';
    }
    if (defined($snatToPort)) {
        $rule->{'snattoport'} = $snatToPort;
    } else {
        $rule->{'snattoport'} = '';
    }
    if (defined($notes)) {
        $rule->{'notes'} = $notes;
    } else {
        $rule->{'notes'} = '';
    }

    debug("SNAT rule:\n" . encode_json($rule) . "\n");
    $decoded = update_snat_rule($albApiUrl, $guid, $rule);

    return($decoded);
}



sub remove_snat_rule {
    debug("=== In remove_snat_rule\n");

    my ($albApiUrl, $guid, $id, $interface, $sourceIp, $sourcePort,
        $destinationIp, $destinationPort, $protocol, 
        $snatToIp, $snatToPort, $notes) = @_;

    # GET SNAT rule
    my $rule = get_snat_rule($albApiUrl, $guid, $id, $interface, $sourceIp, $sourcePort,
                             $destinationIp, $destinationPort, $protocol,
                             $snatToIp, $snatToPort, $notes);
    if (!defined($rule) || !defined($rule->{'id'}) || ($rule->{'id'} eq '')) {
        error("SNAT rule not found in remove_snat_rule()", 1);
    }
    debug("SNAT rule: " . encode_json($rule) . "\n");

    # Remove the SNAT rule
    my $path = "POST/6?iAction=6&iType=1";
    my $del_rule = {'id' => $rule->{'id'}};
    my $request = encode_json($del_rule);

    debug("curl -s -k -H \"Cookie: GUID=$guid;\" -d '$request' \"$albApiUrl/$path\"\n");
    my $json = alb_api_post($guid, "$albApiUrl/$path", $request);
    if (!$json) {
        error("Failed to connect to ALB API to remove a SNAT rule in remove_snat_rule()", 1);
    }
    my $decoded = decode_json($json);

    if (defined($decoded->{'StatusImage'}) && ($decoded->{'StatusText'} ne 'Your changes have been applied')) {
        error("ALB API request to remove a SNAT rule failed in remove_snat_rule(): '" . $decoded->{'StatusText'} . "'", 1);
    }

    debug("Result:\n". $json ."\n");

    return($decoded);
}



# Configure ALB Virtual Services for WAF add-on
sub configure_alb_vs {
    my ($albApiUrl, $guid, $albIp, $albMask, $addonName) = @_;

    create_ssl_cert($albApiUrl, $guid, $SSL_CERT_ID, $VS_ADDR, '2048', '365');

    remove_all_vs($albApiUrl, $guid);

    create_vs($albApiUrl, $guid, "DVWA Server x.x.x.x:8070", $albIp, $albMask, 
              '8070', 'Layer 4', $DVWA_ADDON_NAME, '80', 'Damn Vulnerable Web Application', '');

    create_vs($albApiUrl, $guid, "ZAP Management Access x.x.x.x:8080/zap/", $albIp, $albMask, 
              '8080', 'Layer 4', $ZAP_ADDON_NAME, '8080', 'OWASP ZAP Management', '');

    create_vs($albApiUrl, $guid, "Zed Attack Proxy", $albIp, $albMask, 
              '8090', 'Layer 4', $ZAP_ADDON_NAME, '8090', 'OWASP ZAP Proxy', '');

    create_vs($albApiUrl, $guid, "HTTP WAF Input", $albIp, $albMask, 
              '80', 'Layer 4', $WAF_ADDON_NAME, '80', 'Web Application Firewall Input', '');

    create_vs($albApiUrl, $guid, "HTTPS WAF Input", $albIp, $albMask, 
              '443', 'Layer 4', $WAF_ADDON_NAME, '80', 'Web Application Firewall Input', $SSL_CERT_ID);

    create_vs($albApiUrl, $guid, "WAF Management Access x.x.x.x:88/waf/", $albIp, $albMask, 
              '88', 'Layer 4', $WAF_ADDON_NAME, '88', 'Web Application Firewall Management', '');
}



# Display a text message $msg instead of a login page.
# If $msg is empty, restore the original ALB login page.
sub display_login_message {
    my $msg = $_[0];

    my $index = "/var/www/lighttpd/index.html";    
    my $index_msg = $index.".msg";
    my $index_orig = $index.".orig";

    if ($msg) {
        if (! -f $index_msg) {
            error("Required file $index_msg is missing", 1);
        }

        # Set mesage text in $index_msg file
        open(FILE, $index_msg);
        my @lines = <FILE>;
        close(FILE);
        foreach my $l (@lines) {
            if ($l =~ /<span id="jetnexusALBName"/) {
                $l =~ s/>.*</>$msg</;
            }
        }
        open(FILE, "> $index_msg");
        print(FILE @lines);
        close(FILE);

        # Backup original index.html
        if (! -f $index_orig) {
            system('cp', $index, $index_orig);
        }

        # Replace $index with $index_msg
        system('cp', $index_msg, $index);
    } else {
        if (! -f $index_orig) {
            error("Required file $index_orig is missing", 1);
        }

        # Restore original index.html
        system('cp', $index_orig, $index);
    }
}

