package fingerbank::api;

use JSON;
use URI;
use LWP::UserAgent;
use HTTP::Request;

sub query {
    my ($key, $params) = @_;
    my $logger = Log::Log4perl->get_logger('');                                                                             

    my $ua = LWP::UserAgent->new;
    $ua->timeout(2);   # An interrogate query should not take more than 2 seconds
    my $query_args = encode_json($params);

    my %parameters = ( key => $key );
    my $url = URI->new("https://fingerbank.inverse.ca/api/v1/combinations/interrogate");
    $url->query_form(%parameters);

    my $req = HTTP::Request->new( GET => $url->as_string);
    $req->content_type('application/json');
    $req->content($query_args);

    my $res = $ua->request($req);

    if ( $res->is_success ) {
        my $result = decode_json($res->content);
        $logger->debug("Successfully interrogate upstream Fingerbank project for matching. Got device : ".$result->{device}->{id});
        return $result;
    } else {
        $logger->debug("An error occured while interrogating upstream Fingerbank project: " . $res->status_line);
        return undef;
    }

}

1;

