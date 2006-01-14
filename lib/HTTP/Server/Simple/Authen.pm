package HTTP::Server::Simple::Authen;

use strict;
our $VERSION = '0.01';

use Carp;
use MIME::Base64;
use NEXT;

sub authenticate {
    my $self = shift;
    my($cgi) = @_;
    if (($ENV{HTTP_AUTHORIZATION} || '') =~ /^Basic (.*?)$/) {
        my $credential = $1;
        my($user, $pass) = split /:/, MIME::Base64::decode($1);
        return $self->authen_handler->authenticate($user || '', $pass || '')
            && $self->authorize_user($user);
    }

    return;
}

sub needs_authen { 1 }
sub authen_realm { "Authorized area" }
sub authorize_user { 1 }

sub authen_handler {
    my $class = ref(shift);
    Carp::croak("You have to override $class\::authen_handler to return Authen::Simple object");
}

sub handle_request {
    my $self = shift;
    if ($self->needs_authen(@_) && ! $self->authenticate(@_)) {
        my $realm = $self->authen_realm();
        print "HTTP/1.0 401\r\n";
        print qq(WWW-Authenticate: Basic realm="$realm"\r\n\r\n);
        print "Authentication required.";
    } else {
        $self->NEXT::handle_request(@_);
    }
}

1;
__END__

=head1 NAME

HTTP::Server::Simple::Authen - Authentication plugin for HTTP::Server::Simple

=head1 SYNOPSIS

  package MyServer;
  use base qw( HTTP::Server::Simple::Authen HTTP::Server::Simple::CGI);

  use Authen::Simple::Passwd;
  sub authen_handler {
      Authen::Simple::Passwd->new(passwd => '/etc/passwd');
  }

  MyServer->new->run();

=head1 DESCRIPTION

HTTP::Server::Simple::Authen is an HTTP::Server::Simple plugin to
allow HTTP authentication. Authentication scheme is pluggable and you
can use whatever Authentication protocol that Authen::Simple supports.

=head1 METHODS

Your subclass has to override following methods to implement HTTP
authentication.

=over 4

=item authen_handler

Should return a valid Authen::Simple instance to authenticate HTTP
request (Required).

=item authen_realm

Returns a string for Authentication realm to be shown in the browser's
dialog box. Defaults to 'Authorized area'.

=item needs_authen

Returns true if the request needs authentication. Takes C<$cgi>
parameter as parameter. Default to return 1 (which means all the
requests should be authenticated).

For example, you can use the following code to authenticate URL under
C</foo/>.

  sub needs_authen {
      my($self, $cgi) = @_;
      return $cgi->path_info =~ m!/foo/!;
  }

=item authorize_user

Returns true if you allow authenticated user to access the
content. Takes username as a parameter. By default it always returns
true, which means the same thing with Apache's C<Require valid-user>.

The following code means it only authorizes usernames with 8 chars
long.

  sub authorize_user {
      my($self, $username) = @_;
      return length($username) == 8;
  }

=back

=head1 AUTHOR

Tatsuhiko Miyagawa E<lt>miyagawa@bulknews.netE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

L<HTTP::Server::Simple>, L<Authen::Simple>

=cut
