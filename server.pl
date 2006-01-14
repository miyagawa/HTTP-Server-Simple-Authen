#!/usr/bin/perl -w
use strict;
use lib 'lib';

package MyServer;
use base qw( HTTP::Server::Simple::Authen HTTP::Server::Simple::CGI );

use Authen::Simple::Passwd;
sub authen_handler {
    Authen::Simple::Passwd->new(passwd => '/etc/passwd');
}

MyServer->new->run;

