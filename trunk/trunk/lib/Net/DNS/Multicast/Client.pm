#!/usr/bin/perl

use strict;

package Net::DNS::Multicast::Client;

sub new {
    my $class = shift;
    my $self = { @ARGV };
    bless $self, ref $class || $class;
    return $self;
}

1;
