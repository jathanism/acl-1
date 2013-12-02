#!/usr/bin/perl

## Copyright (C) 2011  Cody Dumont (NWN Corp)
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License
## as published by the Free Software Foundation; either version 2
## of the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
## This script will parse Cisco ACL from a output of the "sh run" command.
## For more details see www.melcara.com
##
## Version 0.05

use strict;
use Getopt::Std;

my %opt;
my $opt = shift;
my $file;
our @first_data;
our @data;
our @names;
my @object_grp;
my $object_grp_ctr = 0;
my $first_data_ctr = 0;
my $cfg_type;
my @acl_grp;
my $acl_grp_ctr = 0;
my $name_ctr = 0;

my @ignored = qw(: PIX interface nameif enable passwd hostname domain-name fixup
          names no logging mtu ip failover pdm arp global nat static
          route timeout aaa-server http snmp-server floodguard telnet ssh
          console terminal aaa !);   ## 10 dec - removed "name" from ignored list

sub get_acl
{
     my $acl = $_[0];
     my @tmp = @first_data;
     my $get_entry = 0;
     my @acl_data;
     foreach (@tmp)
     {

          if ($_ =~ m/access-list/ && $_ =~ $acl && $get_entry == 0)
          {
               $get_entry = 1;
          }
          elsif ($_ =~ m/access-list/ && $_ !~ $acl && $get_entry == 1)
          {
               $get_entry = 0;
               last;
          }
          elsif($get_entry == 1)
          {
               push @acl_data, $_;
          }
     }

     my $line_num = 1;
     foreach (@acl_data)
     {
          my @matches = split / /,$_;
          my %acl_hash;
          $acl_hash{line} = $line_num;
          $line_num++;

          $acl_hash{function} = $matches[1];
          if($matches[1] eq "deny"){splice @matches,2,2}
          $acl_hash{protocol} = $matches[2];
          $acl_hash{orig} = $_;

          if ($matches[3] eq 'any'){ $acl_hash{s_net} = 'any'}
          elsif($matches[3] eq 'host') { $acl_hash{s_net} = "host $matches[4]"}
          elsif($matches[3] =~ m/^\d+\.\d+\.\d+\.\d+$/) { $acl_hash{s_net} = $matches[3];$acl_hash{s_mask} = $matches[4]};

          #set the source PROTOCOL side varibles of the ACL
          if ($matches[5] eq 'eq') { $acl_hash{s_port} = $matches[6]}
          elsif ($matches[5] eq 'range') { $acl_hash{s_port} = "range $matches[6] $matches[7]"};


          #Set the Destination side of the varibles

          if ($matches[4] eq 'any') { $acl_hash{d_net} = 'any'}
          elsif ($matches[5] eq 'any') { $acl_hash{d_net} = 'any'}

          elsif($matches[4] eq 'host') { $acl_hash{d_net} = "host $matches[5]"}
          elsif($matches[5] eq 'host') { $acl_hash{d_net} = "host $matches[6]"}
          elsif($matches[6] eq 'host') { $acl_hash{d_net} = "host $matches[7]"}
          elsif($matches[7] eq 'host') { $acl_hash{d_net} = "host $matches[8]"}
          elsif($matches[8] eq 'host') { $acl_hash{d_net} = "host $matches[9]"}

          #elsif($matches[4] =~ m/^\d+\.\d+\.\d+\.\d+$/) { $acl_hash{d_net} = $matches[4];$acl_hash{d_mask} = $matches[5]}
          elsif($matches[5] =~ m/^\d+\.\d+\.\d+\.\d+$/) { $acl_hash{d_net} = $matches[5];$acl_hash{d_mask} = $matches[6]}
          elsif($matches[6] =~ m/^\d+\.\d+\.\d+\.\d+$/) { $acl_hash{d_net} = $matches[6];$acl_hash{d_mask} = $matches[7]}
          elsif($matches[7] =~ m/^\d+\.\d+\.\d+\.\d+$/) { $acl_hash{d_net} = $matches[7];$acl_hash{d_mask} = $matches[8]}
          elsif($matches[8] =~ m/^\d+\.\d+\.\d+\.\d+$/) { $acl_hash{d_net} = $matches[8];$acl_hash{d_mask} = $matches[9]}


          #set the Dest PROTOCOL side varibles of the ACL
          if ($matches[5] eq 'eq') { $acl_hash{d_port} = $matches[6]}
          elsif ($matches[6] eq 'eq') { $acl_hash{d_port} = $matches[7]}
          elsif ($matches[7] eq 'eq') { $acl_hash{d_port} = $matches[8]}
          elsif ($matches[8] eq 'eq') { $acl_hash{d_port} = $matches[9]}

          elsif ($matches[5] eq 'gt') { $acl_hash{d_port} = "gt $matches[6]"}
          elsif ($matches[6] eq 'gt') { $acl_hash{d_port} = "gt $matches[7]"}
          elsif ($matches[7] eq 'gt') { $acl_hash{d_port} = "gt $matches[8]"}
          elsif ($matches[8] eq 'gt') { $acl_hash{d_port} = "gt $matches[9]"}


          elsif ($matches[5] eq 'range') { $acl_hash{d_port} = "range $matches[6] $matches[7]"}
          elsif ($matches[6] eq 'range') { $acl_hash{d_port} = "range $matches[7] $matches[8]"}
          elsif ($matches[7] eq 'range') { $acl_hash{d_port} = "range $matches[8] $matches[9]"}
          elsif ($matches[8] eq 'range') { $acl_hash{d_port} = "range $matches[9] $matches[10]"}

          if ($acl_hash{function} eq "remark")
          {
               my @tmp = split / /,$_;
               shift @tmp;shift @tmp;
               $acl_hash{protocol} = join " ",@tmp;
          }
          $_ = \%acl_hash;
     }

     return @acl_data;
} # end sub get_acl

sub get_obj_grp
{
     my $var = $_[0];     
     foreach (@object_grp)
     {
          if($_->{name} eq $var)
          {
               return $_;
          }
     }
}

sub find_name
{
     my $var = $_[0];
     my $not_found = 1;
     foreach my $name (@names)
     {
          if ($name->{name} eq $var)
          {
               $var = $name->{ip};
               $not_found = 0;
          }
     }
     if ($not_found == 1)
     {
          $var = "NOT FOUND";
     }
     return $var;
}
print ""; # end of sub routines

getopt("v", \%opt);
if (defined $opt{"v"} || $opt eq "-v" || $opt eq "v")
{
    print "ACL Parser for Cisco IOS, PIX & ASA\n";
    print "DEVELOPED AND OWNED BY Cody Dumont - NWN Security Testing Assessment and Response (STAR)\n";
    print "Licensed to Planet Earth.\n";
    print "I used some code for another tool of this type from James Bly AT mangeek.com\"\n";
    print "http://mangeek.com/portfolio/pixparser.html\n";
    print "Also Anthony <antgoodlife AT gmail.com> contributed by doing some testing and verification\n";
    print "Version Number 0.05 - Jan 2011\n";
    print "\"For Questions Please Contact Cody Dumont \- cody\@melcara.com\"\n";
    exit
}
elsif($opt eq "")
{
    print "The command requires a File Name as a command line argument\n";
    print "acl2csv.pl /foo/bar/old_pix_config.txt\n";
    exit;
}
else
{
    $file = $opt
}

open FILE, $file or die "The file \"$file\" is not a valid filename\"\n";
@first_data = <FILE>;
close FILE;
chomp @first_data;
foreach (@first_data)
{
	$_ =~ tr/\r//d;
}


foreach (@first_data)
{
     if ($_ =~ /version 12/)
     {
          $cfg_type = "IOS";
          last;
     }
     elsif($_ =~ /ASA Version/)
     {
          $cfg_type = "ASA";
          last;
     }
     elsif($_ =~ /PIX Version/)
     {
          $cfg_type = "PIX";
          last;
     }
}

if ($cfg_type eq "IOS")
{
     my @hostname = grep /hostname/,@first_data;
     my @interfaces = grep /interface/,@first_data;
     foreach my $int (@interfaces)
     {
          my %hash;
          my ($a,$b) = split / /, $int;
          $hash{int} = $b;
          my @in_acl;
          my @out_acl;

          $first_data_ctr = 0;
          my @loop_data = @first_data;
          foreach (@loop_data)
          {
               if ($_ eq $int && $_ =~ /[0-9]/)
               {
                    my @tmp = @first_data;
                    @tmp = splice @tmp,$first_data_ctr,30;
                    my $access_group = grep /access-group/,@tmp;

                    if($access_group > 0)
                    {
                         shift @tmp;
                         foreach (@tmp)
                         {
                              if ($_ =~ /interface/)
                              {
                                   last;
                              }
                              elsif($_ =~ /access-group/ && $_ =~ /in/)
                              {
                                   my @t1 = split / /,$_;
                                   $hash{in_acl} = $t1[3];
                                   my @in_acl = get_acl($t1[3]);
                                   $hash{in_acl_entry} = \@in_acl;
                              }
                              elsif($_ =~ /access-group/ && $_ =~ /out/)
                              {
                                   my @t1 = split / /,$_;
                                   $hash{out_acl} = $t1[3];
                                   my @out_acl = get_acl($t1[3]);
                                   $hash{out_acl_entry} = \@out_acl;
                              }
                         } #end foreach temp
                    }# end foreach access group le 0
               } # end thest if interface
               $first_data_ctr++;
          } #nd foreach loop data
          $int = \%hash;
     }# end foreach interfaces

     open FILE, ">$hostname[0]\-output.csv";
     print FILE "INT,ACL NAME,LINE,FUNCTION,PROTOCOL,SOURCE NET,SOUORCE MASK,SOURCE_PORT,DEST NET,DEST MASK,DEST PORT,ORIGINAL\n";
     foreach my $int (@interfaces)
     {
          if ($int->{in_acl} ne "" || $int->{out_acl} ne "")
          {
               my $prefix_in = "$int->{int},$int->{in_acl}";
               #$prefix_in =~ tr/\r//d;
               my $prefix_out = "$int->{int},$int->{out_acl}";
               #$prefix_out =~ tr/\r//d;
               if ($int->{in_acl_entry}->[0] ne "")
               {
                    my @tmp = @{$int->{in_acl_entry}};
                    #chomp @tmp;
                    foreach (@tmp)
                    {
                         
                         if($_->{orig} !~ /remark/)
                         {
                              print FILE "$prefix_in,$_->{line},$_->{function},$_->{protocol},$_->{s_net},$_->{s_mask},$_->{s_port},$_->{d_net},$_->{d_mask},$_->{d_port},$_->{orig}\n";
                         }
                    }
               }

               if ($int->{out_acl_entry}->[0] ne "")
               {
                    my @tmp = @{$int->{out_acl_entry}};


                    foreach (@tmp)
                    {
                         if($_->{orig} !~ /remark/)
                         {
                              print FILE "$prefix_out,$_->{line},$_->{function},$_->{protocol},$_->{s_net},$_->{s_mask},$_->{s_port},$_->{d_net},$_->{d_mask},$_->{d_port},$_->{orig}\n";
                         }
                    }
               }
          }
     }
     close FILE;
     print "compelted\n";
     exit;
}
elsif($cfg_type eq "ASA" || $cfg_type eq "PIX")
{
     my @hostname = grep /hostname/,@first_data;
     @names = grep /^name /, @first_data;
     @object_grp = grep /^object-group /, @first_data;
     @acl_grp = grep /^access-list /, @first_data;
     my $acl_cnt = 0;
     
     foreach my $entry (@names)
     {
          my %tmp;
          my @tmp = split / /,$entry;
          $tmp{name} = $tmp[2];
          $tmp{ip} = $tmp[1];
          $entry = \%tmp;
     }
     
     foreach my $entry (@object_grp)
     {
          my @matches = split / /,$entry;
          my %hash;          
          $hash{type} = $matches[1];
          $hash{name} = $matches[2];
          $hash{protocol} = $matches[3];
          my $obj_ctr = 1;
          my @obj_entry;
          my $obj_name;
          #$first_data_ctr = 0;
          
          foreach(@first_data)
          {
               my @a = split / /,$_;
               if ($a[0] eq "object-group" && $_ eq $entry)
               {
                    $obj_name = $hash{name};
               }
               elsif ($a[0] eq "object-group" && $obj_entry[0] ne "")
               {
                    last;
               }               
               elsif($obj_name eq $hash{name} && $a[1] eq "network-object")
               {
                    my $a = "$a[2] $a[3]";
                    push @obj_entry,$a;
               }
               elsif($obj_name eq $hash{name} && $a[1] eq "service-object")
               {
                    my @tmp_a = @a;
                    shift @tmp_a;
                    shift @tmp_a;
                    my $a = join " ",@tmp_a ;# "$a[2] $a[3] $a[4] $a[5] $a[6]"
                    push @obj_entry,$a;
               }
               elsif($obj_name eq $hash{name} && $a[1] eq "port-object")
               {
                    my $a = "$a[2] $a[3] $a[4]";
                    push @obj_entry,$a;
               }
               elsif($_ =~ 'access-list')
               {
                    last;
               }
               else
               {
                    print "";
               }
          }
          $hash{entries} = \@obj_entry;
          $entry = \%hash;
          print "";
     }
     foreach my $entry (@acl_grp)
     {
          $entry =~ s/\,|\// /g;
          my @matches = split / /,$entry;
          
          if ($cfg_type eq "PIX" && $matches[2] !~ /extended|standard|webtype|remark/)
          {
               my @a = @matches[0..1];
               shift @matches;
               shift @matches;
               my @b = @matches;
               undef @matches;
               push @matches, @a;
               push @matches,"PIX_ACL";
               push @matches, @b;
               print "";
          }
          my %hash;
          if(ref $acl_grp[$acl_cnt-1] eq "HASH" && $acl_grp[$acl_cnt-1]->{original} =~ /remark/)
          {
               my @remark = split / /,$acl_grp[$acl_cnt-1]->{original};
               shift @remark;
               shift @remark;
               shift @remark;
               $hash{remark} = join " ",@remark;
          }
          
          $hash{name} = $matches[1];
          $hash{func} = $matches[3];
          $hash{protocol} = $matches[4];
          $hash{original} = $entry;
          $hash{type} = $matches[2];
          
          my $objgrp_num;
          my @hash_obj_grp;
          
          if($entry =~ /log alerts/)
          {
               $hash{log} = "alerts";
          }
          elsif($entry =~ /log critical/)
          {
               $hash{log} = "critical";
          }
          elsif($entry =~ /log debugging/)
          {
               $hash{log} = "debugging";
          }
          elsif($entry =~ /log disable/)
          {
               $hash{log} = "disable";
          }
          elsif($entry =~ /log emergencies/)
          {
               $hash{log} = "emergencies";
          }
          elsif($entry =~ /log errors/)
          {
               $hash{log} = "errors";
          }
          elsif($entry =~ /log informational/)
          {
               $hash{log} = "informational";
          }
          elsif($entry =~ /log notifications/)
          {
               $hash{log} = "notifications";
          }
          elsif($entry =~ /log warnings/)
          {
               $hash{log} = "warnings";
          }
          elsif($entry =~ /log interval/)
          {
               my $ctr = 0;
               foreach (@matches)
               {
                    if($_ eq "interval")
                    {
                         $hash{'log'} = "interval $matches[$ctr + 1]";
                         last;
                    }
                    ++$ctr; 
               }
          }
          elsif($entry =~ /log/)
          {
               $hash{log} = "log";
          }
          
          if($entry =~ /time-range/)
          {
               my $ctr = 0;
               foreach (@matches)
               {
                    if($_ eq "time-range")
                    {
                         $hash{'time-range'} = "$matches[$ctr + 1]";
                         last;
                    }
                    ++$ctr; 
               }
          }
          
          if($entry =~ /inactive/)
          {
               $hash{inactive} = "YES";
          }
          
          
          if($entry =~ /object-group/)
          {
               my @tmp = grep /object-group/, @matches;
               $objgrp_num = @tmp;
          }
          
          if ($matches[2] eq "webtype")
          {
               if($matches[5] eq "any" && $matches[6]  =~ /eq|gt|lt|neq|range/)
               {
                    $hash{dest_net} = "$matches[5]";
                    $hash{dest_port} = "$matches[6] $matches[7] $matches[8]";
               }
               elsif($matches[7]  =~ /eq|gt|lt|neq|range/)
               {
                    $hash{dest_net} = "$matches[5] $matches[6]";
                    $hash{dest_port} = "$matches[7] $matches[8] $matches[9]";
                    $hash{dest_port} =~ s/log|time-range|inactive//g;
                    
               }
               elsif($matches[4]  =~ /url/)
               {
                    $hash{dest_net} = "$matches[7]";
                    $hash{dest_port} = "$matches[5]";
                    $hash{original} =~ s/  /\/\//;
               }
               
          }
          elsif ($matches[2] eq "standard")
          {
               $hash{dest_net} = "$matches[4] $matches[5]";
               $hash{protocol} = "ip";
          }
          elsif ($objgrp_num == 4)
          {
               if($matches[5] eq "object-group" && $matches[7] eq "object-group" && $matches[9] eq "object-group" && $matches[11] eq "object-group")
               {
                    my $source = get_obj_grp ($matches[6]);
                    my $source_port = get_obj_grp ($matches[8]);
                    my $destination = get_obj_grp ($matches[10]);
                    my $dest_port = get_obj_grp ($matches[12]);
                    
                    foreach my $src (@{$source->{entries}})
                    {
                         foreach my $src_prt (@{$source_port->{entries}})
                         {
                              foreach my $dst (@{$destination->{entries}})
                              {
                                   foreach my $dst_prt (@{$dest_port->{entries}})
                                   {
                                        my %t_hash;
                                        $t_hash{protocol} = "$matches[4]";
                                        $t_hash{source_port} = $src_prt;
                                        $t_hash{dest_port} = $dst_prt;
                                        $t_hash{source_net} = $src;
                                        $t_hash{dest_net} = $dst;
                                        push @hash_obj_grp,\%t_hash;
                                   }
                              }
                         }
                    } # end foreach my $src (@{$source->{entries}})
               }
               else
               {
                    #print "\n\nThe else statement for 4 object group matches-I will exit now\n\n";
                    #exit;
               }
               $hash{objects} = \@hash_obj_grp;
          }
          elsif ($objgrp_num == 3)
          {
               my $protocol = get_obj_grp ($matches[5]);
               my $source = get_obj_grp ($matches[7]);
               my $destination = get_obj_grp ($matches[9]);
               my $source_port = "";
               my $dest_port = "";
               
               if($matches[4] eq "object-group")
               {
                    foreach my $pro (@{$protocol->{entries}})
                    {
                         foreach my $src (@{$source->{entries}})
                         {
                              print "";
                              foreach my $dst (@{$destination->{entries}})
                              {
                                   my %t_hash;
                                   #print "$pro $src $dst\n";
                                   my @tmp = split / /,$pro;
                                   $t_hash{source_net} = $src;
                                   $t_hash{dest_net} = $dst;
                                   $t_hash{protocol} = $tmp[0];
                                   
                                   if($pro =~ /destination eq|gt|lt|neq / && $pro =~ /source eq|gt|lt|neq /)
                                   {
                                        $t_hash{protocol} = $tmp[0];
                                        $t_hash{source_port} = "$tmp[2] $tmp[3]";
                                        $t_hash{dest_port} = "$tmp[5] $tmp[6]";
                                   }
                                   elsif($pro =~ /destination range / && $pro =~ /source range /)
                                   {
                                        $t_hash{protocol} = $tmp[0];
                                        $t_hash{source_port} = "$tmp[2] $tmp[3] $tmp[4]";
                                        $t_hash{dest_port} = "$tmp[6] $tmp[7] $tmp[8]";
                                   }
                                   elsif($pro =~ /source eq|gt|lt|neq /)
                                   {
                                        $t_hash{protocol} = $tmp[0];
                                        $t_hash{source_port} = "$tmp[2] $tmp[3]";
                                   }
                                   elsif($pro =~ /destination eq|gt|lt|neq /)
                                   {
                                        $t_hash{protocol} = $tmp[0];
                                        $t_hash{dest_port} = "$tmp[2] $tmp[3]";
                                   }
                                   elsif($pro =~ /source range /) 
                                   {
                                        $t_hash{protocol} = $tmp[0];
                                        $t_hash{source_port} = "$tmp[2] $tmp[3] $tmp[4]";
                                   }
                                   elsif($pro =~ /destination range /) 
                                   {
                                        $t_hash{protocol} = $tmp[0];
                                        $t_hash{dest_port} = "$tmp[2] $tmp[3] $tmp[4]";
                                   }
                                   push @hash_obj_grp,\%t_hash;
                              }
                         } # end foreach my $dst (@{$destination->{entries}})
                    } # end foreach my $src (@{$source->{entries}})
               } # end if($matches[4] eq "object-group")
               else
               {
                    if($matches[5] eq "object-group" && $matches[7] eq "object-group" && $matches[11] eq "object-group")
                    {
                         $source = get_obj_grp ($matches[6]);
                         $source_port = get_obj_grp ($matches[8]);
                         $destination = "$matches[9] $matches[10]";
                         $dest_port = get_obj_grp ($matches[12]);
                    }
                    elsif($matches[5] eq "object-group" && $matches[7] eq "object-group" && $matches[9] eq "object-group")
                    {
                         $source = get_obj_grp ($matches[6]);
                         my $a = get_obj_grp ($matches[8]);
                         my $b = get_obj_grp ($matches[10]);
                         
                         if($a->{type} eq "service" && $b->{type} eq "network" )
                         {
                              $source_port = $a;
                              $destination = $b;
                              $dest_port = "$matches[11] $matches[12]  $matches[13]";
                         }
                         elsif($a->{type} eq "network" && $b->{type} eq "service")
                         {
                              $dest_port = $b;
                              $destination = $a;
                         }
                         else
                         {
                              #print "\n\n Exit in 3 group match on an else statement - i will exit now\n\n";
                              #exit;
                         }
                    }
                    elsif($matches[5] eq "object-group" && $matches[9] eq "object-group" && $matches[11] eq "object-group")
                    {
                         $source = get_obj_grp ($matches[6]);
                         $source_port = "$matches[7] $matches[8]";
                         $destination = get_obj_grp ($matches[10]);
                         $dest_port = get_obj_grp ($matches[12]);
                    }
                    else
                    {
                         #print "\n\n Exit in 3 group match on an else statement - i will exit now\n\n";
                         #exit;
                    }
                    
                    if(ref $source eq "HASH" && ref $source_port eq "HASH" && ref $dest_port eq "HASH")
                    {
                         foreach my $src (@{$source->{entries}})
                         {
                              foreach my $src_prt (@{$source_port->{entries}})
                              {
                                   foreach my $dst_prt (@{$dest_port->{entries}})
                                   {
                                        my %t_hash;
                                        $t_hash{protocol} = "$matches[4]";
                                        $t_hash{source_port} = $src_prt;
                                        $t_hash{dest_port} = $dst_prt;
                                        $t_hash{source_net} = $src;
                                        $t_hash{dest_net} = "$matches[9] $matches[10]";
                                        push @hash_obj_grp,\%t_hash;
                                   }
                              }
                         } # end foreach my $src (@{$source->{entries}})
                    }
                    elsif(ref $source eq "HASH" && ref $source_port eq "HASH" && ref $destination eq "HASH")
                    {
                         foreach my $src (@{$source->{entries}})
                         {
                              foreach my $src_prt (@{$source_port->{entries}})
                              {
                                   foreach my $dst (@{$destination->{entries}})
                                   {
                                        my %t_hash;
                                        $t_hash{protocol} = "$matches[4]";
                                        $t_hash{source_port} = $src_prt;
                                        $t_hash{dest_port} = $dest_port;
                                        $t_hash{source_net} = $src;
                                        $t_hash{dest_net} = $dst;
                                        push @hash_obj_grp,\%t_hash;
                                   }
                              }
                         } # end foreach my $src (@{$source->{entries}})
                    }
                    elsif(ref $source eq "HASH" && ref $dest_port eq "HASH" && ref $destination eq "HASH")
                    {
                         foreach my $src (@{$source->{entries}})
                         {
                              foreach my $dest_prt (@{$dest_port->{entries}})
                              {
                                   foreach my $dst (@{$destination->{entries}})
                                   {
                                        my %t_hash;
                                        $t_hash{protocol} = "$matches[4]";
                                        $t_hash{source_port} = $source_port;
                                        $t_hash{dest_port} = $dest_prt;
                                        $t_hash{source_net} = $src;
                                        $t_hash{dest_net} = $dst;
                                        push @hash_obj_grp,\%t_hash;
                                   }
                              }
                         } # end foreach my $src (@{$source->{entries}})
                    }
                    else
                    {
                         #print "\n\ntripple object, but not services - fix after send to csv\n\n";;
                         #exit;
                    }
               }
               $hash{objects} = \@hash_obj_grp;
          }
          elsif ($objgrp_num == 2)
          {               
               $hash{protocol} = $matches[4];
               my ($source, $destination, $source_port, $dest_port);
               
               ### SOURCE CHECKS
               
               if ($matches[5] eq "object-group" && $matches[7] eq "range")
               {
                    $source = get_obj_grp ($matches[6]);
                    $source_port = "$matches[7] $matches[8] $matches[9]";
                    $destination = get_obj_grp ($matches[11]);
               }
               elsif ($matches[5] eq "object-group" && $matches[7] =~ /eq|gt|lt|neq/)
               {
                    $source = get_obj_grp ($matches[6]);
                    $source_port = "$matches[7] $matches[8]";
               }
               elsif ($matches[5] eq "object-group" && $matches[7] eq "object-group")
               {
                    my $a = get_obj_grp ($matches[8]);
                    if($a->{type} eq "network")
                    {
                         $destination = $a;
                         if($matches[5] eq "object-group")
                         {
                              $source = get_obj_grp ($matches[6]);
                         }
                         elsif (ref $source ne "HASH")
                         {
                              $source = "$matches[5] $matches[6]";
                         }
                         else
                         {
                              print "";
                         }
                         $dest_port = "$matches[9] $matches[10] $matches[11]"
                    }
                    elsif($a->{type} eq "service")
                    {
                         $source = get_obj_grp ($matches[6]);
                         $source_port = $a;
                         $destination = "$matches[9] $matches[10]";
                         $dest_port = "$matches[11] $matches[12] $matches[13]"
                    }
               }
               elsif ($matches[5] eq "object-group" && $matches[7] !~ /eq|gt|lt|neq/)
               {
                    $source = get_obj_grp ($matches[6]);
               }
               
               #### DESTINATION CHECKS
               
               if ($matches[9] eq "object-group")
               {
                    my $a = get_obj_grp ($matches[10]);
                    if($a->{type} eq "network" && $matches[11] eq "")
                    {
                         $destination = $a;
                    }
                    elsif($a->{type} eq "network" && $matches[11] =~ /eq|gt|lt|neq|range/)
                    {
                         $destination = $a;
                         $dest_port = "$matches[11] $matches[12] $matches[13]";
                    }
                    elsif($a->{type} eq "network" && $matches[11] eq "object-group")
                    {
                         #print "exit 2 group and match 11 eq object\n";
                         #exit;
                    }
                    elsif($a->{type} eq "service")
                    {
                         if($matches[7] eq "object-group")
                         {
                              $destination = get_obj_grp ($matches[8]);
                              $source = "$matches[5] $matches[6]";
                         }
                         elsif($matches[5] eq "any" && $matches[8] eq "any")
                         {
                              $source = $matches[5];
                              $source_port = get_obj_grp ($matches[7]);
                              $destination = $matches[8];
                              $dest_port = $a
                         }
                         else
                         {
                              $destination = "$matches[7] $matches[8]";
                         }
                         $dest_port = $a
                    }
                    else
                    {
                         #print " I am exiting on the 2 object-groups and matches-9 eq network\n\n";
                         #exit;
                    }
               }
               elsif($matches[9] =~ /eq|gt|lt|neq|range/ && $dest_port eq "")
               {
                    #print "\n\nexit at double match9 and dest port empty\n\n";
                    #exit;
               }
               elsif($matches[12] eq "range")
               {
                    $dest_port = "$matches[12] $matches[13] $matches[14]"
               }
               elsif($matches[11] eq "object-group")
               {
                    $dest_port = get_obj_grp ($matches[12]);
                    $destination = "$matches[9] $matches[10]"
               }
               elsif($matches[5] eq "any" && $matches[8] eq "object-group" && $matches[6] eq "object-group")
               {
                    $source = $matches[5];
                    $dest_port = get_obj_grp ($matches[9]);
                    $destination = get_obj_grp ($matches[7]);
               }
               elsif($matches[5] eq "any" && $matches[9] eq "object-group" && $matches[8] eq "any")
               {
                    $source = $matches[5];
                    $source_port = get_obj_grp ($matches[7]);
                    $dest_port = get_obj_grp ($matches[10]);
                    $destination = $matches[8];
               }
               else
               {
                    #print "\n\nDESTINATION LOOP 770 - double object group else has been triggered\n";
                    #print "\n$entry\n\n";
               }
               
               if(ref $source eq "HASH" && ref $source_port eq "HASH")
               {
                    foreach my $src (@{$source->{entries}})
                    {
                         foreach my $obj (@{$source_port->{entries}})
                         {
                              my %t_hash;
                              $t_hash{source_net} = $src;
                              $t_hash{dest_net} = $destination;
                              my @tmp = split / /,$obj;
                              $t_hash{source_port} = "$tmp[0] $tmp[1] $tmp[2]";
                              $t_hash{dest_port} = $dest_port;
                              push @hash_obj_grp,\%t_hash;
                         }
                    }
               }
               elsif(ref $source eq "HASH" && ref $dest_port eq "HASH")
               {
                    foreach my $src (@{$source->{entries}})
                    {
                         foreach my $obj (@{$dest_port->{entries}})
                         {
                              my %t_hash;
                              $t_hash{source_net} = $src;
                              $t_hash{source_port} = $source_port;
                              $t_hash{dest_net} = $destination;
                              my @tmp = split / /,$obj;
                              $t_hash{dest_port} = "$tmp[0] $tmp[1] $tmp[2]";
                              push @hash_obj_grp,\%t_hash;
                         }
                    }
               }
               elsif(ref $destination eq "HASH" && ref $dest_port eq "HASH")
               {
                    foreach my $dst (@{$destination->{entries}})
                    {
                         foreach my $obj (@{$dest_port->{entries}})
                         {
                              my %t_hash;
                              $t_hash{source_net} = $source;
                              $t_hash{dest_net} = $dst;
                              my @tmp = split / /,$obj;
                              $t_hash{dest_port} = "$tmp[0] $tmp[1] $tmp[2]";
                              push @hash_obj_grp,\%t_hash;
                         }
                    }
               }
               elsif(ref $destination eq "HASH" && ref $source eq "HASH" && $matches[7] =~ /eq|gt|lt|neq/) # should be last in the list for testing
               {
                    foreach my $dst (@{$destination->{entries}})
                    {
                         foreach my $src (@{$source->{entries}})
                         {
                              my %t_hash;
                              $t_hash{source_net} = $src;
                              $t_hash{dest_net} = $dst;
                              $t_hash{source_port} = "$matches[7] $matches[8]";
                              $t_hash{dest_port} = "$matches[11] $matches[12] $matches[13]";
                              push @hash_obj_grp,\%t_hash;
                         }
                    }
               }
               elsif(ref $destination eq "HASH" && ref $source eq "HASH" && $matches[7] eq "range") # should be last in the list for testing
               {
                    foreach my $dst (@{$destination->{entries}})
                    {
                         foreach my $src (@{$source->{entries}})
                         {
                              my %t_hash;
                              $t_hash{source_net} = $src;
                              $t_hash{dest_net} = $dst;
                              $t_hash{source_port} = "$matches[7] $matches[8] $matches[9]";
                              $t_hash{dest_port} = "$matches[12] $matches[13] $matches[14]";
                              push @hash_obj_grp,\%t_hash;
                         }
                    }
               }
               elsif(ref $destination eq "HASH" && ref $source eq "HASH") # should be last in the list for testing
               {
                    foreach my $dst (@{$destination->{entries}})
                    {
                         foreach my $src (@{$source->{entries}})
                         {
                              my %t_hash;
                              $t_hash{source_net} = $src;
                              $t_hash{dest_net} = $dst;
                              $t_hash{dest_port} = $dest_port;
                              push @hash_obj_grp,\%t_hash;
                         }
                    }
               }
               elsif(ref $destination eq "HASH" && ref $source eq "HASH") # should be last in the list for testing
               {
                    foreach my $dst (@{$destination->{entries}})
                    {
                         foreach my $src (@{$source->{entries}})
                         {
                              my %t_hash;
                              $t_hash{source_net} = $src;
                              $t_hash{dest_net} = $dst;
                              $t_hash{dest_port} = $dest_port;
                              push @hash_obj_grp,\%t_hash;
                         }
                    }
               }
               elsif(ref $dest_port eq "HASH" && ref $source_port eq "HASH") 
               {
                    foreach my $dst (@{$dest_port->{entries}})
                    {
                         foreach my $src (@{$source_port->{entries}})
                         {
                              my %t_hash;
                              $t_hash{source_net} = $source;
                              $t_hash{source_port} = $src;
                              $t_hash{dest_net} = $destination;
                              $t_hash{dest_port} = $dst;
                              push @hash_obj_grp,\%t_hash;
                         }
                    }
               }
               else
               {
                    #print "the double object HASH else has been triggered";
                    #exit;
               }
               $hash{objects} = \@hash_obj_grp;
          }
          elsif ($objgrp_num == 1)
          {
               $hash{protocol} = $matches[4];
               my ($source, $destination, $source_port, $dest_port, $protocol);
               
               if ($matches[5] eq "object-group" && $matches[7] eq "any")
               {
                    $source = get_obj_grp ($matches[6]);
                    $destination = "any";
                    $dest_port = "$matches[8] $matches[9] $matches[10]";
               }
               elsif ($matches[5] eq "object-group" && $matches[7] =~ /range/)
               {
                    $source = get_obj_grp ($matches[6]);
                    $source_port = "$matches[7] $matches[8] $matches[9]";
                    $destination = "$matches[10] $matches[11]";
                    $dest_port = "$matches[12] $matches[13] $matches[14]";
               }
               elsif ($matches[5] eq "object-group" && $matches[7] =~ /eq|gt|lt|neq/)
               {
                    $source = get_obj_grp ($matches[6]);
                    $source_port = "$matches[7] $matches[8]";
                    $destination = "$matches[9] $matches[10]";
                    $dest_port = "$matches[11] $matches[12] $matches[13]";
               }
               elsif ($matches[5] eq "object-group" && $matches[9] =~ /eq|gt|lt|neq/)
               {
                    $source = get_obj_grp ($matches[6]);
                    $destination = "$matches[7] $matches[8]";
                    $dest_port = "$matches[9] $matches[10] $matches[11]";
               }
               elsif ($matches[5] eq "object-group" && $matches[8] !~ /eq|gt|lt|neq/)
               {
                    $source = get_obj_grp ($matches[6]);
                    $destination = "$matches[7] $matches[8]";
                    $dest_port = "$matches[9] $matches[10] $matches[11]";
               }
               elsif ($matches[5] eq "object-group" && $matches[8] !~ /range/)
               {
                    $source = get_obj_grp ($matches[6]);
                    $destination = "$matches[7] $matches[8]";
               }
               elsif ($matches[7] eq "object-group")
               {
                    my $a = get_obj_grp ($matches[8]);
                    if($a->{type} eq "network")
                    {
                         $source = "$matches[5] $matches[6]";
                         $source_port = "";
                         $destination = $a;
                         $dest_port = "$matches[9] $matches[10] $matches[11]";
                    }
                    elsif($a->{type} eq "service" && $matches[6] eq "any" && $matches[5] eq "any")
                    {
                         $source = "$matches[5]";
                         $source_port = "";
                         $destination = $matches[6];
                         $dest_port = $a;
                    }
                    elsif($a->{type} eq "service" && $matches[9] eq "any") # should at the end
                    {
                         $source = "$matches[5] $matches[6]";
                         $source_port = "";
                         $destination = $matches[9];
                         $dest_port = $a;
                    }
                    else
                    {
                         #print " Exit - matches 7 single object group\n";exit;
                    }
               }
               elsif ($matches[9] eq "object-group")
               {
                    $source = "$matches[5] $matches[6]";
                    $destination = "$matches[7] $matches[8]";
                    $dest_port = get_obj_grp ($matches[10]);
               }
               elsif ($matches[8] eq "object-group" && $matches[7] eq "any")
               {
                    $source = "$matches[5] $matches[6]";
                    $destination = "$matches[7]";
                    $dest_port = get_obj_grp ($matches[9]);
               }
               elsif ($matches[8] eq "object-group" && $matches[5] eq "any")
               {
                    $source = "$matches[5]";
                    $destination = "$matches[6] $matches[7]";
                    $dest_port = get_obj_grp ($matches[9]);
               }
               elsif ($matches[6] eq "object-group" && $matches[5] eq "any")
               {
                    $source = "$matches[5]";
                    $destination = get_obj_grp ($matches[7]);
               }
               elsif ($matches[4] eq "object-group" && $matches[8] eq "any")
               {
                    $protocol = get_obj_grp ($matches[5]);
                    $source = "$matches[6] $matches[7]";
                    $destination = $matches[8];
               }
               elsif ($matches[4] eq "object-group" && $matches[6] eq "any" && $matches[7] eq "any")
               {
                    $protocol = get_obj_grp ($matches[5]);
                    $source = "$matches[6]";
                    $destination = $matches[7];
               }
               elsif ($matches[10] eq "object-group" && $matches[5] eq "any" && $matches[9] eq "any")
               {
                    $protocol = $matches[4];
                    $source = $matches[5];
                    $source_port = "$matches[6] $matches[7] $matches[8]";
                    $destination = $matches[9];
                    $dest_port = get_obj_grp ($matches[11]);
               }
               else
               {
                    #print "Else statement for single object group\n";
                    #exit;
               }
               
               if(ref $source eq "HASH" && $matches[7] eq "any")
               {
                    foreach my $src (@{$source->{entries}})
                    {
                         my %t_hash;
                         $t_hash{source_net} = $src;
                         $t_hash{dest_net} = "any";
                         $t_hash{dest_port} = $dest_port;
                         push @hash_obj_grp,\%t_hash;
                    }
               }
               elsif(ref $source eq "HASH" && $matches[8] !~ /eq|gt|lt|neq/)
               {
                    foreach my $src (@{$source->{entries}})
                    {
                         my %t_hash;
                         $t_hash{source_net} = $src;
                         $t_hash{source_port} = $source_port;
                         $t_hash{dest_net} = $destination;
                         $t_hash{dest_port} = $dest_port;
                         push @hash_obj_grp,\%t_hash;
                    }
               }
               elsif (ref $source eq "HASH" && $matches[7] !~ /eq|gt|lt|neq/)
               {
                    foreach my $src (@{$source->{entries}})
                    {
                         my %t_hash;
                         $t_hash{source_net} = $src;
                         $t_hash{source_port} = $source_port;
                         $t_hash{dest_net} = $destination;
                         $t_hash{dest_port} = $dest_port;
                         push @hash_obj_grp,\%t_hash;
                    }
               }
               elsif (ref $protocol eq "HASH")
               {
                    foreach my $pro (@{$protocol->{entries}})
                    {
                         my %t_hash;
                         $t_hash{dest_net} = $destination;
                         $t_hash{source_net} = $source;
                         my @tmp = split / /,$pro;
                         
                         if($pro =~ /destination eq|gt|lt|neq / && $pro =~ /source eq|gt|lt|neq /)
                         {
                              $t_hash{protocol} = $tmp[0];
                              $t_hash{source_port} = "$tmp[2] $tmp[3]";
                              $t_hash{dest_port} = "$tmp[5] $tmp[6]";
                         }
                         elsif($pro =~ /destination range / && $pro =~ /source range /)
                         {
                              $t_hash{protocol} = $tmp[0];
                              $t_hash{source_port} = "$tmp[2] $tmp[3] $tmp[4]";
                              $t_hash{dest_port} = "$tmp[6] $tmp[7] $tmp[8]";
                         }
                         elsif($pro =~ /source eq|gt|lt|neq /)
                         {
                              $t_hash{protocol} = $tmp[0];
                              $t_hash{source_port} = "$tmp[2] $tmp[3]";
                         }
                         elsif($pro =~ /destination eq|gt|lt|neq /)
                         {
                              $t_hash{protocol} = $tmp[0];
                              $t_hash{dest_port} = "$tmp[2] $tmp[3]";
                         }
                         elsif($pro =~ /source range /) 
                         {
                              $t_hash{protocol} = $tmp[0];
                              $t_hash{source_port} = "$tmp[2] $tmp[3] $tmp[4]";
                         }
                         elsif($pro =~ /destination range /) 
                         {
                              $t_hash{protocol} = $tmp[0];
                              $t_hash{dest_port} = "$tmp[2] $tmp[3] $tmp[4]";
                         }
                         elsif($pro =~ /tcp|udp/) 
                         {
                              $t_hash{protocol} = $tmp[0];
                              $t_hash{dest_port} = "$tmp[2] $tmp[3] $tmp[4]";
                         }
                         else
                         {
                              $t_hash{protocol} = $tmp[0];
                         }
                         push @hash_obj_grp,\%t_hash;
                    }
               }
               elsif (ref $destination eq "HASH") # removed - && $matches[9] =~ /eq|gt|lt|neq/ - should be last line
               {
                    foreach my $dst (@{$destination->{entries}})
                    {
                         my %t_hash;
                         $t_hash{dest_net} = $dst;
                         $t_hash{source_port} = $source_port;
                         $t_hash{source_net} = $source;
                         $t_hash{dest_port} = $dest_port;
                         push @hash_obj_grp,\%t_hash;
                    }
               }
               elsif (ref $dest_port eq "HASH") # removed - && $matches[9] =~ /eq|gt|lt|neq/ - should be last line
               {
                    foreach my $dst (@{$dest_port->{entries}})
                    {
                         my %t_hash;
                         $t_hash{dest_net} = $destination;
                         $t_hash{source_port} = $source_port;
                         $t_hash{source_net} = $source;
                         $t_hash{dest_port} = $dst;
                         push @hash_obj_grp,\%t_hash;
                    }
               }
               else
               {
                    #print "else for t_hash on single - exiting";
                    #exit;
               }
               
               $hash{objects} = \@hash_obj_grp;
               print "";
          }
          else
          {     
               if ($entry =~ /any/)
               {
                    my @tmp = grep /any/, @matches;
                    my $any_cnt = @tmp;
                    undef @tmp;
                    
                    if($any_cnt == 2)
                    {
                         if($matches[5] eq "any" && $matches[6] eq "any" && $matches[7] =~ /eq|gt|lt|neq|range/)
                         {
                              $hash{protocol} = "$matches[4]";
                              $hash{source_net} = "$matches[5]";
                              $hash{source_port} = "";
                              $hash{dest_net} = "$matches[6]";
                              $hash{dest_port} = "$matches[7] $matches[8] $matches[9]";
                         }
                         elsif($matches[5] eq "any" && $matches[8] eq "any")
                         {
                              $hash{protocol} = "$matches[4]";
                              $hash{source_net} = "$matches[5]";
                              $hash{source_port} = "$matches[6] $matches[7]";
                              $hash{dest_net} = "$matches[8]";
                              $hash{dest_port} = "$matches[9] $matches[10] $matches[11]";
                         }
                         elsif($matches[5] eq "any" && $matches[9] eq "any" && $matches[6] eq "range")
                         {
                              $hash{protocol} = "$matches[4]";
                              $hash{source_net} = "$matches[5]";
                              $hash{source_port} = "$matches[6] $matches[7] $matches[8]";
                              $hash{dest_net} = "$matches[9]";
                              $hash{dest_port} = "$matches[10] $matches[11] $matches[12]";
                         }
                         else
                         {
                              $hash{protocol} = "$matches[4]";
                              $hash{source_net} = "$matches[5]";
                              $hash{source_port} = "";
                              $hash{dest_net} = "$matches[6]";
                              $hash{dest_port} = "";
                         } # end else for double ANY detail
                    }
                    else
                    {
                         if($matches[9] eq "any" && $matches[7] =~ /eq|gt|lt|neq/) 
                         {
                              $hash{protocol} = "$matches[4]";
                              $hash{source_net} = "$matches[5] $matches[6]";
                              $hash{source_port} = "$matches[7] $matches[8]";
                              $hash{dest_net} = "$matches[9]";
                              $hash{dest_port} = "$matches[10] $matches[11] $matches[12]";
                         }
                         elsif($matches[10] eq "any" && $matches[7] =~ /range/) 
                         {
                              $hash{protocol} = "$matches[4]";
                              $hash{source_net} = "$matches[5] $matches[6]";
                              $hash{source_port} = "$matches[7] $matches[8] $matches[9]";
                              $hash{dest_net} = "$matches[10]";
                              $hash{dest_port} = "$matches[11] $matches[12] $matches[13]";
                         }
                         elsif($matches[5] eq "any" && $matches[8] =~ /eq|gt|lt|neq|range/) 
                         {
                              $hash{protocol} = "$matches[4]";
                              $hash{source_net} = "$matches[5]";
                              $hash{source_port} = "";
                              $hash{dest_net} = "$matches[6] $matches[7]";
                              $hash{dest_port} = "$matches[8] $matches[9] $matches[10]";
                         }
                         elsif($matches[5] eq "any" && $matches[6] =~ /eq|gt|lt|neq/) 
                         {
                              $hash{protocol} = "$matches[4]";
                              $hash{source_net} = "$matches[5]";
                              $hash{source_port} = "$matches[6] $matches[7]";
                              $hash{dest_net} = "$matches[8] $matches[9]";
                              $hash{dest_port} = "$matches[10] $matches[11] $matches[12]";
                         }
                         elsif($matches[5] eq "any" && $matches[6] =~ /range/) 
                         {
                              $hash{protocol} = "$matches[4]";
                              $hash{source_net} = "$matches[5]";
                              $hash{source_port} = "$matches[6] $matches[7] $matches[8]";
                              $hash{dest_net} = "$matches[9] $matches[10]";
                              $hash{dest_port} = "$matches[11] $matches[12] $matches[13]";
                         }
                         elsif($matches[7] eq "any")  # this should be next to last
                         {
                              $hash{protocol} = "$matches[4]";
                              $hash{source_net} = "$matches[5] $matches[6]";
                              $hash{source_port} = "";
                              $hash{dest_net} = "$matches[7]";
                              $hash{dest_port} = "$matches[8] $matches[9] $matches[10]";
                         }
                         else
                         {
                              print "";
                              $hash{protocol} = "$matches[4]";
                              $hash{source_net} = "$matches[5]";
                              $hash{dest_net} = "$matches[6] $matches[7]";
                         }
                    }# end else for single ANY
                    print "";
               }
               else
               {
                    if($matches[9] =~ /eq|gt|lt|neq/)
                    {                    
                         $hash{protocol} = "$matches[4]";
                         $hash{source_port} = "";
                         $hash{dest_port} = "$matches[9] $matches[10]";
                         $hash{source_net} = "$matches[5] $matches[6]";
                         $hash{dest_net} = "$matches[7] $matches[8]";
                    }
                    elsif($matches[9] =~ /range/)
                    {                    
                         $hash{protocol} = "$matches[4]";
                         $hash{source_port} = "";
                         $hash{dest_port} = "$matches[9] $matches[10] $matches[11]";
                         $hash{source_net} = "$matches[5] $matches[6]";
                         $hash{dest_net} = "$matches[7] $matches[8]";
                    }
                    elsif($matches[8] =~ /range/)
                    {
                         #print "no object - matches 8 eq range";exit;
                    }
                    elsif($matches[7] =~ /range/)
                    {
                         $hash{protocol} = "$matches[4]";
                         $hash{source_port} = "$matches[7] $matches[8] $matches[9]";
                         $hash{dest_port} = "$matches[12] $matches[13]  $matches[14]";
                         $hash{source_net} = "$matches[5] $matches[6]";
                         $hash{dest_net} = "$matches[10] $matches[11]";
                    }
                    elsif($matches[8] =~ /eq|gt|lt|neq/)
                    {                    
                         $hash{protocol} = "$matches[4]";
                         $hash{source_port} = "";
                         $hash{dest_port} = "$matches[9] $matches[10]";
                         $hash{source_net} = "$matches[5]";
                         $hash{dest_net} = "$matches[6] $matches[7]";
                    }
                    elsif($matches[7] =~ /eq|gt|lt|neq/)
                    {                    
                         $hash{protocol} = "$matches[4]";
                         $hash{source_net} = "$matches[5] $matches[6]";
                         $hash{source_port} = "$matches[7] $matches[8]";
                         $hash{dest_net} = "$matches[9] $matches[10]";
                         $hash{dest_port} = "$matches[11] $matches[12] $matches[13]";
                    }
                    else
                    {
                         $hash{protocol} = "$matches[4]";
                         $hash{source_net} = "$matches[5] $matches[6]";
                         $hash{dest_net} = "$matches[7] $matches[8]";
                    }
               
               } # end else for the any statement
          } # end else for no object-group
          $entry = \%hash;
          ++$acl_cnt;
     }
     
     my @host = split / /,$hostname[0];
     open FILE, ">$host[1]\-output.csv";
     #print FILE "NAME,LINE,TYPE,FUNCTION,PROTOCOL,SOURCE NET,SOURCE_PORT,DEST NET,DEST PORT,TIME,INACTIVE,LOG,REMARK,ORIGINAL\n";
     my $acl_name_var;
     my $acl_name_ctr = 1;
     foreach my $entry (@acl_grp)
     {
          my $acl = $entry->{name};
          if($acl_name_var eq "")
          {
               $acl_name_var = $acl;
          }
          elsif($acl eq $acl_name_var)
          {
               ++$acl_name_ctr
          }
          elsif($acl ne $acl_name_var)
          {
               $acl_name_var = $entry->{name};
               $acl_name_ctr = 1;
          }
          
          if($entry->{original} !~ /remark/)
          {
               if(ref $entry->{objects} eq "ARRAY")
               {
                    foreach my $obj (@{$entry->{objects}})
                    {
                         $obj->{dest_port} =~ s/inactive//;
                         if (exists $obj->{protocol})
                         {
                              $entry->{protocol} = $obj->{protocol};
                         }
                         print FILE "$entry->{name},$acl_name_ctr,$entry->{type},$entry->{func},$entry->{protocol},$obj->{source_net},$obj->{source_port},$obj->{dest_net},$obj->{dest_port},$entry->{'time-range'},$entry->{inactive},$entry->{log},$entry->{remark},$entry->{original}\n";
                    }
               }
               else
               {
                    $entry->{dest_port} =~ s/inactive//;
                    print FILE "$entry->{name},$acl_name_ctr,$entry->{type},$entry->{func},$entry->{protocol},$entry->{source_net},$entry->{source_port},$entry->{dest_net},$entry->{dest_port},$entry->{'time-range'},$entry->{inactive},$entry->{log},$entry->{remark},$entry->{original}\n";
               }
          }
     }
     close FILE;
     print "completed\n";
} # end elsif pix and ASA
else
{
     print "I could not determin the config type Please review file\n";
     exit;
}
