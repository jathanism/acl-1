#!/usr/bin/perl
use strict;
use Getopt::Std;

my %opt;
my $opt = shift;

my $file;
our @first_data;
our @data;
our @names;

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
    print "I used some code for another tool of this type from James Bly @  mangeek.com\"\n";
    print "http://mangeek.com/portfolio/pixparser.html";
    print "Version Number 0.02 - Dev 2010\n";
    print "\"For Questions Please Contact Cody Dumont \- cody\@melcara.com\"\n";
    exit
}
elsif($opt eq "")
{
    print "The command requires a File Name as a command line argument\n";
    print "acl2csv.pl c\:\\old_pix_config.txt\n";
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

my @object_grp;
my $object_grp_ctr = 0;
my $first_data_ctr = 0;
my $cfg_type;
my @acl_grp;
my $acl_grp_ctr = 0;
my $name_ctr = 0;

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

     #open FILE, ">$hostname[0]\-output.csv";
     open FILE, ">output.csv";

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
elsif($cfg_type eq "ASA")
{
     my @hostname = grep /hostname/,@first_data;
     @names = grep /^name /, @first_data;
     @object_grp = grep /^object-group /, @first_data;
     @acl_grp = grep /^access-list /, @first_data;
     
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
                    my $a = "$a[2] $a[3] $a[4] $a[5]";
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
          my @matches = split / /,$entry;
          my %hash;
          
          #print "\nNOTE TO CODY - ADD IN CODE FOR REMARKS\n";
          
          $hash{name} = $matches[1];
          $hash{func} = $matches[3];
          $hash{protocol} = $matches[4];
          $hash{original} = $entry;
          
          
          #  Source NET
          if ($matches[5] eq 'any'){$hash{source_net} = 'any'}
          elsif($matches[5] eq 'host')
          {
               if ($matches[6] =~ m/^\d+\.\d+\.\d+\.\d+$/)
               {
                    $hash{source_net} = "host $matches[8]"
               }
               else
               {
                    my $a = find_name($matches[6]);$hash{source_net} = "host $a"
               }
          }
          elsif($matches[5] =~ m/^\d+\.\d+\.\d+\.\d+$/){$hash{source_net} = "$matches[5] $matches[6]"}
          elsif($matches[5] eq "object-group"){$hash{source_net} = "$matches[5] $matches[6]"}
          elsif($matches[2] =~ /remark/) { print "";}
          else{my $a = find_name($matches[5]);$hash{source_net} = "$a $matches[6]"}
          
          if ($hash{source_net} eq "")
          {
               print "";
          }
          
          # set the source PROTOCOL side varibles of the ACL
          if ($matches[7] eq 'eq') { $hash{source_port} = $matches[8]}
          elsif ($matches[6] eq 'eq') { $hash{source_port} = $matches[7]}
          elsif($matches[2] =~ /remark/) { print "";}
          elsif ($matches[6] eq "object-group")
          {
               print "THEIS IS AN OBJECT GROUP IN THE SOURCE";
               exit;
          }
          
          # Set the Destination side of the varibles
          if ($matches[6] eq 'any') { $hash{dest_net} = 'any'}
          elsif($matches[7] eq 'object-group'){$hash{dest_net} = "$matches[7] $matches[8]"}
          elsif($matches[7] eq 'any') { $hash{dest_net} = 'any'}
          elsif($matches[6] eq 'host')
          {
               $hash{dest_net} = "host $matches[7]"
          }
          elsif($matches[7] eq 'host')
          {
               if ($matches[8] =~ m/^\d+\.\d+\.\d+\.\d+$/)
               {
                    $hash{dest_net} = "host $matches[8]"
               }
               else
               {
                    my $a = find_name($matches[8]);$hash{dest_net} = "host $a"
               }
          }
          elsif($matches[9] eq 'host')
          {
               if ($matches[10] =~ m/^\d+\.\d+\.\d+\.\d+$/)
               {
                    $hash{dest_net} = "host $matches[10]"
               }
               else
               {
                    my $a = find_name($matches[10]);$hash{dest_net} = "host $a"
               }
          }
          elsif($matches[8] eq 'host')
          {
               if ($matches[9] =~ m/^\d+\.\d+\.\d+\.\d+$/)
               {
                    $hash{dest_net} = "host $matches[9]"
               }
               else
               {
                    my $a = find_name($matches[9]);$hash{dest_net} = "host $a"
               }
          }
          elsif($matches[6] =~ m/^\d+\.\d+\.\d+\.\d+$/)
          {
               $hash{dest_net} = "$matches[6] $matches[7]"
          }
          elsif($matches[7] =~ m/^\d+\.\d+\.\d+\.\d+$/)
          {
               $hash{dest_net} = "$matches[7] $matches[8]"
          }
          elsif($matches[2] =~ /remark/) { print "";}
          else{my $a = find_name($matches[7]);$hash{source_net} = "$a $matches[8]"}
          
          # set the Dest PROTOCOL side varibles of the ACL
          if ($matches[8] eq 'eq') { $hash{dest_port} = $matches[9]}
          elsif($matches[2] =~ /remark/) { print "";}
          elsif ($matches[9] eq 'eq') { $hash{dest_port} = $matches[10]}
          elsif ($matches[11] eq 'eq') { $hash{dest_port} = $matches[12]}
          elsif ($matches[10] eq 'eq') { $hash{dest_port} = $matches[11]}
          elsif ($matches[11] eq 'gt') { $hash{dest_port} = "gt $matches[12]"}
          elsif ($matches[8] eq 'range') { $hash{dest_port} = "range $matches[9] $matches[10]"}
          elsif ($matches[9] eq 'range') { $hash{dest_port} = "range $matches[10] $matches[11]"}
          elsif ($matches[6] eq 'any' && $matches[7] eq "eq") { $hash{dest_port} = $matches[8]}
          elsif ($matches[6] eq 'any' && $matches[7] =~ /./) { $hash{dest_port} = $matches[7]}
          elsif($matches[8] eq 'object-group') { $hash{dest_port} = "object-group $matches[9]"}
          $entry = \%hash;
     }
     

     #open FILE, ">$hostname[0]\-output.csv";
     open FILE, ">output.csv";

     print FILE "NAME,LINE,FUNCTION,PROTOCOL,SOURCE NET,SOURCE_PORT,DEST NET,DEST PORT,REMARK,ORIGINAL\n";
     my $acl_name_var;
     my $acl_name_ctr = 1;
     foreach (@acl_grp)
     {
          my $acl = $_->{name};
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
               $acl_name_var = $_->{name};
               $acl_name_ctr = 1;
          }
          
          if($_->{original} !~ /remark/)
          {
               print FILE "$_->{name},$acl_name_ctr,$_->{func},$_->{protocol},$_->{source_net},$_->{source_port},$_->{dest_net},$_->{dest_port},$_->{remark},$_->{original}\n";
          }
     }
     close FILE;
     print "compelted\n";
}


elsif($cfg_type eq "PIX")
{
     my @hostname = grep /hostname/,@first_data;

     foreach(@first_data)
     {
          my $line = $_;
          my $first = 1;
          my $skip = 0;
          my %object_grp_hash;
          my %acl_hash;
          if($line =~ m/^\s*.*$/)
          {
               foreach (@ignored)
               {
                    if ($line =~ $_  && $line !~ /access-list/)
                    {
                         $skip = 1;
                         last;
                    }
               }
               if ($skip == 0)
               {
                    my @matches = split / /,$line;

                    if($matches[0] eq 'object-group')
                    {
                         $object_grp_hash{type} = $matches[1];
                         $object_grp_hash{name} = $matches[2];
                         $object_grp_hash{protocol} = $matches[3];

                         my $obj_ctr = 1;
                         my @tmp;
                         until ($first_data[$first_data_ctr + $obj_ctr] =~ 'object-group' || $first_data[$first_data_ctr + $obj_ctr] =~ 'access-list')
                         {
                              $tmp[$obj_ctr-1] = $first_data[$first_data_ctr + $obj_ctr];
                              ++$obj_ctr;
                         }

                         $object_grp_hash{entries} = \@tmp;
                         $object_grp[$object_grp_ctr] = \%object_grp_hash;
                         ++$object_grp_ctr;
                         print "";
                    }
                    elsif($matches[0] eq 'access-list')
                    {
                         if ($_ =~ m/access-list (.*?) (?:permit|deny) (.*?) (.*?) (.*)/)
                         {
                              if($first_data[$first_data_ctr -1] =~ /remark/)
                              {
                                   my @tmp = split / /,$first_data[$first_data_ctr -1];
                                   splice @tmp,0,3;
                                   $acl_hash{remark} = join " ",@tmp;
                                   $acl_hash{remark} =~ s/\,/ /g;
                              }
                              $acl_hash{name} = $matches[1];
                              $acl_hash{func} = $matches[2];
                              $acl_hash{protocol} = $matches[3];

                              # set the source Network side varibles of the ACL
                              if ($matches[4] eq 'any') { $acl_hash{source_net} = 'any'}
                              elsif($matches[4] eq 'host') { $acl_hash{source_net} = "host $matches[5]"}
                              elsif($matches[4] =~ m/^\d+\.\d+\.\d+\.\d+$/) { $acl_hash{source_net} = "$matches[4] $matches[5]"};

                              # set the source PROTOCOL side varibles of the ACL
                              if ($matches[6] eq 'eq') { $acl_hash{source_port} = $matches[7]}
                              elsif ($matches[5] eq 'eq') { $acl_hash{source_port} = $matches[6]};

                              # Set the Destination side of the varibles
                              if ($matches[5] eq 'any') { $acl_hash{dest_net} = 'any'}
                              elsif ($matches[6] eq 'any') { $acl_hash{dest_net} = 'any'}
                              elsif($matches[5] eq 'host') { $acl_hash{dest_net} = "host $matches[6]"}
                              elsif($matches[6] eq 'host') { $acl_hash{dest_net} = "host $matches[7]"}
                              elsif($matches[8] eq 'host') { $acl_hash{dest_net} = "host $matches[9]"}
                              elsif($matches[7] eq 'host') { $acl_hash{dest_net} = "host $matches[8]"}
                              elsif($matches[5] =~ m/^\d+\.\d+\.\d+\.\d+$/) { $acl_hash{dest_net} = "$matches[5] $matches[6]"};

                              # set the Dest PROTOCOL side varibles of the ACL
                              if ($matches[7] eq 'eq') { $acl_hash{dest_port} = $matches[8]}
                              elsif ($matches[8] eq 'eq') { $acl_hash{dest_port} = $matches[9]}
                              elsif ($matches[10] eq 'eq') { $acl_hash{dest_port} = $matches[11]}
                              elsif ($matches[9] eq 'eq') { $acl_hash{dest_port} = $matches[10]}
                              elsif ($matches[10] eq 'gt') { $acl_hash{dest_port} = "gt $matches[11]"}
                              elsif ($matches[7] eq 'range') { $acl_hash{dest_port} = "range $matches[8] $matches[9]"}
                              elsif ($matches[8] eq 'range') { $acl_hash{dest_port} = "range $matches[9] $matches[10]"}
                              elsif ($matches[5] eq 'any' && $matches[7] eq "eq") { $acl_hash{dest_port} = $matches[7]}
                              elsif ($matches[5] eq 'any' && $matches[7] =~ /./) { $acl_hash{dest_port} = $matches[6]}
                              elsif($matches[7] eq 'object-group') { $acl_hash{dest_port} = "object-group $matches[8]"}

                              $acl_hash{original} = $_;

                              $acl_grp[$acl_grp_ctr] = \%acl_hash;
                              ++ $acl_grp_ctr;
                         }
                    }
               }
          }
          print "";
          ++$first_data_ctr;
     } # end foreach first_data loop

     #open FILE, ">$hostname[0]\-output.csv";
     open FILE, ">output.csv";

     print FILE "NAME,LINE,FUNCTION,PROTOCOL,SOURCE NET,SOURCE_PORT,DEST NET,DEST PORT,REMARK,ORIGINAL\n";
     my $acl_name_var;
     my $acl_name_ctr = 1;
     foreach (@acl_grp)
     {
          my $acl = $_->{name};
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
               $acl_name_var = $_->{name};
               $acl_name_ctr = 1;
          }

          print FILE "$_->{name},$acl_name_ctr,$_->{func},$_->{protocol},$_->{source_net},$_->{source_port},$_->{dest_net},$_->{dest_port},$_->{remark},$_->{original}\n";
     }
     close FILE;
     print "compelted\n";
}



else
{
     print "I could not determin the config type Please review file\n";
     exit;
}
