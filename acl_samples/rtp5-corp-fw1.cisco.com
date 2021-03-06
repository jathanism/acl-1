object-group network multicast_networks-global-1
 network-object 224.0.0.0 240.0.0.0
object-group network bogus_networks
 network-object 0.0.0.0 255.0.0.0
 network-object 255.0.0.0 255.0.0.0
object-group network rfc1918_networks-global-1
 network-object 10.0.0.0 255.0.0.0
 network-object 172.16.0.0 255.240.0.0
 network-object 192.168.0.0 255.255.0.0
object-group network cisco_internal_networks-global-1
 group-object rfc1918_networks-global-1
 network-object 12.5.186.32 255.255.255.248
 network-object 12.159.148.12 255.255.255.252
 network-object 12.159.148.16 255.255.255.240
 network-object 12.130.27.0 255.255.255.0
 network-object 63.241.93.0 255.255.255.0
 network-object 64.100.16.0 255.255.240.0
 network-object 64.100.32.0 255.255.224.0
 network-object 64.100.64.0 255.255.192.0
 network-object 64.100.128.0 255.255.128.0
 network-object 64.101.0.0 255.255.128.0
 network-object 64.101.128.0 255.255.192.0
 network-object 64.101.192.0 255.255.192.0
 network-object 64.102.0.0 255.255.128.0
 network-object 64.102.128.0 255.255.224.0
 network-object 64.102.192.0 255.255.224.0
 network-object 64.102.224.0 255.255.240.0
 network-object 64.102.252.0 255.255.254.0
 network-object 64.103.0.0 255.255.240.0
 network-object 64.103.16.0 255.255.248.0
 network-object 64.103.28.0 255.255.252.0
 network-object 64.103.32.0 255.255.252.0
 network-object 64.103.40.0 255.255.248.0
 network-object 64.103.48.0 255.255.240.0
 network-object 64.103.64.0 255.255.224.0
 network-object 64.103.96.0 255.255.240.0
 network-object 64.103.112.0 255.255.240.0
 network-object 64.103.128.0 255.255.128.0
 network-object 64.104.0.0 255.255.224.0
 network-object 64.104.32.0 255.255.248.0
 network-object 64.104.40.0 255.255.252.0
 network-object 64.104.48.0 255.255.248.0
 network-object 64.104.64.0 255.255.240.0
 network-object 64.104.80.0 255.255.248.0
 network-object 64.104.88.0 255.255.252.0
 network-object 64.104.96.0 255.255.240.0
 network-object 64.104.116.0 255.255.252.0
 network-object 64.104.120.0 255.255.252.0
 network-object 64.104.128.0 255.255.240.0
 network-object 64.104.144.0 255.255.248.0
 network-object 64.104.152.0 255.255.252.0
 network-object 64.104.156.0 255.255.252.0
 network-object 64.104.160.0 255.255.224.0
 network-object 64.104.192.0 255.255.224.0
 network-object 64.104.224.0 255.255.240.0
 network-object 64.104.240.0 255.255.248.0
 network-object 128.107.96.0 255.255.224.0
 network-object 128.107.128.0 255.255.192.0
 network-object 128.107.192.0 255.255.240.0
 network-object 134.24.132.0 255.255.252.0
 network-object 144.254.0.0 255.255.192.0
 network-object 144.254.64.0 255.255.224.0
 network-object 144.254.128.0 255.255.128.0
 network-object 161.44.0.0 255.255.0.0
 network-object 171.68.0.0 255.252.0.0
 network-object 173.36.0.0 255.255.128.0
 network-object 173.36.128.0 255.255.192.0
 network-object 173.37.0.0 255.255.224.0
 network-object 173.37.32.0 255.255.224.0
 network-object 173.37.64.0 255.255.192.0
 network-object 173.37.128.0 255.255.192.0
 network-object 173.37.128.0 255.255.248.0
 network-object 173.37.136.0 255.255.252.0
 network-object 173.37.140.0 255.255.252.0
 network-object 173.37.224.0 255.255.224.0
 network-object 173.38.0.0 255.255.224.0
 network-object 173.38.32.0 255.255.224.0
 network-object 173.38.64.0 255.255.224.0
 network-object 173.38.128.0 255.255.128.0
 network-object 173.39.0.0 255.255.192.0
 network-object 173.39.64.0 255.255.240.0
 network-object 173.39.96.0 255.255.240.0
 network-object 173.39.112.0 255.255.248.0
 network-object 173.39.128.0 255.255.240.0
 network-object 173.39.160.0 255.255.224.0
 network-object 173.39.192.0 255.255.192.0
 network-object 192.118.76.64 255.255.255.240
 network-object 192.118.79.0 255.255.255.224
 network-object 192.118.79.32 255.255.255.248
 network-object 192.122.173.0 255.255.255.0
 network-object 192.122.174.0 255.255.255.0
 network-object 192.133.144.0 255.255.240.0
 network-object 192.133.160.0 255.255.240.0
 network-object 192.133.176.0 255.255.248.0
 network-object 192.133.184.0 255.255.252.0
 network-object 192.133.188.0 255.255.254.0
 network-object 192.133.191.0 255.255.255.0
 network-object 192.133.192.0 255.255.224.0
 network-object 192.133.224.0 255.255.240.0
 network-object 192.133.240.0 255.255.252.0
 network-object 192.135.240.0 255.255.248.0
 network-object 192.135.251.0 255.255.255.0
 network-object 192.190.222.0 255.255.254.0
 network-object 196.25.175.16 255.255.255.252
 network-object 196.25.175.32 255.255.255.240
 network-object 198.92.0.0 255.255.192.0
 network-object 199.106.70.0 255.255.255.0
 network-object 216.148.52.0 255.255.252.0
 network-object 72.163.16.0 255.255.240.0
 network-object 72.163.32.0 255.255.224.0
 network-object 72.163.64.0 255.255.192.0
 network-object 72.163.128.0 255.255.192.0
 network-object 72.163.192.0 255.255.240.0
 network-object 72.163.208.0 255.255.248.0
 network-object 72.163.224.0 255.255.224.0
 network-object 216.128.32.0 255.255.224.0
 network-object 173.38.96.0 255.255.240.0
 network-object 192.133.190.0 255.255.255.0
object-group network dmz_networks-sjc-1
 network-object 128.107.224.0 255.255.224.0
 network-object 192.31.7.0 255.255.255.0
 network-object 198.133.219.0 255.255.255.0
 network-object 204.69.198.0 255.255.254.0
 network-object 204.69.200.0 255.255.255.0
 network-object 128.107.208.0 255.255.240.0
 network-object 128.107.64.0 255.255.240.0
 network-object 128.107.80.0 255.255.240.0
 network-object 173.36.192.0 255.255.192.0
 network-object 192.135.239.0 255.255.255.0
 network-object 128.107.227.208 255.255.255.240
 network-object 128.107.234.64 255.255.255.192
 network-object 128.107.241.64 255.255.255.224
object-group network dmz_networks-rtp-1
 network-object 64.102.254.0 255.255.254.0
 network-object 192.135.250.0 255.255.255.0
 network-object 64.102.240.0 255.255.248.0
 network-object 64.102.248.0 255.255.252.0
 network-object 64.100.0.0 255.255.240.0
 network-object 173.38.120.0 255.255.248.0
 network-object 10.115.131.128 255.255.255.128
 network-object 64.100.248.0 255.255.248.0
 network-object 64.102.220.0 255.255.254.0
 network-object 64.102.242.176 255.255.255.240
 network-object 64.102.243.0 255.255.255.128
object-group network dmz_networks-ams-1
 network-object 64.103.36.0 255.255.252.0
 network-object 64.103.24.0 255.255.252.0
 network-object 144.254.51.0 255.255.255.0
 network-object 173.38.152.0 255.255.252.0
 network-object 10.61.46.0 255.255.255.0
object-group network dmz_networks-aus-1
 network-object 64.104.252.0 255.255.254.0
 network-object 64.104.248.0 255.255.255.0
 network-object 64.104.248.0 255.255.248.0
 network-object 10.66.129.128 255.255.255.128
object-group network dmz_networks-japan-1
 network-object 64.104.44.0 255.255.252.0
 network-object 64.104.56.0 255.255.248.0
object-group network dmz_networks-singapore-1
 network-object 64.104.94.0 255.255.254.0
 network-object 173.39.120.0 255.255.248.0
object-group network dmz_networks-bgl-1
 network-object 72.163.0.0 255.255.240.0
 network-object 72.163.216.0 255.255.248.0
 network-object 10.64.63.0 255.255.255.0
 network-object 173.39.80.0 255.255.240.0
 network-object 173.39.92.0 255.255.252.0
 network-object 10.105.24.0 255.255.252.0
 network-object 173.39.12.0 255.255.252.0
object-group network dmz_networks-hk-1
 network-object 64.104.124.0 255.255.252.0
 network-object 173.39.144.0 255.255.240.0
object-group network dmz_networks-bxb-1
 network-object 12.159.148.0 255.255.255.248
 network-object 12.159.148.8 255.255.255.252
 network-object 12.159.148.32 255.255.255.224
 network-object 12.159.148.64 255.255.255.192
 network-object 12.159.148.128 255.255.255.128
 network-object 12.159.150.0 255.255.254.0
 network-object 12.159.148.120 255.255.255.248
 network-object 12.159.148.0 255.255.252.0
 network-object 198.135.0.0 255.255.248.0
object-group network dmz_networks-isr-1
 network-object 10.56.109.0 255.255.255.192
 network-object 10.56.109.64 255.255.255.192
 network-object 192.118.76.0 255.255.255.192
 network-object 192.118.76.80 255.255.255.240
 network-object 192.118.76.96 255.255.255.224
 network-object 192.118.76.128 255.255.255.128
 network-object 192.118.77.0 255.255.255.0
 network-object 192.118.78.0 255.255.255.0
 network-object 192.118.79.40 255.255.255.248
 network-object 192.118.79.48 255.255.255.240
 network-object 192.118.79.64 255.255.255.192
 network-object 192.118.79.128 255.255.255.128
object-group network dmz_networks-brnt-1
 network-object 196.25.175.0 255.255.255.240
 network-object 196.25.175.20 255.255.255.252
 network-object 196.25.175.24 255.255.255.248
 network-object 196.25.175.48 255.255.255.248
 network-object 196.25.175.56 255.255.255.248
object-group network dmz_networks-rich-1
 network-object 12.5.186.0 255.255.255.248
 network-object 12.5.186.8 255.255.255.252
 network-object 12.5.186.12 255.255.255.252
 network-object 12.5.186.16 255.255.255.248
 network-object 12.5.186.24 255.255.255.248
 network-object 12.5.186.48 255.255.255.252
 network-object 12.5.186.52 255.255.255.252
 network-object 12.5.186.56 255.255.255.252
 network-object 12.5.186.60 255.255.255.252
 network-object 12.5.187.0 255.255.255.252
 network-object 12.5.187.64 255.255.255.252
 network-object 12.5.187.80 255.255.255.252
 network-object 12.5.187.248 255.255.255.248
 network-object 12.46.104.0 255.255.254.0
 network-object 72.163.0.0 255.255.240.0
 network-object 173.37.192.0 255.255.224.0
 network-object 10.101.164.0 255.255.252.0
 network-object 173.37.144.0 255.255.248.0
 network-object 173.36.112.0 255.255.240.0
 network-object 10.123.20.0 255.255.254.0
object-group network dmz_networks-linksys-1
 network-object 204.69.198.0 255.255.255.0
object-group network dmz_networks-vancouver-1
 network-object 209.82.96.192 255.255.255.224
 network-object 10.85.148.0 255.255.255.240
object-group network dmz_networks-rcdn9-1
 network-object 72.163.0.0 255.255.240.0
 network-object 10.201.96.0 255.255.240.0
object-group network dmz_networks-alln-1
 network-object 173.36.112.0 255.255.240.0
 network-object 173.37.144.104 255.255.255.248
 network-object 173.37.144.112 255.255.255.240
 network-object 173.37.144.160 255.255.255.240
 network-object 173.37.144.224 255.255.255.240
 network-object 173.37.144.192 255.255.255.224
 network-object 173.37.145.0 255.255.255.192
 network-object 173.37.145.160 255.255.255.224
 network-object 173.37.145.224 255.255.255.224
 network-object 173.37.145.64 255.255.255.192
 network-object 173.37.146.0 255.255.255.224
 network-object 173.37.146.64 255.255.255.192
 network-object 173.37.146.128 255.255.255.128
object-group network dmz_networks-shanghai-1
 network-object 72.163.248.0 255.255.252.0
object-group network DMZ_TandbergVCE-rtp-1
 network-object 64.102.249.32 255.255.255.224
object-group network Internal_TandbergVCS-rtp-1
 network-object 64.102.252.224 255.255.255.240
 network-object 64.102.252.96 255.255.255.224
 network-object 64.102.104.64 255.255.255.192
object-group network DMZ_TandbergVCE-ams-1
 network-object 64.103.25.128 255.255.255.224
object-group network Internal_TandbergVCS-ams-1
 network-object 144.254.217.0 255.255.255.192
object-group network DMZ_TandbergVCE-syd-1
 network-object 64.104.249.0 255.255.255.224
object-group network Internal_TandbergVCS-syd-1
 network-object 64.104.237.64 255.255.255.192
object-group network Internal_TandbergVCS-sjc-1
 network-object 171.71.193.0 255.255.255.192
object-group network DMZ_TandbergVCE-sjc-1
 network-object 128.107.85.0 255.255.255.224
object-group network TAA_TandbergVCS_Oslo
 network-object 64.103.59.16 255.255.255.240
object-group network dmz_networks-sciatl-1
 network-object 192.133.190.0 255.255.255.0
object-group network guest_networks-global-1
 network-object 64.102.160.0 255.255.224.0
 network-object 128.107.0.0 255.255.192.0
 network-object 144.254.96.0 255.255.224.0
 network-object 64.104.56.0 255.255.254.0
 network-object 64.104.92.0 255.255.254.0
 network-object 64.104.112.0 255.255.252.0
 network-object 64.104.254.0 255.255.254.0
 network-object 144.254.44.0 255.255.252.0
 network-object 144.254.36.0 255.255.252.0
 network-object 64.104.44.0 255.255.255.240
 network-object 64.104.94.64 255.255.255.240
 network-object 64.100.56.0 255.255.248.0
object-group network dmz_networks-global-1
 group-object dmz_networks-sjc-1
 group-object dmz_networks-rtp-1
 group-object dmz_networks-aus-1
 group-object dmz_networks-ams-1
 group-object dmz_networks-japan-1
 group-object dmz_networks-bgl-1
 group-object dmz_networks-singapore-1
 group-object dmz_networks-isr-1
 group-object dmz_networks-bxb-1
 group-object dmz_networks-rich-1
 group-object dmz_networks-hk-1
 group-object dmz_networks-brnt-1
 group-object dmz_networks-linksys-1
 group-object dmz_networks-vancouver-1
 group-object guest_networks-global-1
 group-object dmz_networks-shanghai-1
 group-object dmz_networks-sciatl-1
object-group network ext_loopbacks_rtp
 network-object 172.17.213.16 255.255.255.248
 network-object 10.81.255.0 255.255.255.224
 network-object 10.81.225.192 255.255.255.192
 network-object 10.115.131.128 255.255.255.224
object-group network dmz_loopbacks-japan-1
 network-object 10.70.65.96 255.255.255.224
 network-object 10.70.225.96 255.255.255.224
 network-object host 64.104.44.97
object-group network dmz_loopbacks-aus-1
 network-object 172.17.253.0 255.255.255.0
 network-object 10.66.129.0 255.255.255.0
object-group network dmz_loopbacks-ams-1
 network-object 10.61.32.0 255.255.255.224
 network-object 10.61.46.32 255.255.255.224
object-group network dmz_loopbacks-bxb-1
 network-object 10.86.230.64 255.255.255.240
 network-object 10.86.234.0 255.255.255.0
object-group network dmz_loopbacks-sjc-1
 network-object 172.17.153.0 255.255.255.0
object-group network dmz_loopbacks-isr-1
 network-object 10.56.72.32 255.255.255.224
 network-object 10.56.109.160 255.255.255.224
 network-object 10.56.109.128 255.255.255.224
object-group network dmz_loopbacks-rich-1
 network-object 10.89.255.192 255.255.255.192
 network-object 10.101.14.0 255.255.254.0
 network-object 10.101.206.0 255.255.254.0
object-group network dmz_loopbacks-hk-1
 network-object host 10.75.225.7
 network-object host 10.75.225.8
 network-object host 10.75.225.9
 network-object 10.75.225.192 255.255.255.192
object-group network dmz_loopbacks-singapore-1
 network-object host 10.68.1.6
 network-object host 10.68.1.7
 network-object host 10.68.1.8
 network-object host 10.68.1.9
 network-object host 10.68.1.10
 network-object host 10.68.1.15
 network-object host 10.68.1.16
 network-object 10.68.12.0 255.255.255.0
object-group network dmz_loopbacks-bgl-1
 network-object host 64.104.159.129
 network-object host 64.104.159.130
 network-object host 64.104.159.1
 network-object 64.104.159.128 255.255.255.192
 network-object 10.64.63.0 255.255.255.0
 network-object 10.105.24.0 255.255.255.192
object-group network dmz_loopbacks-brnt-1
 network-object 10.59.15.224 255.255.255.248
object-group network dmz_loopbacks-vancouver-1
 network-object 10.85.148.0 255.255.255.240
object-group network dmz_loopbacks-rcdn9-1
 network-object 10.101.14.0 255.255.254.0
object-group network dmz_loopbacks-alln-1
 network-object 10.123.20.0 255.255.254.0
object-group network dmz_loopbacks-shanghai-1
 network-object 10.75.11.0 255.255.255.0
object-group network dmz_loopbacks-lwr
 network-object 192.133.209.0 255.255.255.0
object-group network dmz_loopbacks-global-1
 group-object ext_loopbacks_rtp
 group-object dmz_loopbacks-japan-1
 group-object dmz_loopbacks-aus-1
 group-object dmz_loopbacks-ams-1
 group-object dmz_loopbacks-bxb-1
 group-object dmz_loopbacks-sjc-1
 group-object dmz_loopbacks-isr-1
 group-object dmz_loopbacks-rich-1
 group-object dmz_loopbacks-hk-1
 group-object dmz_loopbacks-singapore-1
 group-object dmz_loopbacks-bgl-1
 group-object dmz_loopbacks-brnt-1
 group-object dmz_loopbacks-vancouver-1
 group-object dmz_loopbacks-rcdn9-1
 group-object dmz_loopbacks-alln-1
 group-object dmz_loopbacks-shanghai-1
 group-object dmz_loopbacks-lwr
object-group network tacacs_servers-global-1
 network-object host 171.68.10.137
 network-object host 161.44.11.123
 network-object host 64.104.193.36
 network-object host 171.70.149.213
 network-object host 171.70.149.201
 network-object host 64.102.121.150
 network-object host 64.102.121.152
 network-object host 144.254.227.116
 network-object host 144.254.227.117
 network-object host 64.104.193.4
 network-object host 64.104.193.29
 network-object host 64.104.123.228
 network-object host 171.70.168.246
 network-object host 64.102.6.243
 network-object host 144.254.71.234
 network-object host 173.38.203.29
 network-object host 173.36.13.78
 network-object host 72.163.128.165
 network-object host 161.44.121.11
 network-object host 64.104.123.61
 network-object host 171.68.50.87
 network-object host 72.163.42.123
 network-object host 173.39.102.14
 network-object host 171.70.168.112
 network-object host 64.104.193.223
 network-object host 64.104.1.73
object-group network tftp_servers-global-1
 network-object host 171.70.168.154
 network-object host 171.70.168.173
 network-object host 171.70.139.30
 network-object host 64.100.32.200
 network-object host 171.69.17.19
 network-object host 173.37.87.150
 network-object host 173.37.87.189
object-group network eman_syslog-global-1
 network-object host 171.70.168.186
 network-object host 171.70.168.142
 network-object host 64.102.6.250
 network-object host 144.254.71.186
 network-object host 64.104.14.186
 network-object host 64.104.200.250
 network-object host 64.101.128.58
 network-object host 171.70.139.31
 network-object host 64.102.12.253
 network-object host 144.254.73.23
 network-object host 64.104.193.42
 network-object host 64.102.12.44
 network-object host 64.104.200.69
 network-object host 144.254.73.63
 network-object host 72.163.42.118
 network-object 171.68.58.128 255.255.255.224
 network-object 144.254.214.160 255.255.255.240
 network-object 64.103.209.160 255.255.255.240
 network-object 173.37.161.224 255.255.255.240
 network-object 64.100.49.192 255.255.255.240
 network-object host 72.163.43.30
 network-object host 64.100.39.9
 network-object host 171.68.46.20
 network-object host 72.163.192.86
 network-object host 144.254.73.185
 network-object host 64.100.39.11
 network-object host 64.100.39.10
 network-object host 72.163.43.31
 network-object host 72.163.43.32
 network-object host 171.68.46.21
 network-object host 171.68.46.22
 network-object host 72.163.192.87
 network-object host 72.163.192.88
 network-object host 144.254.73.186
 network-object host 144.254.73.187
object-group network snmp_managers-global-1
 network-object 171.68.226.0 255.255.255.128
 network-object 171.70.156.128 255.255.255.224
 network-object 171.70.168.0 255.255.255.0
 network-object 64.104.14.128 255.255.255.192
 network-object 64.104.200.192 255.255.255.192
 network-object 64.102.6.128 255.255.255.192
 network-object 64.103.101.128 255.255.255.192
 network-object 144.254.71.128 255.255.255.128
 network-object 161.44.9.64 255.255.255.192
 network-object 72.163.49.192 255.255.255.192
 network-object 173.37.124.0 255.255.255.192
 network-object 173.37.87.128 255.255.255.192
 network-object 173.36.10.128 255.255.255.192
 network-object 173.38.200.64 255.255.255.192
 network-object 173.37.75.192 255.255.255.224
 network-object 64.104.200.128 255.255.255.128
 network-object 144.254.71.0 255.255.255.0
 network-object host 144.254.148.15
 network-object 144.254.10.0 255.255.255.128
 network-object 161.44.140.128 255.255.255.128
 network-object 161.44.124.0 255.255.255.128
 network-object host 64.101.128.58
 network-object 64.101.128.0 255.255.255.192
 network-object 64.104.123.128 255.255.255.128
 network-object 64.104.164.0 255.255.255.128
 network-object 64.104.76.128 255.255.255.128
 network-object 64.104.128.192 255.255.255.192
 network-object 72.163.128.0 255.255.255.128
 network-object host 171.70.89.154
 network-object host 171.70.89.156
 network-object host 171.70.89.158
 network-object host 171.70.89.160
 network-object host 171.71.180.200
 network-object 171.68.58.128 255.255.255.224
 network-object 144.254.214.160 255.255.255.240
 network-object 64.103.209.160 255.255.255.240
 network-object 173.37.161.224 255.255.255.240
 network-object 64.100.49.192 255.255.255.240
 network-object 173.38.14.64 255.255.255.192
 network-object 173.38.43.0 255.255.255.192
 network-object 173.36.131.0 255.255.255.192
object-group network netflow_hosts-global-1
 network-object host 144.254.49.189
 network-object host 64.104.195.28
 network-object host 64.102.6.160
 network-object host 171.68.226.94
 network-object host 173.37.108.4
 network-object host 64.102.12.60
 network-object host 72.163.132.151
 network-object host 173.36.128.10
object-group network dmz_smtp-global-1
 network-object host 128.107.241.178
 network-object host 128.107.241.179
 network-object host 128.107.241.180
 network-object host 128.107.234.214
 network-object host 128.107.234.215
 network-object host 64.104.252.245
 network-object host 192.135.250.71
 network-object host 64.104.252.248
 network-object host 64.104.252.249
 network-object host 64.103.36.153
 network-object host 64.103.36.154
 network-object host 64.102.255.45
 network-object host 64.102.255.46
 network-object host 128.107.234.204
 network-object host 128.107.234.205
 network-object host 128.107.234.206
 network-object host 128.107.243.13
 network-object host 128.107.243.14
 network-object host 128.107.243.16
 network-object host 128.107.234.207
 network-object host 128.107.234.210
 network-object host 128.107.234.208
 network-object host 128.107.234.209
 network-object host 64.102.255.47
 network-object host 72.163.7.179
 network-object host 72.163.7.180
 network-object host 72.163.7.170
 network-object host 72.163.7.171
 network-object host 72.163.7.172
 network-object host 72.163.7.173
 network-object host 72.163.7.174
 network-object host 72.163.7.175
 network-object host 72.163.7.176
 network-object host 72.163.7.177
 network-object host 72.163.7.178
 network-object host 72.163.7.181
 network-object host 72.163.7.182
 network-object host 72.163.7.166
 network-object host 72.163.7.167
 network-object host 72.163.7.168
 network-object host 64.103.36.169
 network-object host 64.103.36.170
 network-object host 64.103.36.171
 network-object host 64.103.36.172
object-group network proxy_servers-sjc-1
 network-object host 128.107.241.169
 network-object host 128.107.241.170
object-group network proxy_servers-rtp-1
 network-object host 64.102.255.40
object-group network proxy_servers-ams-1
 network-object host 64.103.36.133
object-group network proxy_servers-syd-1
 network-object host 64.104.252.247
 network-object host 64.104.252.245
object-group network proxy_servers-global-1
 group-object proxy_servers-sjc-1
 group-object proxy_servers-rtp-1
 group-object proxy_servers-ams-1
 group-object proxy_servers-syd-1
object-group network internal_smtp-vip-only-global-1
 network-object host 144.254.72.80
 network-object host 144.254.72.81
 network-object host 72.163.197.20
 network-object host 64.104.123.94
 network-object host 64.104.129.221
 network-object host 171.68.58.10
 network-object host 64.102.124.15
 network-object host 171.71.177.236
 network-object host 171.68.223.136
 network-object host 173.37.93.161
 network-object host 173.37.113.194
 network-object host 64.104.193.198
object-group network internal_smtp-global-1
 network-object host 64.104.195.48
 network-object host 144.254.74.140
 network-object host 171.71.177.237
 network-object host 171.71.177.254
 network-object host 171.68.223.137
 network-object host 171.68.223.138
 network-object host 171.71.177.238
 network-object host 64.102.124.12
 network-object host 64.102.124.13
 network-object host 171.71.177.236
 network-object host 171.68.223.136
 network-object host 64.104.193.198
 network-object host 144.254.224.150
 network-object host 64.104.88.158
 network-object host 64.104.129.221
 network-object host 64.104.129.195
 network-object host 64.104.129.219
 network-object host 64.104.129.10
 network-object host 64.104.193.196
 network-object host 64.104.193.197
 network-object host 64.102.124.15
 network-object host 173.37.93.161
 network-object host 173.37.93.152
 network-object host 173.37.93.153
 network-object host 173.37.93.154
 network-object host 173.37.93.155
 network-object host 173.37.93.156
 network-object host 173.37.93.157
 network-object host 72.163.197.20
 network-object host 72.163.197.16
 network-object host 72.163.197.17
 network-object host 72.163.197.18
 network-object host 72.163.197.19
 network-object host 144.254.72.80
 network-object host 144.254.72.81
 network-object host 144.254.72.75
 network-object host 144.254.72.76
 network-object host 144.254.72.77
 network-object host 173.37.113.194
 network-object host 173.37.113.188
 network-object host 173.37.113.189
 network-object host 173.37.113.190
 network-object host 173.37.113.191
 network-object host 173.37.113.192
 network-object host 173.37.113.193
 network-object host 171.68.58.10
 network-object host 171.68.58.6
 network-object host 171.68.58.7
 network-object host 171.68.58.8
 network-object host 171.68.58.9
 network-object host 173.37.86.81
 network-object host 173.37.86.82
 network-object host 173.37.86.72
 network-object host 173.37.86.73
 network-object host 173.37.86.74
 network-object host 173.37.86.75
 network-object host 173.37.86.76
 network-object host 173.37.86.77
 network-object host 173.37.86.78
 network-object host 173.37.86.79
 network-object host 173.37.86.80
 network-object host 173.36.130.12
 network-object host 173.36.130.13
 network-object host 173.36.130.14
 network-object host 173.36.130.15
 network-object host 144.254.224.146
 network-object host 144.254.224.147
 network-object host 72.163.197.25
 network-object host 72.163.197.26
 network-object host 72.163.197.27
 network-object host 72.163.197.28
object-group network ntp_servers-global-1
 network-object host 171.68.10.150
 network-object host 171.68.10.80
 network-object host 10.81.254.131
 network-object host 10.81.254.202
 network-object host 64.103.34.14
 network-object host 64.103.34.15
 network-object host 64.104.222.16
 network-object host 64.104.193.12
 network-object host 171.68.10.151
 network-object host 171.68.10.138
 network-object host 216.128.60.106
 network-object host 64.102.6.134
 network-object host 64.102.6.135
 network-object host 144.254.231.240
 network-object host 144.254.231.241
 network-object host 144.254.15.68
 network-object host 144.254.15.78
 network-object host 10.52.150.75
 network-object host 10.66.141.50
 network-object host 10.66.141.51
 network-object host 10.64.58.50
 network-object host 10.64.58.51
 network-object host 171.68.38.65
 network-object host 171.68.38.66
 network-object host 72.163.32.43
 network-object host 173.37.136.16
object-group network nntp_servers-global-1
 network-object host 204.123.2.59
 network-object host 4.1.16.34
 network-object host 4.24.20.64
 network-object host 4.24.20.130
 network-object host 4.24.20.166
 network-object host 4.24.22.218
 network-object host 4.24.22.222
 network-object host 131.119.28.149
 network-object host 131.119.28.151
 network-object host 195.16.160.135
 network-object host 199.94.215.12
 network-object host 4.0.22.2
 network-object host 4.0.54.2
object-group network raex_subnets-global-1
 network-object 10.86.240.0 255.255.240.0
 network-object 10.98.0.0 255.255.0.0
 network-object 10.86.96.0 255.255.224.0
object-group network datacenter_networks-sjc20-1
 network-object 128.107.182.0 255.255.254.0
 network-object 128.107.184.0 255.255.252.0
object-group network datacenter_networks-sjc5-1
 network-object 171.70.64.0 255.255.248.0
 network-object 171.70.88.0 255.255.248.0
 network-object 171.70.104.0 255.255.248.0
 network-object 171.71.152.0 255.255.252.0
 network-object 171.71.160.0 255.255.240.0
object-group network datacenter_networks-sjc12-1
 network-object 171.70.156.0 255.255.252.0
 network-object 171.70.152.0 255.255.255.224
 network-object 171.70.136.0 255.255.248.0
 network-object 171.70.144.0 255.255.252.0
 network-object 171.70.148.0 255.255.252.0
 network-object 171.70.168.0 255.255.252.0
 network-object 171.71.176.0 255.255.248.0
object-group network datacenter_networks-sjck-1
 network-object 171.68.222.0 255.255.254.0
 network-object 171.68.224.0 255.255.252.0
 network-object 171.68.196.0 255.255.255.0
 network-object 171.68.197.32 255.255.255.240
 network-object 171.68.197.96 255.255.255.224
 network-object 171.68.200.0 255.255.248.0
 network-object 171.68.235.96 255.255.255.224
 network-object 171.68.235.128 255.255.255.192
 network-object 171.68.235.192 255.255.255.224
 network-object 171.68.235.224 255.255.255.224
 network-object 171.68.10.0 255.255.255.0
object-group network datacenter_networks-rtp-1
 network-object 161.44.1.0 255.255.255.224
 network-object 161.44.10.64 255.255.255.192
 network-object 161.44.11.0 255.255.255.0
 network-object 64.102.0.0 255.255.240.0
 network-object 64.102.16.0 255.255.240.0
 network-object 64.102.112.0 255.255.240.0
object-group network datacenter_networks-sjcd-1
 network-object 171.69.12.0 255.255.255.128
 network-object 171.69.12.128 255.255.255.128
 network-object 171.69.15.0 255.255.255.128
 network-object 171.69.15.128 255.255.255.128
 network-object 171.69.28.0 255.255.255.128
 network-object 171.69.2.0 255.255.255.192
 network-object 171.69.2.64 255.255.255.192
 network-object 171.69.28.128 255.255.255.128
 network-object 171.69.19.0 255.255.255.0
 network-object 171.69.18.0 255.255.255.0
 network-object 171.69.29.0 255.255.255.128
 network-object 171.69.29.128 255.255.255.128
 network-object 171.69.27.0 255.255.255.128
object-group network datacenter_networks-sjce-1
 network-object 171.69.17.0 255.255.255.0
 network-object 198.92.30.0 255.255.255.0
 network-object 171.69.1.128 255.255.255.192
 network-object 171.69.16.0 255.255.255.128
 network-object 171.69.21.0 255.255.255.0
 network-object 171.69.23.0 255.255.255.128
 network-object 171.69.23.128 255.255.255.128
 network-object 171.69.20.0 255.255.255.128
 network-object 171.69.22.192 255.255.255.192
 network-object 171.69.16.128 255.255.255.128
 network-object 171.69.22.0 255.255.255.128
 network-object 171.69.20.128 255.255.255.128
 network-object 171.69.24.0 255.255.255.128
 network-object 171.69.24.128 255.255.255.128
 network-object 171.69.25.0 255.255.255.128
 network-object 171.69.25.128 255.255.255.128
 network-object 171.69.1.0 255.255.255.192
object-group network dc_waivers-global-1
 network-object host 64.101.140.220
 network-object host 64.102.19.198
 network-object host 64.102.19.199
 network-object host 64.102.19.200
 network-object host 64.104.15.102
 network-object host 64.104.15.101
 network-object host 64.104.106.50
 network-object host 72.163.237.6
 network-object host 64.104.206.250
 network-object host 64.104.206.251
 network-object host 64.104.206.252
 network-object host 144.254.15.100
 network-object host 144.254.15.118
 network-object host 144.254.15.119
 network-object host 144.254.190.26
 network-object host 161.44.122.57
 network-object host 171.68.227.69
 network-object host 171.68.227.73
 network-object host 171.68.227.75
 network-object host 64.102.16.213
 network-object 64.104.243.128 255.255.255.128
object-group network datacenters-emea-1
 network-object 144.254.72.0 255.255.252.0
 network-object 144.254.224.0 255.255.248.0
object-group network datacenters-global-1
 group-object datacenter_networks-sjce-1
 group-object datacenter_networks-sjcd-1
 group-object datacenter_networks-sjc20-1
 group-object datacenter_networks-sjc5-1
 group-object datacenter_networks-sjc12-1
 group-object datacenter_networks-sjck-1
 group-object datacenter_networks-rtp-1
 group-object datacenters-emea-1
object-group network aaa_spa_servers-global-1
 network-object host 171.70.149.213
 network-object host 171.70.149.201
 network-object host 64.102.121.150
 network-object host 64.102.121.152
 network-object host 64.104.193.4
 network-object host 64.104.193.29
 network-object host 144.254.227.116
 network-object host 144.254.227.117
 network-object host 173.38.203.28
 network-object host 173.36.13.8
 network-object host 72.163.128.164
 network-object host 161.44.121.6
 network-object host 64.104.123.50
 network-object host 171.68.50.139
 network-object host 72.163.43.59
 network-object host 173.39.102.8
 network-object host 171.70.168.111
 network-object host 64.104.193.225
 network-object host 64.104.1.70
object-group network dmzdc_gw-sjc-1
 network-object host 172.17.153.29
 network-object host 172.17.153.30
 network-object host 172.17.153.26
 network-object host 172.17.153.27
object-group network dmzdc_gw-rtp-1
 network-object host 10.81.255.8
 network-object host 10.81.255.5
object-group network cclc_internal-sjc-1
 network-object host 171.69.196.14
 network-object host 171.69.196.15
 network-object host 171.69.196.16
object-group network cclc_external-sjc-1
 network-object host 208.0.30.37
 network-object host 208.0.30.38
 network-object host 208.0.30.39
object-group network ncbu_vpn-sjc-1
 network-object host 128.107.201.196
 network-object host 128.107.201.197
 network-object host 128.107.201.198
 network-object host 128.107.201.210
 network-object host 128.107.201.209
object-group network ect-stld-1
 network-object host 64.104.229.1
 network-object host 64.104.229.2
object-group network CUMA_internal-sjc-1
 network-object host 172.27.204.150
 network-object host 172.27.204.151
 network-object host 172.27.204.152
 network-object host 172.27.204.153
object-group network ispgw_loopbacks-tokyo-1
 network-object host 10.70.225.97
 network-object host 10.70.225.109
 network-object host 10.70.225.110
object-group network oer_bgp_gw-global-1
 network-object host 10.70.65.103
 network-object host 10.56.72.33
 network-object host 10.86.230.65
 network-object host 10.75.225.8
 network-object host 64.104.159.129
 network-object host 10.68.1.7
 network-object host 10.58.15.225
 network-object host 10.59.15.225
 network-object host 10.75.225.193
 network-object host 10.75.225.194
 network-object host 64.104.159.131
object-group network mp_dmzdc-sjc-1
 network-object host 128.107.228.104
 network-object host 128.107.228.106
 network-object host 128.107.227.72
 network-object host 128.107.228.107
 network-object host 128.107.227.74
object-group network mp_int_ldap-global-1
 network-object host 171.70.156.38
 network-object host 64.102.4.195
 network-object host 144.254.226.4
object-group network tac_vpn_concentrators-rtp-1
 network-object host 64.102.156.82
 network-object host 64.102.156.83
 network-object host 64.102.156.84
 network-object host 64.102.156.85
 network-object host 64.102.156.86
 network-object host 64.102.156.87
 network-object host 64.102.156.88
 network-object host 64.102.156.89
 network-object host 64.102.156.90
 network-object host 64.102.156.91
 network-object host 64.102.156.92
 network-object host 64.102.156.93
 network-object host 64.102.156.94
 network-object host 64.102.156.95
object-group network microsoft_gre_support-sjc-1
 network-object host 131.107.0.140
 network-object host 131.107.0.141
 network-object host 131.107.0.145
 network-object host 131.107.0.146
 network-object host 131.107.0.147
object-group network skinny-alpha-1
 network-object host 10.32.134.100
 network-object host 10.32.134.107
 network-object host 10.32.134.108
 network-object host 10.32.134.162
 network-object host 10.32.134.163
 network-object 10.32.128.0 255.255.224.0
 network-object 10.32.160.0 255.255.240.0
 network-object 10.32.176.0 255.255.248.0
 network-object 10.32.186.0 255.255.254.0
 network-object 10.32.188.0 255.255.254.0
 network-object 10.89.30.128 255.255.255.128
 network-object 10.89.31.0 255.255.255.0
 network-object 10.89.165.128 255.255.255.128
object-group network skinny_cm-alpha-1
 network-object host 10.32.134.100
 network-object host 10.32.134.107
 network-object host 10.32.134.108
 network-object host 10.32.134.162
 network-object host 10.32.134.163
 network-object host 10.88.12.70
 network-object host 10.88.12.71
 network-object host 10.88.12.72
object-group network hp_vendor_vpn-global-1
 network-object 15.219.153.192 255.255.255.192
 network-object 15.195.201.192 255.255.255.192
 network-object 15.203.233.192 255.255.255.224
object-group network microsoft_vpn_support-sjc-1
 network-object host 131.107.0.135
 network-object host 131.107.0.136
 network-object host 131.107.0.144
 network-object host 131.107.0.148
 network-object host 131.107.0.149
 network-object host 131.107.0.138
 network-object host 131.107.0.140
 network-object host 131.107.0.142
 network-object host 131.107.0.145
 network-object host 207.46.125.12
 network-object host 207.46.125.13
 network-object host 205.248.102.75
 network-object host 205.248.102.74
object-group network cco_dr_hosts-rtp-1
 network-object host 64.102.255.109
 network-object host 64.102.255.110
 network-object host 64.102.255.101
 network-object host 64.102.255.102
 network-object host 64.102.255.100
object-group network cco_dr_smx-rtp-1
 network-object host 171.70.144.82
 network-object host 171.70.144.83
 network-object host 171.70.144.86
 network-object host 171.68.10.148
 network-object host 171.70.144.84
 network-object host 171.70.144.85
 network-object host 171.70.144.87
object-group network orative_int_auth-sjc-1
 network-object host 172.27.188.20
 network-object host 172.27.188.21
 network-object host 172.27.188.22
 network-object host 172.27.188.23
 network-object host 172.27.188.24
 network-object host 172.27.188.25
 network-object host 172.27.188.52
 network-object host 172.27.188.54
object-group network ace_dmz_test_env-sjc-1
 network-object 128.107.74.160 255.255.255.240
object-group network cognio_vpn_external-rtp-1
 network-object host 64.102.253.90
 network-object host 64.102.253.94
object-group network cognio_vpn_internal-rtp-1
 network-object host 65.207.96.7
object-group network netqos_servers-global-1
 network-object host 144.254.73.15
 network-object host 144.254.73.71
 network-object host 171.70.178.119
 network-object host 171.70.178.120
 network-object host 171.70.178.121
 network-object host 171.70.178.122
 network-object host 171.70.178.123
 network-object host 171.70.178.124
 network-object host 171.70.89.236
 network-object host 173.37.180.198
 network-object host 173.37.180.199
 network-object host 64.100.38.28
 network-object host 72.163.192.111
 network-object host 72.163.192.5
 network-object host 173.37.180.168
 network-object host 64.100.39.40
 network-object host 64.100.38.29
 network-object host 64.104.123.92
 network-object host 64.104.15.62
 network-object host 64.104.193.75
 network-object host 173.37.246.29
object-group network sciatl_dmz_bcp-sciatl-1
 network-object host 64.102.245.40
 network-object host 64.102.245.41
 network-object host 64.102.245.51
 network-object host 64.102.245.52
 network-object host 64.102.245.54
 network-object host 64.102.245.55
object-group network ipass_ext_hosts-global-1
 network-object host 204.198.128.102
 network-object host 212.113.31.130
 network-object host 203.102.167.170
 network-object host 216.239.102.125
 network-object host 216.239.111.125
 network-object host 216.239.108.125
 network-object host 216.239.110.125
 network-object host 216.239.105.125
 network-object host 216.239.104.125
 network-object host 208.212.202.21
 network-object host 216.239.101.125
 network-object host 216.239.99.125
 network-object host 216.239.98.125
 network-object host 216.239.109.125
 network-object host 216.239.103.125
 network-object host 216.239.107.125
object-group network dmzdc_dns_svr-sjc-1
 network-object host 128.107.241.182
 network-object host 128.107.241.183
 network-object host 128.107.241.184
 network-object host 128.107.241.185
object-group network vpn_concentrator-sing-1
 network-object host 64.104.88.228
 network-object host 64.104.88.229
 network-object host 64.104.88.230
object-group network vpn_concentrator-hk-1
 network-object host 64.104.123.4
 network-object host 64.104.123.5
 network-object host 64.104.123.6
object-group network vpn_concentrator-bgl-1
 network-object host 64.104.142.3
 network-object host 64.104.142.5
 network-object host 64.104.142.6
object-group network vpn_concentrator-isr-1
 network-object host 192.118.79.6
 network-object host 192.118.79.7
 network-object host 192.118.79.8
object-group network vpn_concentrator-japan-1
 network-object host 64.104.14.228
 network-object host 64.104.14.229
 network-object host 64.104.14.230
 network-object host 64.104.14.244
 network-object host 64.104.14.245
object-group network vpn_concentrator-brnt-1
 network-object host 196.25.175.35
object-group network vpn_concentrator-syd-1
 network-object host 64.104.192.129
 network-object host 64.104.192.130
object-group network vpn_concentrator-rtp-1
 network-object host 64.102.252.2
 network-object host 64.102.252.3
 network-object host 64.102.252.4
 network-object host 64.102.252.5
 network-object host 64.102.252.6
 network-object host 64.102.252.11
 network-object host 64.102.252.7
object-group network vpn_ggsg_concentrator-rtp-1
 network-object host 64.102.222.4
 network-object host 64.102.222.5
 network-object host 64.102.222.6
object-group network vpn_concentrator-rich-1
 network-object host 12.5.186.34
 network-object host 12.5.186.35
 network-object host 12.5.186.36
object-group network vpn_concentrator-bgl-2
 network-object host 72.163.198.165
 network-object host 72.163.198.166
 network-object host 72.163.198.167
 network-object host 72.163.198.168
 network-object host 72.163.198.169
 network-object host 72.163.198.170
 network-object host 72.163.198.171
object-group network asa_vpn-sjc-1
 network-object host 171.70.192.76
 network-object host 171.70.192.77
 network-object host 171.70.192.78
 network-object host 171.70.192.79
object-group network sjc_vpn_40-sjc-1
 network-object host 171.70.192.34
 network-object host 171.70.192.35
 network-object host 171.70.192.36
object-group network vpn_concentrator-sjc-1
 network-object host 171.70.192.83
 network-object host 171.70.192.82
object-group network AnyConnect-Provision-ASAs-SJ
 network-object host 171.70.192.69
 network-object host 171.70.192.70
 network-object host 171.70.192.71
object-group network vpn_concentrator_ams
 network-object host 144.254.221.37
 network-object host 144.254.221.38
 network-object host 144.254.221.39
 network-object host 144.254.221.40
 network-object host 144.254.221.41
 network-object host 144.254.221.42
object-group network vpn_concentrator_asa-bxb-1
 network-object host 198.135.0.164
 network-object host 198.135.0.165
 network-object host 198.135.0.166
 network-object host 198.135.0.167
 network-object host 198.135.0.168
object-group network vpn_concentrator-shn-1
 network-object host 72.163.248.228
 network-object host 72.163.248.229
 network-object host 72.163.248.230
object-group network vpn_concentrator_crdc-shn-1
 network-object host 72.163.248.212
 network-object host 72.163.248.213
 network-object host 72.163.248.214
object-group network vpn_concentrator_ect-shn-1
 network-object host 72.163.248.241
object-group network sjc_vpn_41-sjc-1
 network-object host 171.70.192.34
 network-object host 171.70.192.35
 network-object host 171.70.192.36
object-group network ect-global-1
 network-object host 171.70.192.2
 network-object host 171.70.192.3
 network-object host 171.70.192.5
 network-object host 171.70.192.6
 network-object host 171.70.192.7
 network-object host 171.70.192.8
 network-object host 171.70.192.9
 network-object host 171.70.192.10
 network-object host 171.70.192.25
object-group network auth_src-sjc-1
 network-object host 128.107.224.210
 network-object host 128.107.224.211
 network-object host 128.107.224.212
object-group network auth_dest-sjc-1
 network-object host 171.70.144.141
 network-object host 171.70.144.142
 network-object host 171.70.144.143
object-group network ect-hk-1
 network-object host 64.104.123.19
 network-object host 64.104.123.20
 network-object host 64.104.123.17
object-group network ect-tokyo-1
 network-object host 64.104.15.225
 network-object host 64.104.15.226
object-group network xnet_vpn_concentrators-sjc-1
 network-object host 171.71.3.4
 network-object host 171.71.3.6
 network-object host 171.71.3.14
 network-object host 171.71.3.26
 network-object host 171.71.3.10
object-group network microsoft_vpn_support-sjc-2
 network-object host 131.107.0.135
 network-object host 131.107.0.136
 network-object host 207.46.125.12
 network-object host 207.46.125.13
object-group network outbound_vpn-sjc-1
 network-object host 161.225.129.27
 network-object host 208.42.68.11
object-group network agilent_vpn_ext-sjc-1
 network-object host 192.25.240.21
 network-object host 192.25.142.21
object-group network agilent_vpn_int-sjc-1
 network-object host 171.71.136.92
 network-object host 171.71.136.93
 network-object host 171.71.136.101
 network-object host 171.71.146.66
 network-object host 128.107.128.45
 network-object host 128.107.132.95
object-group network hotspot_bbsm-ams-1
 network-object host 10.61.32.82
 network-object host 10.48.101.18
 network-object host 10.60.15.195
 network-object host 10.48.101.20
 network-object host 144.254.129.57
 network-object host 10.52.245.1
 network-object host 144.254.133.121
 network-object host 10.59.15.193
 network-object host 10.58.15.195
 network-object host 144.254.137.25
 network-object host 144.254.135.25
 network-object host 144.254.132.89
 network-object host 144.254.134.89
 network-object host 10.50.15.193
 network-object host 144.254.128.153
 network-object host 144.254.135.217
 network-object host 10.59.18.244
 network-object host 144.254.128.121
 network-object host 144.254.128.217
 network-object host 10.52.22.5
 network-object host 144.254.130.57
 network-object host 144.254.129.185
 network-object host 144.254.129.121
 network-object host 144.254.131.57
 network-object host 144.254.132.57
 network-object host 144.254.131.249
 network-object host 144.254.133.249
 network-object host 144.254.136.25
 network-object host 10.57.19.241
 network-object host 144.254.138.153
 network-object host 144.254.139.153
 network-object host 144.254.129.249
 network-object host 144.254.134.185
 network-object host 10.59.17.241
 network-object host 144.254.133.89
 network-object host 144.254.132.121
 network-object host 144.254.131.26
 network-object host 10.61.32.133
 network-object host 144.254.134.153
 network-object host 10.53.32.129
 network-object host 144.254.136.57
object-group network hotspot_bbsm-hk-1
 network-object 10.74.193.0 255.255.255.128
 network-object 10.74.1.0 255.255.255.0
 network-object 10.74.65.0 255.255.255.128
 network-object 10.74.97.0 255.255.255.128
 network-object 10.74.129.0 255.255.255.128
 network-object 10.74.160.64 255.255.255.224
 network-object 10.74.184.64 255.255.255.192
 network-object 10.72.32.64 255.255.255.224
 network-object 10.72.65.0 255.255.255.128
object-group network hotspot_bbsm-sing-1
 network-object 10.68.1.0 255.255.255.0
 network-object 10.68.65.0 255.255.255.128
 network-object 10.68.81.0 255.255.255.128
 network-object 10.68.97.0 255.255.255.128
 network-object 10.68.120.64 255.255.255.224
 network-object 10.68.128.64 255.255.255.224
 network-object 10.68.112.64 255.255.255.224
 network-object 10.68.136.64 255.255.255.224
 network-object 10.68.144.64 255.255.255.224
object-group network ect-ntn-1
 network-object host 192.118.79.33
 network-object host 192.118.79.34
object-group network ect-ams-1
 network-object host 144.254.220.185
 network-object host 144.254.220.186
 network-object host 144.254.220.141
object-group network mp_dmz_ext-sjc-1
 network-object host 128.107.233.37
 network-object host 128.107.241.117
 network-object host 128.107.241.118
object-group network mp_dmz_int-sjc-1
 network-object host 10.32.135.100
 network-object host 10.32.135.101
 network-object host 10.32.157.30
 network-object host 10.32.157.31
object-group network cco_download_svr-rtp-1
 network-object host 64.102.255.117
 network-object host 64.102.255.118
 network-object host 64.102.255.119
 network-object host 64.102.255.120
object-group network cco_download_svr_auth-rtp-1
 network-object host 171.70.144.82
 network-object host 171.70.144.83
 network-object host 171.70.144.86
 network-object host 171.68.10.148
object-group network dmz_siteminder-sjc-1
 network-object host 198.133.219.171
 network-object host 198.133.219.172
 network-object host 198.133.219.173
 network-object host 198.133.219.175
 network-object host 198.133.219.176
 network-object host 198.133.219.177
 network-object host 198.133.219.179
 network-object host 198.133.219.180
 network-object host 198.133.219.181
 network-object host 198.133.219.187
 network-object host 198.133.219.188
 network-object host 198.133.219.189
 network-object host 198.133.219.182
 network-object host 198.133.219.183
 network-object host 198.133.219.184
 network-object host 198.133.219.185
 network-object host 198.133.219.11
 network-object host 198.133.219.12
 network-object host 128.107.242.143
 network-object host 128.107.242.144
 network-object host 128.107.242.183
 network-object host 128.107.242.147
object-group network hotspot_pilot-rtp-1
 network-object host 64.102.241.34
 network-object host 64.102.241.35
 network-object host 64.102.241.36
object-group network hotspot_pilot-sjc-1
 network-object host 171.70.144.141
 network-object host 171.70.144.142
 network-object host 171.70.144.143
object-group network vpn_tac_support-global-1
 network-object host 64.101.152.24
 network-object host 64.101.152.25
 network-object host 64.101.153.21
 network-object host 64.101.153.22
object-group network esenoc_vpn-rtp-1
 network-object host 64.102.223.132
 network-object host 64.102.223.130
 network-object host 64.102.223.134
object-group network ese_vpn-rtp-1
 network-object host 64.102.223.23
 network-object host 64.102.223.24
 network-object host 64.102.223.25
object-group network ect-rtp-1
 network-object host 64.102.223.3
 network-object host 64.102.223.4
 network-object host 64.102.223.23
 network-object host 64.102.223.24
 network-object host 64.102.223.25
 network-object host 64.102.7.50
 network-object host 64.100.36.241
object-group network anyconnect_xmm_rcd-rcdn-1
 network-object host 72.163.6.8
 network-object host 72.163.6.9
object-group network anyconnect_int_ds_hosts-rcdn-1
 network-object host 72.163.56.102
 network-object host 171.68.38.106
 network-object host 171.68.224.6
object-group network anyconnect_exchange_hosts-rcdn-1
 network-object host 72.163.62.158
 network-object host 72.163.62.222
 network-object host 72.163.63.30
 network-object host 72.163.129.198
 network-object host 64.104.123.83
 network-object host 144.254.231.90
 network-object host 171.70.151.132
 network-object host 128.107.191.10
object-group network hp_vendor_vpn_ext-rtp-1
 network-object host 156.153.32.179
 network-object host 156.153.37.11
 network-object host 156.152.0.27
 network-object host 192.6.149.2
object-group network hp_vendor_vpn_int-rtp-1
 network-object host 64.102.35.65
 network-object host 64.102.35.66
 network-object host 64.102.35.67
 network-object host 64.102.35.68
 network-object host 64.102.35.69
 network-object host 64.102.35.70
object-group network hp_vendor_vpn_int-sjc-1
 network-object host 171.71.82.39
 network-object host 171.71.82.40
 network-object host 171.71.82.107
 network-object host 171.71.82.108
 network-object host 171.71.82.141
 network-object host 171.71.82.142
 network-object host 171.71.82.143
 network-object host 171.71.82.144
 network-object host 171.71.82.145
 network-object host 171.71.82.146
 network-object host 171.71.82.147
 network-object host 171.71.82.148
 network-object host 171.71.82.149
 network-object host 171.71.82.150
object-group network japan_site2site_vpn_backup-tokyo-1
 network-object host 60.45.180.122
 network-object host 211.129.214.33
 network-object host 61.118.255.118
 network-object host 61.119.224.184
 network-object host 222.146.248.157
object-group network alpha_lwapp-sjc-1
 network-object host 171.70.35.130
 network-object host 171.70.35.131
 network-object host 171.70.35.132
 network-object host 171.70.35.133
 network-object host 171.70.35.134
 network-object host 171.70.35.135
 network-object host 171.70.35.136
 network-object host 171.70.35.137
object-group network sjc_wgsx-sjc-1
 network-object 128.107.225.144 255.255.255.240
 network-object 128.107.242.128 255.255.255.128
 network-object 128.107.74.128 255.255.255.224
 network-object 128.107.74.16 255.255.255.240
 network-object 128.107.74.32 255.255.255.224
 network-object 204.69.199.64 255.255.255.224
 network-object 198.133.219.0 255.255.255.0
 network-object host 128.107.234.202
 network-object host 128.107.234.203
 network-object host 128.107.248.83
object-group network rtp_wgsx-rtp-1
 network-object 64.102.243.128 255.255.255.128
 network-object 64.102.255.64 255.255.255.192
 network-object host 64.102.246.169
object-group network ldap_dsx_servers-global-1
 network-object host 171.71.184.6
 network-object host 171.68.224.207
 network-object host 72.163.57.6
 network-object host 173.37.137.6
 network-object host 64.102.9.230
 network-object host 173.38.202.104
object-group network eam_monitors-global-1
 network-object host 144.254.71.141
 network-object host 72.163.128.13
 network-object host 144.254.10.20
 network-object host 161.44.124.8
 network-object host 64.104.123.150
 network-object host 64.103.101.141
 network-object host 64.101.128.13
 network-object host 64.102.6.141
 network-object host 64.104.76.146
 network-object host 171.70.168.141
 network-object host 171.70.168.172
 network-object host 171.68.226.84
 network-object host 64.104.200.225
 network-object host 64.104.14.144
 network-object host 173.37.87.135
 network-object 173.37.87.128 255.255.255.192
 network-object 173.37.137.64 255.255.255.192
object-group network dmz_dns-rch-1
 network-object host 72.163.5.198
 network-object host 72.163.5.199
 network-object host 72.163.5.200
object-group network dmz_dns-sjc-1
 network-object host 128.107.241.182
 network-object host 128.107.241.183
 network-object host 128.107.241.184
 network-object host 128.107.241.174
 network-object host 128.107.241.181
object-group network dmz_dns-rtp-1
 network-object host 64.102.255.42
 network-object host 64.102.255.43
 network-object host 64.102.255.50
 network-object host 64.102.255.51
object-group network smtp_servers-linksys-1
 network-object host 66.153.61.98
 network-object host 66.161.11.5
object-group network outbound_vpn-global-1
 network-object host 10.49.167.241
 network-object host 10.49.215.193
 network-object host 10.49.223.195
 network-object host 10.51.95.193
 network-object host 10.52.22.3
 network-object host 10.52.22.7
 network-object host 10.52.245.33
 network-object host 10.52.245.34
 network-object host 10.52.245.35
 network-object host 10.53.31.228
 network-object host 10.56.223.129
 network-object host 10.57.18.241
 network-object host 10.57.19.241
 network-object host 10.57.23.241
 network-object host 10.58.23.232
 network-object host 10.58.36.5
 network-object host 10.59.17.241
 network-object host 10.61.32.133
 network-object host 144.254.128.185
 network-object host 144.254.128.249
 network-object host 144.254.129.249
 network-object host 144.254.130.249
 network-object host 144.254.131.185
 network-object host 144.254.131.209
 network-object host 144.254.131.26
 network-object host 144.254.132.121
 network-object host 144.254.132.153
 network-object host 144.254.132.217
 network-object host 144.254.133.185
 network-object host 144.254.133.217
 network-object host 144.254.133.25
 network-object host 144.254.133.89
 network-object host 144.254.134.153
 network-object host 144.254.134.185
 network-object host 144.254.134.25
 network-object host 144.254.134.57
 network-object host 144.254.135.89
 network-object host 144.254.136.153
 network-object host 144.254.136.89
 network-object host 144.254.138.153
 network-object host 144.254.138.25
 network-object host 144.254.139.153
 network-object host 144.254.139.89
 network-object host 144.254.141.153
object-group network uc_verizon_sip_trunk-rtp-1
 description Verizon PSTN SIP Trunk CUBE gateways RTP
 network-object host 64.102.244.136
 network-object host 64.102.244.137
object-group network uc_cucm_subscribers-rtp-1
 description Call Manager Subscribers Eastern USA
 network-object host 64.100.36.166
 network-object host 64.100.24.203
 network-object host 64.100.24.204
 network-object host 64.100.36.167
 network-object host 64.102.2.90
 network-object host 64.100.24.205
 network-object host 64.102.117.6
 network-object host 64.100.25.23
 network-object host 64.102.117.7
 network-object host 64.100.25.24
 network-object host 64.102.117.8
 network-object host 64.100.25.39
 network-object host 64.100.24.221
 network-object host 64.102.2.22
 network-object host 64.102.2.31
 network-object host 64.100.24.232
 network-object host 64.100.145.250
 network-object host 64.100.145.251
 network-object host 161.44.122.121
 network-object host 161.44.172.102
 network-object host 161.44.172.81
 network-object host 161.44.122.132
 network-object host 161.44.208.221
 network-object host 161.44.204.167
 network-object host 161.44.204.169
 network-object host 161.44.208.232
 network-object host 172.18.157.18
 network-object host 172.18.157.19
 network-object host 64.100.36.175
 network-object host 64.100.24.207
 network-object host 64.100.24.208
 network-object host 64.100.36.176
 network-object host 64.100.36.177
 network-object host 64.100.24.209
 network-object host 64.100.145.252
 network-object host 64.100.145.253
 network-object host 64.100.36.178
 network-object host 64.100.24.194
 network-object host 64.100.24.195
 network-object host 64.100.36.179
object-group network uc_cucm_subscribers-sjc-1
 description Call Manager Subscribers Western USA
 network-object host 171.70.112.212
 network-object host 171.68.196.222
 network-object host 171.70.112.213
 network-object host 171.68.196.223
 network-object host 171.70.112.214
 network-object host 171.68.196.224
 network-object host 171.70.112.215
 network-object host 171.68.196.225
 network-object host 171.70.112.216
 network-object host 171.68.196.226
 network-object host 171.70.112.217
 network-object host 171.68.196.227
 network-object host 171.70.112.218
 network-object host 171.68.196.228
 network-object host 171.70.112.219
 network-object host 171.68.196.229
 network-object host 171.70.112.204
 network-object host 171.68.196.204
 network-object host 171.70.112.205
 network-object host 171.68.196.205
 network-object host 171.68.38.28
 network-object host 171.68.38.29
 network-object host 72.163.36.151
 network-object host 72.163.36.152
 network-object host 171.68.196.200
 network-object host 171.68.196.207
 network-object host 171.68.196.209
 network-object host 171.68.196.211
 network-object host 171.68.196.213
 network-object host 171.68.196.216
 network-object host 171.68.196.217
 network-object host 171.68.196.219
 network-object host 72.163.36.136
 network-object host 72.163.36.137
 network-object host 72.163.36.138
 network-object host 72.163.36.139
 network-object host 72.163.36.140
 network-object host 72.163.36.141
 network-object host 72.163.36.142
 network-object host 72.163.36.143
 network-object host 173.36.131.142
 network-object host 173.36.131.143
 network-object host 171.70.146.211
 network-object host 173.36.131.144
 network-object host 171.70.146.212
 network-object host 173.36.131.145
 network-object host 171.70.146.213
 network-object host 173.36.131.146
 network-object host 171.70.146.214
 network-object host 173.36.131.147
 network-object host 171.70.146.215
 network-object host 173.36.131.148
 network-object host 171.70.146.216
 network-object host 173.36.131.149
 network-object host 171.70.146.217
 network-object host 173.36.131.150
 network-object host 171.70.146.218
 network-object host 173.36.131.153
 network-object host 171.70.146.219
object-group network uc_cucm_subscribers-ams-1
 description Call Manager Subscribers EMEA
 network-object host 64.103.100.11
 network-object host 64.103.100.12
 network-object host 64.103.100.14
 network-object host 64.103.100.13
 network-object host 144.254.210.7
 network-object host 144.254.210.8
 network-object host 144.254.210.10
 network-object host 144.254.210.32
 network-object host 144.254.210.33
 network-object host 144.254.210.34
 network-object host 10.48.0.100
 network-object host 10.48.0.101
 network-object host 10.48.0.102
 network-object host 10.48.0.103
object-group network web_security_appliances_mgmt
 network-object 10.81.52.32 255.255.255.224
 network-object 10.61.46.32 255.255.255.224
 network-object 10.64.63.128 255.255.255.224
 network-object 10.56.109.128 255.255.255.224
 network-object 10.101.14.64 255.255.255.224
 network-object 172.17.153.160 255.255.255.224
 network-object 10.68.12.96 255.255.255.224
 network-object 10.66.129.176 255.255.255.240
 network-object 10.75.225.224 255.255.255.224
 network-object 10.70.224.224 255.255.255.224
 network-object 10.64.47.128 255.255.255.224
 network-object 10.70.237.192 255.255.255.192
 network-object 10.115.8.224 255.255.255.224
object-group network uc_verizon_sip_trunk-sjc-1
 description Verizon PSTN SIP Trunk CUBE gateways SJC
 network-object host 128.107.240.56
 network-object host 128.107.240.57
 network-object host 128.107.240.58
object-group network uc_verizon_sip_trunk-ams-1
 description Verizon PSTN SIP Trunk CUBE gateways AMS
 network-object host 10.61.32.12
 network-object host 10.61.32.23
object-group network eman_networks-global-1
object-group network cisco_dns-global-1
 network-object host 128.107.241.185
 network-object host 64.102.255.44
 network-object host 171.68.226.120
 network-object host 171.70.168.183
 network-object host 64.104.14.184
 network-object host 64.103.101.184
 network-object host 64.104.200.248
 network-object host 64.104.76.247
 network-object host 144.254.10.123
 network-object host 161.44.124.122
 network-object host 64.104.123.245
 network-object host 144.254.71.184
 network-object host 72.163.128.140
 network-object host 64.102.6.247
 network-object host 173.37.87.157
 network-object host 72.163.47.11
 network-object host 173.37.137.85
 network-object host 173.37.142.73
 network-object host 64.101.128.56
 network-object host 173.38.200.100
 network-object host 173.36.10.138
 network-object host 173.36.10.10
object-group network Internal_TandbergVCE-syd-1
 network-object host 64.104.249.4
 network-object host 64.104.249.5
 network-object host 64.104.249.6
 network-object host 64.104.249.7
object-group network csirt_splunk_logging
 network-object host 172.18.240.120
 network-object host 172.18.240.121
 network-object host 172.18.240.122
 network-object host 72.163.132.165
 network-object host 173.37.108.25
 network-object host 171.69.162.25
 network-object host 10.66.131.6
 network-object host 64.103.113.4
 network-object host 144.254.226.79
 network-object host 10.68.3.23
 network-object host 173.37.114.102
 network-object host 173.36.9.173
 network-object host 173.36.128.147
 network-object host 172.18.240.18
object-group network sj_alpha_vcse
 network-object host 128.107.83.69
 network-object host 128.107.83.70
 network-object host 128.107.83.74
object-group network sj_alpha_vcs_control
 network-object host 10.35.16.109
 network-object host 10.35.16.113
 network-object host 10.35.16.105
 network-object host 10.35.63.136
 network-object host 10.35.63.134
 network-object host 10.42.23.54
object-group network csg-china-networks
 network-object 10.224.0.0 255.255.0.0
 network-object 10.225.0.0 255.255.224.0
 network-object 10.225.32.0 255.255.224.0
 network-object 173.39.160.0 255.255.224.0
 network-object 72.163.247.192 255.255.255.240
object-group network Corp_RA_VPN_Concentrators
 group-object vpn_concentrator-sing-1
 group-object vpn_concentrator-hk-1
 group-object vpn_concentrator-bgl-1
 group-object vpn_concentrator-isr-1
 group-object vpn_concentrator-japan-1
 group-object vpn_concentrator-brnt-1
 group-object vpn_concentrator-syd-1
 group-object vpn_concentrator-rtp-1
 group-object vpn_ggsg_concentrator-rtp-1
 group-object vpn_concentrator-rich-1
 group-object vpn_concentrator-bgl-2
 group-object vpn_concentrator-sjc-1
 group-object vpn_concentrator_asa-bxb-1
 group-object vpn_concentrator-shn-1
 group-object vpn_concentrator_crdc-shn-1
 group-object vpn_concentrator_ect-shn-1
 group-object vpn_concentrator_ams
object-group network SPVTAC-vpn
 network-object host 64.100.92.11
 network-object host 64.100.92.12
 network-object host 64.100.92.13
object-group network DMZ_TandbergVCE-TYO-1
 network-object 64.104.44.192 255.255.255.224
object-group network Internal_TandbergVCS-TYO-1
 network-object 64.104.2.192 255.255.255.192
object-group network DMZ_TandbergVCE-BGL-1
 network-object 72.163.217.32 255.255.255.224
object-group network Internal_TandbergVCS-BGL-1
 network-object 64.103.209.192 255.255.255.192
object-group network uc_cucm_subscribers-sjc-alpha
 network-object host 10.35.48.102
 network-object host 10.35.48.103
 network-object host 10.35.50.189
 network-object host 10.35.50.190
object-group network uc_verizon_sip_trunk-sjc-alpha
 network-object host 128.107.240.58
object-group network V4-ETE-ORION-SERVERS
 network-object host 171.68.106.28
 network-object host 171.68.106.29
 network-object host 171.68.106.30
object-group service ion-services
 service-object udp eq isakmp 
 service-object udp eq 4500 
 service-object udp eq 10000 
 service-object tcp eq pptp 
 service-object esp 
 service-object ah 
 service-object tcp eq smtp 
 service-object tcp eq pop3 
 service-object tcp eq imap4 
 service-object tcp eq 6665 
 service-object tcp eq 6666 
 service-object tcp eq 6667 
 service-object tcp eq 6697 
 service-object tcp eq 6000 
 service-object tcp eq ssh 
 service-object tcp eq telnet 
object-group network ion-networks
 network-object 10.102.0.0 255.254.0.0
object-group network swvpn_sjc-prod-1
 network-object host 171.70.192.73
 network-object host 171.70.192.80
 network-object host 171.70.192.82
 network-object host 171.70.192.83
 network-object host 171.70.192.86
 network-object host 171.70.192.87
 network-object host 171.70.192.88
 network-object host 171.70.192.89
 network-object host 171.70.192.90
object-group network V4-ACE-ORION-SERVERS
 network-object host 171.68.106.36
 network-object host 171.68.106.37
 network-object host 171.68.106.38
object-group network ipv6_dmz_rtbh-global-1
object-group network ipv6_snmp_managers-global-1
 network-object 2001:420:5e8d:1::/64
 network-object 2001:420:118d:1000::/64
 network-object 2001:420:548d:1::/64
 network-object 2001:420:2c6d:1::/64
 network-object 2001:420:464d:2000::/64
 network-object 2001:420:5a8d:1::/64
 network-object 2001:420:464d:1::/64
 network-object 2001:420:200:1::/64
 network-object 2001:420:508d:1::/64
 network-object 2001:420:210d::/64
 network-object 2001:420:68d:4001::/64
 network-object 2001:420:1080:3001::/64
 network-object 2001:420:5c8d:1::/64
object-group network ipv6_multicast_networks-global-1
 network-object ff00::/8
object-group network ipv6_dmz_loopbacks-bxb-1
 network-object 2001:420:2c48:100::/59
object-group network ipv6_dmz_loopbacks-singapore-1
 network-object 2001:420:5c21:100::/59
object-group network ipv6_dmz_loopbacks-isr-1
 network-object 2001:420:4481:100::/59
object-group network ipv6_dmz_loopbacks-alln-1
 network-object 2001:420:1200:100::/59
object-group network ipv6_dmz_loopbacks-rcdn9-1
 network-object 2001:420:1100:800::/59
object-group network ipv6_dmz_loopbacks-sjc-1
 network-object 2001:420:82:100::/59
object-group network ipv6_dmz_loopbacks-shanghai-1
 network-object 2001:420:5860:100::/59
object-group network ipv6_dmz_loopbacks-ams-1
 network-object 2001:420:4421:100::/59
object-group network ipv6_dmz_loopbacks-bgl-1
 network-object 2001:420:5420:600::/56
object-group network ipv6_dmz_loopbacks-hk-1
 network-object 2001:420:5a20:100::/59
object-group network ipv6_dmz_loopbacks-rtp-1
 network-object 2001:420:2040:100::/59
object-group network ipv6_dmz_loopbacks-aus-1
 network-object 2001:420:5020:100::/59
object-group network ipv6_dmz_loopbacks-japan-1
 network-object 2001:420:5e20:100::/59
object-group network ipv6_dmz_networks-bxb-1
 network-object 2001:420:2c48::/45
object-group network ipv6_dmz_networks-singapore-1
 network-object 2001:420:5c20::/43
object-group network ipv6_dmz_networks-isr-1
 network-object 2001:420:4481::/48
object-group network ipv6_dmz_networks-alln-1
 network-object 2001:420:1200::/41
object-group network ipv6_dmz_networks-rcdn9-1
 network-object 2001:420:1100::/41
object-group network ipv6_dmz_networks-sjc-1
 network-object 2001:420:80::/41
object-group network ipv6_dmz_networks-shanghai-1
 network-object 2001:420:5860::/43
object-group network ipv6_dmz_networks-ams-1
 network-object 2001:420:4420::/43
object-group network ipv6_dmz_networks-bgl-1
 network-object 2001:420:5420::/43
object-group network ipv6_dmz_networks-hk-1
 network-object 2001:420:5a20::/43
object-group network ipv6_dmz_networks-rtp-1
 network-object 2001:420:2040::/42
object-group network ipv6_dmz_networks-aus-1
 network-object 2001:420:5020::/43
object-group network ipv6_dmz_networks-japan-1
 network-object 2001:420:5e20::/43
object-group network ipv6_cisco_internal_networks-global-1
 description ipv6 Internal Networks (from EMAN)
 network-object 2001:420:1180::/41
 network-object 2001:420:4400::/43
 network-object 2001:420:4440::/42
 network-object 2001:420:4480::/42
 network-object 2001:420:44c0::/42
 network-object 2001:420:2000::/42
 network-object 2001:420:2080::/42
 network-object 2001:420:2100::/42
 network-object 2001:420:2140::/42
 network-object 2001:420:21c0::/42
 network-object 2001:420:2200::/42
 network-object 2001:420:2240::/42
 network-object 2001:420:2280::/42
 network-object 2001:420:22c0::/42
 network-object 2001:420:2400::/42
 network-object 2001:420:2480::/42
 network-object 2001:420:24c0::/42
 network-object 2001:420:2600::/40
 network-object 2001:420:27c0::/42
 network-object 2001:420:20c0::/42
 network-object 2001:420:2180::/42
 network-object 2001:420:2300::/40
 network-object 2001:420:2440::/42
 network-object 2001:420:2500::/40
 network-object 2001:420:2700::/41
 network-object 2001:420:2780::/42
 network-object 2001:420:5400::/43
 network-object 2001:420:5440::/42
 network-object 2001:420:5480::/43
 network-object 2001:420:54bf::/48
 network-object 2001:420:54fe::/48
 network-object 2001:420:54ff::/48
 network-object 2001:420:54a0::/44
 network-object 2001:420:54b0::/45
 network-object 2001:420:54b8::/46
 network-object 2001:420:54bc::/47
 network-object 2001:420:54be::/48
 network-object 2001:420:54c0::/43
 network-object 2001:420:54e0::/44
 network-object 2001:420:54f0::/45
 network-object 2001:420:54f8::/46
 network-object 2001:420:54fc::/47
 network-object 2001:420:5500::/40
 network-object 2001:420:5600::/40
 network-object 2001:420:5700::/40
 network-object 2001:420:5a00::/43
 network-object 2001:420:5a40::/42
 network-object 2001:420:5a80::/42
 network-object 2001:420:5aff::/48
 network-object 2001:420:5ac0::/43
 network-object 2001:420:5ae0::/44
 network-object 2001:420:5af0::/45
 network-object 2001:420:5af8::/46
 network-object 2001:420:5afc::/47
 network-object 2001:420:5afe::/48
 network-object 2001:420:5b00::/40
 network-object 2001:420:5c00::/43
 network-object 2001:420:5c40::/42
 network-object 2001:420:5c80::/42
 network-object 2001:420:5cc0::/42
 network-object 2001:420:5d00::/40
 network-object 2001:420:5000::/43
 network-object 2001:420:5040::/42
 network-object 2001:420:5080::/42
 network-object 2001:420:50ff::/48
 network-object 2001:420:50c0::/43
 network-object 2001:420:50e0::/44
 network-object 2001:420:50f0::/45
 network-object 2001:420:50f8::/46
 network-object 2001:420:50fc::/47
 network-object 2001:420:50fe::/48
 network-object 2001:420:5100::/40
 network-object 2001:420:5e00::/43
 network-object 2001:420:5e40::/42
 network-object 2001:420:5e80::/42
 network-object 2001:420:5eff::/48
 network-object 2001:420:5ec0::/43
 network-object 2001:420:5ee0::/44
 network-object 2001:420:5ef0::/45
 network-object 2001:420:5ef8::/46
 network-object 2001:420:5efc::/47
 network-object 2001:420:5efe::/48
 network-object 2001:420:5f00::/40
 network-object 2001:420:2c50::/56
 network-object 2001:420:2c60::/44
 network-object 2001:420:2c7f::/48
 network-object 2001:420:2c42::/47
 network-object 2001:420:2c44::/46
 network-object 2001:420:2c50:100::/56
 network-object 2001:420:2c50:200::/55
 network-object 2001:420:2c50:400::/54
 network-object 2001:420:2c50:800::/53
 network-object 2001:420:2c50:1000::/52
 network-object 2001:420:2c50:2000::/51
 network-object 2001:420:2c50:4000::/50
 network-object 2001:420:2c50:8000::/49
 network-object 2001:420:2c51::/48
 network-object 2001:420:2c52::/47
 network-object 2001:420:2c54::/46
 network-object 2001:420:2c58::/45
 network-object 2001:420:2c70::/45
 network-object 2001:420:2c78::/46
 network-object 2001:420:2c7c::/47
 network-object 2001:420:2c7e::/48
 network-object 2001:420:4480::/48
 network-object 2001:420:4482::/48
 network-object 2001:420:4483::/48
 network-object 2001:420:4484::/46
 network-object 2001:420:5800::/42
 network-object 2001:420:5840::/43
 network-object 2001:420:58ff::/48
 network-object 2001:420:58cd::/48
 network-object 2001:420:5880::/42
 network-object 2001:420:58c0::/45
 network-object 2001:420:58c8::/46
 network-object 2001:420:58cc::/48
 network-object 2001:420:58ce::/47
 network-object 2001:420:58d0::/44
 network-object 2001:420:58e0::/44
 network-object 2001:420:58f0::/45
 network-object 2001:420:58f8::/46
 network-object 2001:420:58fc::/47
 network-object 2001:420:58fe::/48
 network-object 2001:420:5900::/40
 network-object 2001:420::/41
 network-object 2001:420:100::/41
 network-object 2001:420:180::/41
 network-object 2001:420:200::/41
 network-object 2001:420:280::/41
 network-object 2001:420:300::/40
 network-object 2001:420:400::/41
 network-object 2001:420:700::/42
 network-object 2001:420:740::/42
 network-object 2001:420:780::/41
 network-object 2001:420:480::/41
 network-object 2001:420:500::/40
 network-object 2001:420:800::/39
 network-object 2001:420:1000::/41
 network-object 2001:420:1080::/41
 network-object 2001:420:1700::/41
 network-object 2001:420:1780::/41
 network-object 2001:420:1280::/41
 network-object 2001:420:1300::/40
 network-object 2001:420:1400::/39
 network-object 2001:420:1600::/40
 network-object 2001:420:1800::/37
 network-object 2001:420:600::/43
 network-object 2001:420:680::/42
 network-object 2001:420:6c0::/42
 network-object 2001:420:640::/42
 network-object 2001:420:a00::/43
 network-object 2001:420:bff::/48
 network-object 2001:420:a40::/42
 network-object 2001:420:a80::/41
 network-object 2001:420:b00::/41
 network-object 2001:420:b80::/42
 network-object 2001:420:bc0::/43
 network-object 2001:420:be0::/44
 network-object 2001:420:bf0::/45
 network-object 2001:420:bf8::/46
 network-object 2001:420:bfc::/47
 network-object 2001:420:bfe::/48
 network-object 2001:420:d00::/40
 network-object 2001:420:f00::/40
 network-object 2001:420:2900::/40
 network-object 2001:420:2a40::/42
 network-object 2001:420:2a80::/41
 network-object 2001:420:2b00::/40
 network-object 2001:420:2d00::/40
 network-object 2001:420:3100::/40
 network-object 2001:420:3300::/40
 network-object 2001:420:3500::/40
 network-object 2001:420:4000::/43
 network-object 2001:420:4040::/48
 network-object 2001:420:4041::/48
 network-object 2001:420:4042::/48
 network-object 2001:420:4043::/48
 network-object 2001:420:4048::/48
 network-object 2001:420:4049::/48
 network-object 2001:420:404a::/48
 network-object 2001:420:404c::/48
 network-object 2001:420:404e::/48
 network-object 2001:420:4080::/42
 network-object 2001:420:40ff::/48
 network-object 2001:420:4044::/46
 network-object 2001:420:404b::/48
 network-object 2001:420:404d::/48
 network-object 2001:420:404f::/48
 network-object 2001:420:4050::/44
 network-object 2001:420:4060::/43
 network-object 2001:420:40c0::/43
 network-object 2001:420:40e0::/44
 network-object 2001:420:40f0::/45
 network-object 2001:420:40f8::/46
 network-object 2001:420:40fc::/47
 network-object 2001:420:40fe::/48
 network-object 2001:420:4100::/40
 network-object 2001:420:4200::/40
 network-object 2001:420:4300::/40
 network-object 2001:420:4600::/43
 network-object 2001:420:4640::/42
 network-object 2001:420:4680::/41
 network-object 2001:420:4d00::/40
 network-object 2001:420:4e00::/40
 network-object 2001:420:4f00::/40
 network-object 2001:420:4900::/40
 network-object 2001:420:4a00::/40
 network-object 2001:420:4b00::/40
 network-object 2001:420:4501::/48
 network-object 2001:420:4503::/48
 network-object 2001:420:4505::/48
 network-object 2001:420:4507::/48
 network-object 2001:420:448c::/48
 network-object 2001:420:448d::/48
 network-object 2001:420:448e::/48
 network-object 2001:420:448f::/48
 network-object 2001:420:4495::/48
 network-object 2001:420:4496::/48
 network-object 2001:420:4497::/48
 network-object 2001:420:4499::/48
 network-object 2001:420:449b::/48
 network-object 2001:420:449d::/48
 network-object 2001:420:449f::/48
 network-object 2001:420:44a2::/48
 network-object 2001:420:44a3::/48
 network-object 2001:420:44a5::/48
 network-object 2001:420:44a7::/48
 network-object 2001:420:44a9::/48
 network-object 2001:420:44ab::/48
 network-object 2001:420:44ad::/48
 network-object 2001:420:44af::/48
 network-object 2001:420:44b3::/48
 network-object 2001:420:44b6::/48
 network-object 2001:420:44bb::/48
 network-object 2001:420:44bd::/48
 network-object 2001:420:44bf::/48
 network-object 2001:420:44c6::/48
 network-object 2001:420:44c7::/48
 network-object 2001:420:44cd::/48
 network-object 2001:420:44ce::/48
 network-object 2001:420:44cf::/48
 network-object 2001:420:44d3::/48
 network-object 2001:420:44d4::/48
 network-object 2001:420:44d7::/48
 network-object 2001:420:44dd::/48
 network-object 2001:420:44de::/48
 network-object 2001:420:44df::/48
 network-object 2001:420:44ee::/48
 network-object 2001:420:44ef::/48
 network-object 2001:420:44f9::/48
 network-object 2001:420:44fa::/48
 network-object 2001:420:44fd::/48
 network-object 2001:420:2c40::/45
 network-object 2001:420:c00::/42
 network-object 2001:420:c40::/42
 network-object 2001:420:c80::/41
 network-object 2001:420:e00::/40
 network-object 2001:420:2800::/40
 network-object 2001:420:2a00::/43
 network-object 2001:420:2c00::/40
 network-object 2001:420:2e00::/40
 network-object 2001:420:2f00::/40
 network-object 2001:420:3000::/40
 network-object 2001:420:3200::/40
 network-object 2001:420:3400::/40
 network-object 2001:420:3600::/39
 network-object 2001:420:3800::/37
 network-object 2001:420:4500::/40
 network-object 2001:420:4700::/48
 network-object 2001:420:4701::/48
 network-object 2001:420:4702::/47
 network-object 2001:420:4704::/46
 network-object 2001:420:4708::/45
 network-object 2001:420:4710::/44
 network-object 2001:420:4720::/43
 network-object 2001:420:4740::/42
 network-object 2001:420:4780::/41
 network-object 2001:420:4800::/40
 network-object 2001:420:4c00::/40
 network-object 2001:420:5200::/40
 network-object 2001:420:5300::/40
object-group network IPV6_DMZ_SUBNETS
 description ipv6 DMZ Subnet Blocks
 network-object 2001:420:1200::/41
 network-object 2001:420:4420::/43
 network-object 2001:420:2040::/42
 network-object 2001:420:5420::/43
 network-object 2001:420:5a20::/43
 network-object 2001:420:5c20::/43
 network-object 2001:420:5020::/43
 network-object 2001:420:5e20::/43
 network-object 2001:420:2c48::/45
 network-object 2001:420:4481::/48
 network-object 2001:420:5860::/43
 network-object 2001:420:80::/41
 network-object 2001:420:1100::/41
 network-object 2001:420:620::/43
 network-object 2001:420:a20::/43
 network-object 2001:420:2a20::/43
 network-object 2001:420:4020::/43
 network-object 2001:420:4620::/43
object-group network ipv6_dmz_lab_nets
 description ipv6 Production DMZ Lab Networks
 network-object 2001:420:81::/48
 network-object 2001:420:4420::/48
object-group service tandberg-udp udp
 description udp ports (inside to outside)
 port-object eq 1719
 port-object range 2776 2777
 port-object range snmp snmptrap
 port-object eq 3478
 port-object range 6000 6010
 port-object range 50000 52399
 port-object range 60000 61799
object-group network tandberg-inside-ip
 network-object 2001:420:4:eaf0::/60
object-group network tandberg-outside-ip
 network-object 2001:420:4420:1::/64
object-group network amazon_ec2_us-west-1
 network-object 50.112.0.0 255.255.0.0
 network-object 54.245.0.0 255.255.0.0
 network-object 204.236.128.0 255.255.192.0
 network-object 184.72.0.0 255.255.192.0
 network-object 50.18.0.0 255.255.0.0
 network-object 184.169.128.0 255.255.128.0
 network-object 54.241.0.0 255.255.0.0
 network-object 54.244.0.0 255.255.0.0
 network-object 54.214.0.0 255.255.0.0
 network-object 54.215.0.0 255.255.0.0
object-group network amazon_ec2_us-east-1
 network-object 72.44.32.0 255.255.224.0
 network-object 67.202.0.0 255.255.192.0
 network-object 75.101.128.0 255.255.128.0
 network-object 174.129.0.0 255.255.0.0
 network-object 204.236.192.0 255.255.192.0
 network-object 184.73.0.0 255.255.128.0
 network-object 184.72.128.0 255.255.128.0
 network-object 184.72.64.0 255.255.192.0
 network-object 50.16.0.0 255.254.0.0
 network-object 50.19.0.0 255.255.0.0
 network-object 107.20.0.0 255.252.0.0
 network-object 23.20.0.0 255.252.0.0
 network-object 54.242.0.0 255.254.0.0
 network-object 54.234.0.0 255.254.0.0
 network-object 54.236.0.0 255.254.0.0
 network-object 54.224.0.0 255.254.0.0
 network-object 54.226.0.0 255.254.0.0
 network-object 54.208.0.0 255.254.0.0
 network-object 54.210.0.0 255.254.0.0
object-group network amazon_ec2_apac-1
 network-object 175.41.128.0 255.255.192.0
 network-object 122.248.192.0 255.255.192.0
 network-object 46.137.192.0 255.255.192.0
 network-object 46.51.216.0 255.255.248.0
 network-object 54.251.0.0 255.255.0.0
 network-object 175.41.192.0 255.255.192.0
 network-object 46.51.224.0 255.255.240.0
 network-object 176.32.64.0 255.255.240.0
 network-object 103.4.8.0 255.255.248.0
 network-object 176.34.0.0 255.255.192.0
 network-object 54.248.0.0 255.254.0.0
 network-object 54.254.0.0 255.255.0.0
 network-object 54.255.0.0 255.255.0.0
 network-object 54.250.0.0 255.255.0.0
 network-object 54.252.0.0 255.255.0.0
 network-object 54.253.0.0 255.255.0.0
object-group network kumo_product_labs-1
 network-object 172.25.97.128 255.255.255.128
 network-object 192.168.94.0 255.255.255.0
 network-object 172.22.236.0 255.255.255.0
 network-object 10.106.192.0 255.255.255.0
 network-object 10.106.193.0 255.255.255.0
object-group service VCSC-TO-VCSE
 service-object udp eq 2776 
 service-object udp eq 2777 
 service-object udp eq 6001 
object-group service VCSE-TO-VCSC
 service-object udp eq 2776 
 service-object udp eq 2777 
 service-object udp eq 6001 
 service-object tcp eq 7001 
 service-object tcp eq 2776 
object-group network sj_alpha_vcs_express
 network-object host 128.107.85.182
 network-object host 128.107.85.183
 network-object host 128.107.85.184
object-group network webex-cn-hosts-InterCall-access
 network-object host 10.224.67.61
 network-object host 10.224.67.82
 network-object host 10.224.67.93
 network-object host 10.224.67.79
 network-object host 10.224.67.43
 network-object host 10.224.67.36
 network-object host 10.224.67.34
 network-object host 10.224.67.51
 network-object host 10.224.67.45
 network-object host 10.224.67.77
 network-object host 10.224.65.115
 network-object host 10.224.65.24
 network-object host 10.224.65.137
 network-object host 10.224.200.75
 network-object host 10.224.200.89
 network-object host 10.224.200.171
 network-object host 10.224.200.91
 network-object host 10.224.200.128
 network-object host 10.224.65.18
 network-object host 10.224.65.48
 network-object host 10.224.67.24
 network-object host 10.224.67.64
object-group network microsoft_azure_South_Central_US
 network-object 157.55.103.32 255.255.255.240
 network-object 157.55.103.48 255.255.255.240
 network-object 157.55.153.224 255.255.255.240
 network-object 157.55.176.0 255.255.240.0
 network-object 157.55.192.0 255.255.252.0
 network-object 157.55.196.0 255.255.252.0
 network-object 157.55.200.0 255.255.252.0
 network-object 157.55.80.0 255.255.252.0
 network-object 157.55.84.0 255.255.252.0
 network-object 168.62.128.0 255.255.224.0
 network-object 65.52.32.0 255.255.248.0
 network-object 65.54.48.0 255.255.248.0
 network-object 65.55.64.0 255.255.240.0
 network-object 65.55.80.0 255.255.240.0
 network-object 70.37.160.0 255.255.248.0
 network-object 70.37.48.0 255.255.240.0
 network-object 70.37.64.0 255.255.192.0
object-group network microsoft_azure_North_Central_US
 network-object 157.55.136.0 255.255.248.0
 network-object 157.55.151.0 255.255.255.240
 network-object 157.55.160.0 255.255.240.0
 network-object 157.55.208.0 255.255.248.0
 network-object 157.55.216.0 255.255.252.0
 network-object 157.55.220.0 255.255.252.0
 network-object 157.55.24.0 255.255.248.0
 network-object 157.55.252.0 255.255.252.0
 network-object 157.55.60.224 255.255.255.240
 network-object 157.55.60.240 255.255.255.240
 network-object 157.55.73.32 255.255.255.240
 network-object 157.56.12.0 255.255.252.0
 network-object 157.56.24.160 255.255.255.240
 network-object 157.56.24.176 255.255.255.240
 network-object 157.56.24.192 255.255.255.240
 network-object 157.56.28.0 255.255.252.0
 network-object 157.56.8.0 255.255.252.0
 network-object 168.62.224.0 255.255.240.0
 network-object 168.62.96.0 255.255.224.0
 network-object 207.46.192.0 255.255.240.0
 network-object 209.240.220.0 255.255.254.0
 network-object 65.52.0.0 255.255.224.0
 network-object 65.52.106.128 255.255.255.224
 network-object 65.52.106.16 255.255.255.240
 network-object 65.52.106.160 255.255.255.224
 network-object 65.52.106.192 255.255.255.224
 network-object 65.52.106.224 255.255.255.240
 network-object 65.52.106.240 255.255.255.240
 network-object 65.52.106.32 255.255.255.224
 network-object 65.52.106.64 255.255.255.224
 network-object 65.52.106.96 255.255.255.224
 network-object 65.52.107.0 255.255.255.240
 network-object 65.52.192.0 255.255.224.0
 network-object 65.52.232.0 255.255.252.0
 network-object 65.52.236.0 255.255.252.0
 network-object 65.52.240.0 255.255.252.0
 network-object 65.52.244.0 255.255.252.0
 network-object 65.52.48.0 255.255.240.0
object-group network microsoft_azure_East_US
 network-object 65.55.192.0 255.255.224.0
 network-object 65.55.224.0 255.255.224.0
 network-object 65.55.96.0 255.255.240.0
 network-object 157.56.176.0 255.255.248.0
 network-object 168.61.32.0 255.255.240.0
 network-object 168.62.160.0 255.255.224.0
 network-object 168.62.32.0 255.255.224.0
object-group network microsoft_azure_West_US
 network-object 157.56.160.0 255.255.248.0
 network-object 168.61.0.0 255.255.240.0
 network-object 168.61.16.0 255.255.248.0
 network-object 168.62.0.0 255.255.224.0
 network-object 168.62.192.0 255.255.240.0
 network-object 168.62.208.0 255.255.248.0
object-group network ipv6_dmz_loopbacks-brnt-1
object-group network ipv6_dmz_loopbacks-vancouver-1
object-group network ipv6_dmz_networks-brnt-1
object-group network ipv6_dmz_networks-vancouver-1
object-group network raex_oeap-global-1
 network-object host 72.163.215.150
 network-object host 72.163.215.151
 network-object host 72.163.248.182
 network-object host 72.163.248.183
 network-object host 64.104.240.22
 network-object host 64.104.240.23
 network-object host 72.163.19.164
 network-object host 72.163.19.165
 network-object host 72.163.19.166
 network-object host 72.163.19.167
 network-object host 64.102.252.38
 network-object host 64.102.252.39
 network-object host 64.102.252.40
 network-object host 64.102.252.41
 network-object host 64.102.252.42
 network-object host 64.104.83.52
 network-object host 64.104.83.53
 network-object host 64.104.83.54
object-group service webex_as_lab_onetouch_src_ports tcp-udp
 port-object range sip 5061
 port-object range 50000 52900
 port-object range 5070 5071
object-group service webex_as_lab_onetouch_destination_ports tcp-udp
 port-object eq 6001
 port-object eq 7001
 port-object range 2776 2777
object-group service xboxlive_services_udp udp
 port-object eq 88
 port-object eq 3074
 port-object eq 1863
 port-object eq 3330
 port-object eq 5353
object-group service ps3network_services_udp udp
 port-object eq 3478
 port-object eq 3479
 port-object eq 3658
 port-object eq 10070
object-group network kicker-global-1
 network-object host 64.100.35.33
 network-object host 64.100.35.34
 network-object host 171.70.177.12
 network-object host 171.70.177.13
 network-object host 173.37.113.168
 network-object host 173.37.113.169
 network-object host 144.254.72.85
 network-object host 144.254.72.86
 network-object host 72.163.197.21
 network-object host 72.163.197.22
object-group network GES_GLOBAL_NG_HUBS_DMVPN
 network-object host 171.71.3.147
 network-object host 171.71.3.148
 network-object host 64.104.81.243
 network-object host 64.104.81.244
 network-object host 173.36.6.147
 network-object host 173.36.6.148
 network-object host 64.104.155.146
 network-object host 64.104.155.147
 network-object host 64.104.155.210
 network-object host 64.104.155.211
 network-object host 64.100.45.147
 network-object host 64.100.45.148
object-group network GES_GLOBAL_NG_REMOTE_RLANVPN_DMVPN
 network-object host 68.120.110.138
 network-object host 61.47.104.214
 network-object host 122.52.239.153
 network-object host 222.127.10.155
 network-object host 200.76.187.6
 network-object host 98.142.91.26
 network-object host 200.124.196.73
 network-object host 128.242.110.162
 network-object host 119.151.96.2
object-group network ndcs-nw-raex-ect
 network-object host 171.70.192.12
 network-object host 64.102.253.76
 network-object host 198.135.0.180
 network-object host 72.163.19.148
 network-object host 64.104.123.16
 network-object host 144.254.220.33
 network-object host 192.118.79.37
 network-object host 64.104.15.229
object-group service raex-ect-services_tcp tcp
 description Server access ports for 881 routers for the ECT project
 port-object eq https
 port-object eq 8000
object-group network sng_ace_vcse
 network-object host 64.104.94.41
 network-object host 64.104.94.42
object-group network dmz_dns-aln3-1
 network-object host 173.37.146.38
 network-object host 173.37.146.39
 network-object host 173.37.146.40
object-group network dmz_networks-aer01-1
 network-object 173.38.208.0 255.255.240.0
object-group network VCS_Controls_TME_labs
 network-object host 10.22.189.41
 network-object host 10.22.189.42
 network-object host 10.22.189.43
 network-object host 10.22.185.199
 network-object host 10.95.17.51
 network-object host 10.95.17.52
 network-object host 172.19.236.4
 network-object host 172.19.236.5
object-group network sjc_ace_vcse
 network-object host 128.107.82.103
 network-object host 128.107.82.104
object-group network amazon_ec2_emea-1
 network-object 54.228.0.0 255.255.0.0
 network-object 54.216.0.0 255.254.0.0
 network-object 54.229.0.0 255.255.0.0
object-group network amazon_ec2_south_america-1
 network-object 54.233.0.0 255.255.192.0
object-group network DMZ_VCE-RTP-105_106
 network-object host 64.102.249.45
 network-object host 64.102.249.46
object-group network UCLAB319_OT2-VCSC-1_2
 network-object host 10.81.112.32
 network-object host 10.81.112.33

access-list 110 remark MANAGED BY FIREDRILL - last revision details - rswarnak - rev(1.571) - Mon May  6 21_13_51 2013
access-list 110 remark last n2i details - agopi - Mon May  6 23_17_01 2013
access-list 110 extended deny ip 127.0.0.0 255.0.0.0 any 
access-list 110 extended deny udp any any eq 1434 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 64.101.231.11 eq netbios-ssn 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 64.101.231.11 eq 445 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 64.101.231.11 eq tftp 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 gt 1023 host 64.101.231.11 gt 1023 
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 171.70.144.245 eq 445 
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 171.70.144.245 eq tftp 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 72.163.132.92 eq 445 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 72.163.132.92 eq tftp 
access-list 110 extended permit tcp 10.81.52.128 255.255.255.224 host 64.102.105.9 eq 445 
access-list 110 extended permit udp 10.81.52.128 255.255.255.224 host 64.102.105.9 eq tftp 
access-list 110 extended permit tcp 10.101.15.128 255.255.255.192 host 173.37.87.189 eq ftp 
access-list 110 extended permit tcp 10.101.206.0 255.255.254.0 host 173.37.87.189 eq ftp 
access-list 110 extended permit udp host 64.104.127.65 host 173.37.87.189 eq tftp 
access-list 110 extended permit udp host 64.104.95.129 host 173.37.87.189 eq tftp 
access-list 110 extended permit tcp host 128.107.227.11 host 173.37.87.189 eq ssh 
access-list 110 extended permit tcp host 128.107.227.12 host 173.37.87.189 eq ssh 
access-list 110 extended permit udp host 128.107.83.83 any range 16384 32767 
access-list 110 extended permit udp host 128.107.83.102 any range 16384 32767 
access-list 110 extended permit gre host 10.115.8.67 host 172.17.153.20 
access-list 110 extended permit gre host 10.115.8.68 host 128.107.240.170 
access-list 110 extended permit gre host 172.17.153.20 host 10.115.8.67 
access-list 110 extended permit gre host 128.107.240.170 host 10.115.8.68 
access-list 110 extended permit udp 144.254.51.80 255.255.255.240 10.50.176.0 255.255.240.0 eq 6001 
access-list 110 extended permit udp 144.254.51.80 255.255.255.240 10.50.176.0 255.255.240.0 eq 1719 
access-list 110 extended permit udp 144.254.51.80 255.255.255.240 10.50.176.0 255.255.240.0 eq 5050 
access-list 110 extended permit udp 144.254.51.80 255.255.255.240 10.50.176.0 255.255.240.0 eq 2776 
access-list 110 extended permit udp 144.254.51.80 255.255.255.240 10.50.176.0 255.255.240.0 eq 2777 
access-list 110 extended permit tcp 144.254.51.80 255.255.255.240 10.50.176.0 255.255.240.0 eq 2776 
access-list 110 extended permit tcp 144.254.51.80 255.255.255.240 10.50.176.0 255.255.240.0 eq 2777 
access-list 110 extended permit udp 144.254.51.80 255.255.255.240 10.50.176.0 255.255.240.0 range 52399 54999 
access-list 110 extended permit gre host 10.68.12.18 any 
access-list 110 extended permit gre host 10.68.12.19 any 
access-list 110 extended permit tcp object-group dmz_networks-rtp-1 object-group eman_syslog-global-1 eq rsh 
access-list 110 extended permit tcp object-group dmz_networks-rich-1 object-group eman_syslog-global-1 eq rsh 
access-list 110 extended permit tcp object-group dmz_networks-sjc-1 object-group eman_syslog-global-1 eq rsh 
access-list 110 extended permit tcp object-group dmz_networks-alln-1 object-group eman_syslog-global-1 eq rsh 
access-list 110 extended permit udp host 128.107.81.25 host 10.35.120.50 eq 902 
access-list 110 extended permit udp any object-group raex_oeap-global-1 eq 5246 
access-list 110 extended permit udp any object-group raex_oeap-global-1 eq 5247 
access-list 110 extended permit udp host 128.242.110.162 host 171.71.3.147 eq isakmp 
access-list 110 extended permit esp host 128.242.110.162 host 171.71.3.147 
access-list 110 extended permit udp host 128.242.110.162 host 171.71.3.148 eq isakmp 
access-list 110 extended permit esp host 128.242.110.162 host 171.71.3.148 
access-list 110 extended permit esp host 184.94.240.210 host 171.70.203.161 
access-list 110 extended permit esp host 184.94.240.211 host 171.70.203.161 
access-list 110 extended permit udp host 184.94.240.210 host 171.70.203.161 eq isakmp 
access-list 110 extended permit udp host 184.94.240.211 host 171.70.203.161 eq isakmp 
access-list 110 extended permit esp host 178.135.51.58 host 64.103.35.189 
access-list 110 extended permit udp host 178.135.51.58 host 64.103.35.189 eq isakmp 
access-list 110 extended permit udp host 178.135.51.58 host 64.103.35.189 eq 4500 
access-list 110 extended permit esp host 101.95.24.18 host 72.163.247.98 
access-list 110 extended permit udp host 101.95.24.18 host 72.163.247.98 eq isakmp 
access-list 110 extended permit esp host 58.248.15.173 host 72.163.247.98 
access-list 110 extended permit udp host 58.248.15.173 host 72.163.247.98 eq isakmp 
access-list 110 extended permit esp host 118.122.89.227 host 72.163.247.98 
access-list 110 extended permit udp host 118.122.89.227 host 72.163.247.98 eq isakmp 
access-list 110 extended permit esp host 124.128.225.99 host 72.163.247.98 
access-list 110 extended permit udp host 124.128.225.99 host 72.163.247.98 eq isakmp 
access-list 110 extended permit gre host 119.151.96.2 host 64.104.155.211 
access-list 110 extended permit esp host 119.151.96.2 host 64.104.155.211 
access-list 110 extended permit udp host 119.151.96.2 host 64.104.155.211 eq isakmp 
access-list 110 extended permit gre host 119.151.96.2 host 64.104.155.147 
access-list 110 extended permit esp host 119.151.96.2 host 64.104.155.147 
access-list 110 extended permit udp host 119.151.96.2 host 64.104.155.147 eq isakmp 
access-list 110 extended permit udp any host 72.163.248.182 eq 5246 
access-list 110 extended permit udp any host 72.163.248.182 eq 5247 
access-list 110 extended permit udp any host 72.163.248.183 eq 5246 
access-list 110 extended permit udp any host 72.163.248.183 eq 5247 
access-list 110 extended permit udp any host 64.104.119.132 eq 5246 
access-list 110 extended permit udp any host 64.104.119.132 eq 5247 
access-list 110 extended permit udp any host 64.104.119.133 eq 5246 
access-list 110 extended permit udp any host 64.104.119.133 eq 5247 
access-list 110 extended permit udp any host 64.104.119.134 eq 5246 
access-list 110 extended permit udp any host 64.104.119.134 eq 5247 
access-list 110 extended permit esp host 195.29.137.234 host 64.103.35.189 
access-list 110 extended permit udp host 195.29.137.234 host 64.103.35.189 eq isakmp 
access-list 110 extended permit gre host 64.103.36.18 host 10.52.123.25 
access-list 110 extended permit esp host 68.115.237.40 host 171.71.3.14 
access-list 110 extended permit udp host 68.115.237.40 host 171.71.3.14 eq isakmp 
access-list 110 extended permit udp host 68.115.237.40 host 171.71.3.14 eq 4500 
access-list 110 extended permit esp host 68.115.237.41 host 171.71.3.26 
access-list 110 extended permit udp host 68.115.237.41 host 171.71.3.26 eq isakmp 
access-list 110 extended permit udp host 68.115.237.41 host 171.71.3.26 eq 4500 
access-list 110 extended permit udp any host 64.104.32.84 eq isakmp 
access-list 110 extended permit esp any host 64.104.32.84 
access-list 110 extended permit udp any host 64.104.32.84 eq 4500 
access-list 110 extended permit udp any host 64.104.32.84 eq 10000 
access-list 110 extended permit tcp any host 64.104.32.84 eq 10000 
access-list 110 extended permit udp any host 64.104.32.84 eq 443 
access-list 110 extended permit tcp any host 64.104.32.84 eq https 
access-list 110 extended permit udp any host 173.37.184.121 eq isakmp 
access-list 110 extended permit udp any host 173.37.184.121 eq 4500 
access-list 110 extended permit esp any host 173.37.184.121 
access-list 110 extended permit udp any object-group swvpn_sjc-prod-1 eq 443 
access-list 110 extended permit tcp any object-group swvpn_sjc-prod-1 eq https 
access-list 110 extended permit esp host 82.178.19.74 host 216.128.60.197 
access-list 110 extended permit udp host 82.178.19.74 host 216.128.60.197 eq isakmp 
access-list 110 extended permit gre any 173.36.138.128 255.255.255.128 
access-list 110 extended permit esp any 173.36.138.128 255.255.255.128 
access-list 110 extended permit udp host 173.36.203.18 any range 9000 9001 
access-list 110 extended permit udp host 173.36.203.225 any range 9000 9001 
access-list 110 extended permit gre host 64.103.36.241 host 10.62.84.1 
access-list 110 extended permit udp host 144.254.51.84 host 10.50.177.18 range 902 903 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.1 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.18 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.20 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.17 
access-list 110 extended permit gre host 64.104.127.65 host 10.72.32.65 
access-list 110 extended permit udp object-group dmz_loopbacks-global-1 object-group netqos_servers-global-1 range snmp snmptrap 
access-list 110 extended permit udp object-group dmz_loopbacks-global-1 object-group netqos_servers-global-1 eq 9995 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.133.81 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.8 
access-list 110 extended permit tcp 199.19.191.64 255.255.255.192 range sip 5061 any 
access-list 110 extended permit tcp 199.19.191.64 255.255.255.192 eq h323 any 
access-list 110 extended permit udp 199.19.191.64 255.255.255.192 eq 1719 any 
access-list 110 extended permit udp 199.19.191.64 255.255.255.192 range 16384 32767 any 
access-list 110 extended permit tcp host 128.107.82.105 host 10.35.209.92 eq 2776 
access-list 110 extended permit tcp host 128.107.82.105 host 10.35.209.92 eq 7006 
access-list 110 extended permit udp host 128.107.82.105 host 10.35.209.92 eq 2776 
access-list 110 extended permit udp host 128.107.82.105 host 10.35.209.92 eq 2777 
access-list 110 extended permit udp host 128.107.82.105 host 10.35.209.92 eq 6006 
access-list 110 extended permit tcp host 128.107.82.106 host 10.35.209.92 eq 2776 
access-list 110 extended permit tcp host 128.107.82.106 host 10.35.209.92 eq 7006 
access-list 110 extended permit udp host 128.107.82.106 host 10.35.209.92 eq 2776 
access-list 110 extended permit udp host 128.107.82.106 host 10.35.209.92 eq 2777 
access-list 110 extended permit udp host 128.107.82.106 host 10.35.209.92 eq 6006 
access-list 110 extended permit udp any host 171.70.192.73 eq 443 
access-list 110 extended permit udp any host 171.70.192.80 eq 443 
access-list 110 extended permit udp any host 171.70.192.82 eq 443 
access-list 110 extended permit udp any host 171.70.192.83 eq 443 
access-list 110 extended permit udp any host 171.70.192.86 eq 443 
access-list 110 extended permit udp any host 171.70.192.87 eq 443 
access-list 110 extended permit udp any host 171.70.192.88 eq 443 
access-list 110 extended permit udp any host 171.70.192.89 eq 443 
access-list 110 extended permit udp any host 171.70.192.90 eq 443 
access-list 110 extended permit tcp any host 144.254.220.33 eq https 
access-list 110 extended permit tcp any host 144.254.220.33 eq 8000 
access-list 110 extended permit tcp host 173.36.203.197 host 10.194.98.137 range 25000 25999 
access-list 110 extended permit udp host 173.36.203.197 host 10.194.98.137 range 50000 52399 
access-list 110 remark *** SJC KICKSTART SERVER ***
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 171.70.177.16 eq www 
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 173.37.113.172 eq www 
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 144.254.72.87 eq www 
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 171.70.177.16 eq https 
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 173.37.113.172 eq https 
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 144.254.72.87 eq https 
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 173.37.181.23 eq www 
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 gt 1023 host 173.37.181.23 gt 1023 
access-list 110 remark *** SJC Filer with WINES build files ***
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 171.70.150.194 eq 445 
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 171.70.150.194 eq netbios-ssn 
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 171.70.144.245 eq 445 
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 171.70.144.245 eq netbios-ssn 
access-list 110 remark *** SJC Altiris Service ***
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 171.68.46.115 eq 445 
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 171.68.46.115 eq netbios-ssn 
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 171.68.46.115 eq 402 
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 171.68.46.115 eq 415 
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 171.68.46.115 eq 4300 
access-list 110 extended permit tcp 10.28.65.128 255.255.255.128 host 171.68.46.115 eq 1119 
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 171.70.168.39 eq bootps 
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 171.70.168.40 eq bootps 
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 171.70.168.159 eq bootps 
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 171.70.168.39 eq bootpc 
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 171.70.168.40 eq bootpc 
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 171.70.168.159 eq bootpc 
access-list 110 remark *** SJC DNS service ***
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 171.70.168.183 eq domain 
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 171.70.168.155 eq domain 
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 171.70.168.167 eq domain 
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 171.68.226.120 eq domain 
access-list 110 remark *** RCDN DNS service ***
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 173.37.87.157 eq domain 
access-list 110 remark *** NETBIOS Name Service to SJC WINS ***
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 171.71.196.25 eq netbios-ns 
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 171.71.196.26 eq netbios-ns 
access-list 110 remark *** SJC NTP ***
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 10.81.254.131 eq ntp 
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 10.81.254.202 eq ntp 
access-list 110 remark *** Windows Boot - TFTP to filer ***
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 171.70.150.194 eq tftp 
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 host 171.70.144.245 eq tftp 
access-list 110 remark *** Linux Build Ports ***
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 gt 1023 host 171.70.150.194 gt 1023 
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 gt 1023 host 171.70.144.245 gt 1023 
access-list 110 extended permit tcp host 128.107.85.187 host 128.107.201.136 eq 2776 
access-list 110 extended permit tcp host 128.107.85.187 host 128.107.201.136 eq 7006 
access-list 110 extended permit tcp host 128.107.85.187 host 128.107.201.136 eq 2777 
access-list 110 extended permit tcp host 128.107.85.187 host 128.107.201.136 eq 6006 
access-list 110 extended permit tcp host 128.107.85.187 host 10.35.202.2 eq 2776 
access-list 110 extended permit tcp host 128.107.85.187 host 10.35.202.2 eq 7006 
access-list 110 extended permit tcp host 128.107.85.187 host 10.35.202.2 eq 2777 
access-list 110 extended permit tcp host 128.107.85.187 host 10.35.202.2 eq 6006 
access-list 110 extended permit tcp host 128.107.85.187 host 10.35.209.92 eq 2776 
access-list 110 extended permit tcp host 128.107.85.187 host 10.35.209.92 eq 7006 
access-list 110 extended permit tcp host 128.107.85.187 host 10.35.209.92 eq 2777 
access-list 110 extended permit tcp host 128.107.85.187 host 10.35.209.92 eq 6006 
access-list 110 extended permit tcp host 128.107.85.187 host 10.35.150.26 eq 2776 
access-list 110 extended permit tcp host 128.107.85.187 host 10.35.150.26 eq 7006 
access-list 110 extended permit tcp host 128.107.85.187 host 10.35.150.26 eq 2777 
access-list 110 extended permit tcp host 128.107.85.187 host 10.35.150.26 eq 6006 
access-list 110 extended permit esp host 61.142.98.158 host 72.163.247.99 
access-list 110 extended permit udp host 61.142.98.158 host 72.163.247.99 eq isakmp 
access-list 110 extended permit esp host 46.10.158.34 host 64.103.35.61 
access-list 110 extended permit udp host 46.10.158.34 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 80.88.240.250 host 64.103.35.189 
access-list 110 extended permit udp host 80.88.240.250 host 64.103.35.189 eq isakmp 
access-list 110 extended permit gre host 64.103.36.18 host 10.61.2.122 
access-list 110 extended permit esp any host 144.254.220.189 
access-list 110 extended permit udp any host 144.254.220.189 eq isakmp 
access-list 110 extended permit udp any host 144.254.220.189 eq 4500 
access-list 110 extended permit udp host 64.104.94.50 host 10.35.16.42 eq syslog 
access-list 110 extended permit udp host 64.104.94.50 host 10.35.16.43 eq syslog 
access-list 110 extended permit udp host 64.104.94.50 host 10.35.22.18 range snmp snmptrap 
access-list 110 extended permit udp host 64.104.94.50 host 10.35.22.31 range snmp snmptrap 
access-list 110 extended permit udp host 64.104.94.50 host 171.70.93.61 range snmp snmptrap 
access-list 110 extended permit udp host 64.104.94.50 host 10.35.48.76 range snmp snmptrap 
access-list 110 extended permit udp host 64.104.94.50 host 10.35.48.77 range snmp snmptrap 
access-list 110 extended permit udp host 64.104.94.50 host 10.35.48.78 range snmp snmptrap 
access-list 110 extended permit udp host 64.104.94.50 host 10.35.16.41 eq 2055 
access-list 110 extended permit udp host 144.254.51.2 10.54.64.0 255.255.224.0 eq 6001 
access-list 110 extended permit udp host 64.103.39.1 host 10.35.16.42 eq syslog 
access-list 110 extended permit udp host 64.103.39.1 host 10.35.16.43 eq syslog 
access-list 110 extended permit udp host 64.103.39.1 host 10.35.22.18 range snmp snmptrap 
access-list 110 extended permit udp host 64.103.39.1 host 10.35.22.31 range snmp snmptrap 
access-list 110 extended permit udp host 64.103.39.1 host 171.70.93.61 range snmp snmptrap 
access-list 110 extended permit udp host 64.103.39.1 host 10.35.48.76 range snmp snmptrap 
access-list 110 extended permit udp host 64.103.39.1 host 10.35.48.77 range snmp snmptrap 
access-list 110 extended permit udp host 64.103.39.1 host 10.35.48.78 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.0 host 10.35.16.42 eq syslog 
access-list 110 extended permit udp host 128.107.83.5 host 10.35.16.42 eq syslog 
access-list 110 extended permit udp host 128.107.83.94 host 10.35.16.42 eq syslog 
access-list 110 extended permit udp host 128.107.83.52 host 10.35.16.42 eq syslog 
access-list 110 extended permit udp host 128.107.83.0 host 10.35.16.43 eq syslog 
access-list 110 extended permit udp host 128.107.83.5 host 10.35.16.43 eq syslog 
access-list 110 extended permit udp host 128.107.83.94 host 10.35.16.43 eq syslog 
access-list 110 extended permit udp host 128.107.83.52 host 10.35.16.43 eq syslog 
access-list 110 extended permit udp host 128.107.83.0 host 10.35.22.18 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.5 host 10.35.22.18 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.94 host 10.35.22.18 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.52 host 10.35.22.18 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.0 host 10.35.22.31 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.5 host 10.35.22.31 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.94 host 10.35.22.31 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.52 host 10.35.22.31 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.0 host 171.70.93.61 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.5 host 171.70.93.61 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.94 host 171.70.93.61 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.52 host 171.70.93.61 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.0 host 10.35.48.76 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.5 host 10.35.48.76 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.94 host 10.35.48.76 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.52 host 10.35.48.76 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.0 host 10.35.48.77 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.5 host 10.35.48.77 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.94 host 10.35.48.77 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.52 host 10.35.48.77 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.0 host 10.35.48.78 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.5 host 10.35.48.78 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.94 host 10.35.48.78 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.52 host 10.35.48.78 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.83.0 host 10.35.16.41 eq 2055 
access-list 110 extended permit udp host 128.107.83.5 host 10.35.16.41 eq 2055 
access-list 110 extended permit udp host 128.107.83.94 host 10.35.16.41 eq 2055 
access-list 110 extended permit udp host 128.107.83.52 host 10.35.16.41 eq 2055 
access-list 110 extended permit udp host 64.103.39.1 host 10.35.16.41 eq 2055 
access-list 110 extended permit gre host 64.103.36.18 any 
access-list 110 extended permit esp host 116.225.68.162 host 72.163.247.99 
access-list 110 extended permit udp host 116.225.68.162 host 72.163.247.99 eq isakmp 
access-list 110 extended permit udp host 116.225.68.162 host 72.163.247.99 eq 4500 
access-list 110 extended permit esp host 220.249.125.11 host 72.163.247.98 
access-list 110 extended permit udp host 220.249.125.11 host 72.163.247.98 eq isakmp 
access-list 110 extended permit esp host 113.204.103.178 host 72.163.247.98 
access-list 110 extended permit udp host 113.204.103.178 host 72.163.247.98 eq isakmp 
access-list 110 extended permit esp host 203.107.248.198 host 64.104.77.181 
access-list 110 extended permit udp host 203.107.248.198 host 64.104.77.181 eq isakmp 
access-list 110 extended permit udp host 203.107.248.198 host 64.104.77.181 eq 4500 
access-list 110 extended permit udp any host 171.68.106.20 eq isakmp 
access-list 110 extended permit esp any host 171.68.106.20 
access-list 110 extended permit udp any host 171.68.106.20 eq 4500 
access-list 110 extended permit udp any host 171.68.106.20 eq 10000 
access-list 110 extended permit tcp any host 171.68.106.20 eq 10000 
access-list 110 extended permit udp any host 171.68.106.20 eq 443 
access-list 110 extended permit tcp any host 171.68.106.20 eq https 
access-list 110 extended permit udp any host 171.68.106.21 eq isakmp 
access-list 110 extended permit esp any host 171.68.106.21 
access-list 110 extended permit udp any host 171.68.106.21 eq 4500 
access-list 110 extended permit udp any host 171.68.106.21 eq 10000 
access-list 110 extended permit tcp any host 171.68.106.21 eq 10000 
access-list 110 extended permit udp any host 171.68.106.21 eq 443 
access-list 110 extended permit tcp any host 171.68.106.21 eq https 
access-list 110 extended permit udp any host 171.68.106.12 eq isakmp 
access-list 110 extended permit esp any host 171.68.106.12 
access-list 110 extended permit udp any host 171.68.106.12 eq 4500 
access-list 110 extended permit udp any host 171.68.106.12 eq 10000 
access-list 110 extended permit tcp any host 171.68.106.12 eq 10000 
access-list 110 extended permit udp any host 171.68.106.12 eq 443 
access-list 110 extended permit tcp any host 171.68.106.12 eq https 
access-list 110 extended permit esp host 72.163.249.17 host 10.224.223.2 
access-list 110 extended permit udp host 72.163.249.17 host 10.224.223.2 eq isakmp 
access-list 110 extended permit esp host 72.163.249.17 host 10.224.97.198 
access-list 110 extended permit udp host 72.163.249.17 host 10.224.97.198 eq isakmp 
access-list 110 extended permit esp host 72.163.249.17 host 10.224.32.54 
access-list 110 extended permit udp host 72.163.249.17 host 10.224.32.54 eq isakmp 
access-list 110 extended permit esp host 80.254.144.195 144.254.48.0 255.255.255.0 
access-list 110 extended permit udp host 80.254.144.195 144.254.48.0 255.255.255.0 eq isakmp 
access-list 110 extended permit esp host 80.254.144.195 144.254.49.0 255.255.255.0 
access-list 110 extended permit udp host 80.254.144.195 144.254.49.0 255.255.255.0 eq isakmp 
access-list 110 extended permit esp host 89.107.179.21 host 144.254.146.9 
access-list 110 extended permit udp host 89.107.179.21 host 144.254.146.9 eq isakmp 
access-list 110 extended permit tcp any host 64.100.32.216 eq www 
access-list 110 extended permit tcp any host 64.100.32.216 eq https 
access-list 110 extended permit tcp any host 144.254.73.146 eq www 
access-list 110 extended permit tcp any host 144.254.73.146 eq https 
access-list 110 extended permit tcp any host 171.68.46.188 eq www 
access-list 110 extended permit tcp any host 171.68.46.188 eq https 
access-list 110 extended permit esp host 122.28.177.182 host 64.104.20.28 
access-list 110 extended permit udp host 122.28.177.182 host 64.104.20.28 eq isakmp 
access-list 110 extended permit udp host 122.28.177.182 host 64.104.20.28 eq 4500 
access-list 110 extended permit esp host 203.174.191.122 host 64.104.213.240 
access-list 110 extended permit udp host 203.174.191.122 host 64.104.213.240 eq isakmp 
access-list 110 extended permit tcp host 128.107.233.36 host 10.89.29.11 eq 2000 
access-list 110 extended permit udp host 128.107.233.36 host 10.89.29.11 eq tftp 
access-list 110 extended permit udp host 128.107.233.36 host 10.89.29.11 range 20480 32767 
access-list 110 extended permit udp any host 72.163.248.180 range 5246 5247 
access-list 110 extended permit udp any host 72.163.248.181 range 5246 5247 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.19 
access-list 110 extended permit tcp any object-group V4-ETE-ORION-SERVERS eq www 
access-list 110 extended permit tcp host 128.107.85.132 host 10.32.134.101 range ftp-data ssh 
access-list 110 extended permit tcp host 128.107.85.132 host 10.32.134.80 range ftp-data ssh 
access-list 110 extended permit tcp host 128.107.85.133 host 10.32.134.101 range ftp-data ssh 
access-list 110 extended permit tcp host 128.107.85.133 host 10.32.134.80 range ftp-data ssh 
access-list 110 extended permit tcp host 128.107.235.138 host 10.35.173.211 eq ftp-data 
access-list 110 extended permit tcp host 128.107.235.138 host 10.35.173.212 eq ftp-data 
access-list 110 extended permit tcp host 128.107.235.138 host 10.35.176.159 eq ftp-data 
access-list 110 extended permit tcp host 128.107.85.170 host 10.35.48.151 eq 8060 
access-list 110 extended permit tcp host 128.107.85.170 host 10.35.48.152 eq 8060 
access-list 110 extended permit tcp host 128.107.85.170 host 10.35.48.153 eq 8060 
access-list 110 extended permit tcp host 128.107.85.170 host 10.35.48.154 eq 8060 
access-list 110 extended permit tcp host 128.107.85.170 host 10.35.48.155 eq 8060 
access-list 110 extended permit tcp host 128.107.85.170 host 10.35.48.156 eq 8060 
access-list 110 extended permit tcp host 128.107.85.170 host 10.35.48.117 eq 8060 
access-list 110 extended permit tcp host 128.107.85.170 host 10.35.48.118 eq 8060 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.48.151 eq 8060 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.48.152 eq 8060 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.48.153 eq 8060 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.48.154 eq 8060 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.48.155 eq 8060 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.48.156 eq 8060 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.48.117 eq 8060 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.48.118 eq 8060 
access-list 110 extended permit tcp host 128.107.240.56 host 171.68.196.222 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.70.112.213 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.68.196.223 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.70.112.214 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.68.196.224 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.70.112.215 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.68.196.225 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.70.112.216 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.68.196.226 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.70.112.217 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.68.196.227 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.70.112.218 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.68.196.228 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.70.112.219 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.68.196.229 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.70.112.204 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.68.196.204 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.70.112.205 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.68.196.205 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.68.38.28 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 171.68.38.29 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 72.163.36.151 eq sip 
access-list 110 extended permit tcp host 128.107.240.56 host 72.163.36.152 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.70.112.212 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.68.196.222 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.70.112.213 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.68.196.223 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.70.112.214 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.68.196.224 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.70.112.215 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.68.196.225 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.70.112.216 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.68.196.226 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.70.112.217 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.68.196.227 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.70.112.218 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.68.196.228 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.70.112.219 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.68.196.229 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.70.112.204 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.68.196.204 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.70.112.205 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.68.196.205 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.68.38.28 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 171.68.38.29 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 72.163.36.151 eq sip 
access-list 110 extended permit tcp host 128.107.240.57 host 72.163.36.152 eq sip 
access-list 110 extended permit tcp object-group uc_verizon_sip_trunk-rtp-1 object-group uc_cucm_subscribers-rtp-1 eq sip 
access-list 110 extended permit tcp object-group uc_verizon_sip_trunk-sjc-1 object-group uc_cucm_subscribers-sjc-1 eq sip 
access-list 110 extended permit udp object-group uc_verizon_sip_trunk-sjc-1 object-group uc_cucm_subscribers-sjc-1 eq sip 
access-list 110 extended permit tcp object-group uc_verizon_sip_trunk-sjc-alpha object-group uc_cucm_subscribers-sjc-alpha eq sip 
access-list 110 extended permit tcp object-group uc_verizon_sip_trunk-ams-1 object-group uc_cucm_subscribers-ams-1 eq sip 
access-list 110 extended permit tcp object-group web_security_appliances_mgmt object-group csirt_splunk_logging eq ssh 
access-list 110 extended permit tcp host 10.81.52.38 172.18.240.0 255.255.255.0 eq ssh 
access-list 110 extended permit tcp host 128.107.250.242 172.27.204.0 255.255.255.0 eq 5443 
access-list 110 extended permit tcp host 128.107.250.242 172.27.204.0 255.255.255.0 eq 9080 
access-list 110 extended permit tcp host 128.107.250.242 172.27.204.0 255.255.255.0 eq 2195 
access-list 110 extended permit tcp host 128.107.83.73 host 10.35.1.19 eq 5005 
access-list 110 extended permit tcp host 128.107.83.74 host 10.35.1.19 eq 5005 
access-list 110 extended permit esp any host 64.102.223.9 
access-list 110 extended permit udp any host 64.102.223.9 eq isakmp 
access-list 110 extended permit udp any host 64.102.223.9 eq 4500 
access-list 110 extended permit udp any host 64.102.223.9 eq 10000 
access-list 110 extended permit tcp any host 64.102.223.9 eq 10000 
access-list 110 extended permit esp any host 64.102.223.10 
access-list 110 extended permit udp any host 64.102.223.10 eq isakmp 
access-list 110 extended permit udp any host 64.102.223.10 eq 4500 
access-list 110 extended permit udp any host 64.102.223.10 eq 10000 
access-list 110 extended permit tcp any host 64.102.223.10 eq 10000 
access-list 110 extended permit esp any host 64.102.223.12 
access-list 110 extended permit udp any host 64.102.223.12 eq isakmp 
access-list 110 extended permit udp any host 64.102.223.12 eq 4500 
access-list 110 extended permit udp any host 64.102.223.12 eq 10000 
access-list 110 extended permit tcp any host 64.102.223.12 eq 10000 
access-list 110 extended permit udp any host 171.68.106.1 eq isakmp 
access-list 110 extended permit esp any host 171.68.106.1 
access-list 110 extended permit udp any host 171.68.106.1 eq 4500 
access-list 110 extended permit udp any host 171.68.106.1 eq 10000 
access-list 110 extended permit tcp any host 171.68.106.1 eq 10000 
access-list 110 extended permit udp any host 171.68.106.2 eq isakmp 
access-list 110 extended permit esp any host 171.68.106.2 
access-list 110 extended permit udp any host 171.68.106.2 eq 4500 
access-list 110 extended permit udp any host 171.68.106.2 eq 10000 
access-list 110 extended permit tcp any host 171.68.106.2 eq 10000 
access-list 110 extended permit udp any host 171.68.106.4 eq isakmp 
access-list 110 extended permit esp any host 171.68.106.4 
access-list 110 extended permit udp any host 171.68.106.4 eq 4500 
access-list 110 extended permit udp any host 171.68.106.4 eq 10000 
access-list 110 extended permit tcp any host 171.68.106.4 eq 10000 
access-list 110 extended permit tcp host 128.107.225.135 host 72.163.57.6 eq ldap 
access-list 110 extended permit tcp host 128.107.225.135 host 72.163.57.6 eq ldaps 
access-list 110 extended permit tcp host 128.107.225.153 host 72.163.57.6 eq ldap 
access-list 110 extended permit tcp host 128.107.225.153 host 72.163.57.6 eq ldaps 
access-list 110 extended permit tcp host 128.107.225.152 host 72.163.57.6 eq ldap 
access-list 110 extended permit tcp host 128.107.225.152 host 72.163.57.6 eq ldaps 
access-list 110 extended permit tcp host 128.107.228.165 host 72.163.57.6 eq ldap 
access-list 110 extended permit tcp host 128.107.228.165 host 72.163.57.6 eq ldaps 
access-list 110 extended permit tcp host 128.107.225.135 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp host 128.107.225.135 host 64.102.9.230 eq ldaps 
access-list 110 extended permit tcp host 128.107.225.153 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp host 128.107.225.153 host 64.102.9.230 eq ldaps 
access-list 110 extended permit tcp host 128.107.225.152 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp host 128.107.225.152 host 64.102.9.230 eq ldaps 
access-list 110 extended permit tcp host 128.107.228.165 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp host 128.107.228.165 host 64.102.9.230 eq ldaps 
access-list 110 extended permit tcp 173.36.118.0 255.255.255.0 object-group ldap_dsx_servers-global-1 eq ldap 
access-list 110 extended permit esp host 203.174.191.118 host 64.104.213.240 
access-list 110 extended permit udp host 203.174.191.118 host 64.104.213.240 eq isakmp 
access-list 110 extended permit udp object-group sjc_ace_vcse object-group VCS_Controls_TME_labs eq 3478 
access-list 110 extended permit udp object-group sjc_ace_vcse object-group VCS_Controls_TME_labs range 60000 61799 
access-list 110 extended permit udp object-group sjc_ace_vcse object-group VCS_Controls_TME_labs range 56000 57000 
access-list 110 extended permit udp object-group sjc_ace_vcse object-group VCS_Controls_TME_labs range 50000 54999 
access-list 110 extended permit tcp 128.107.237.40 255.255.255.248 171.68.11.64 255.255.255.192 eq 6021 
access-list 110 extended permit tcp 128.107.237.40 255.255.255.248 72.163.41.64 255.255.255.224 eq 6021 
access-list 110 extended permit udp host 128.107.87.52 171.71.216.0 255.255.248.0 eq 3478 
access-list 110 extended permit udp host 128.107.87.52 171.71.224.0 255.255.248.0 eq 3478 
access-list 110 extended permit udp host 128.107.87.52 171.71.232.0 255.255.255.0 eq 3478 
access-list 110 extended permit tcp host 128.107.87.52 171.71.216.0 255.255.248.0 eq 3478 
access-list 110 extended permit tcp host 128.107.87.52 171.71.224.0 255.255.248.0 eq 3478 
access-list 110 extended permit tcp host 128.107.87.52 171.71.232.0 255.255.255.0 eq 3478 
access-list 110 extended permit udp host 128.107.87.53 171.71.216.0 255.255.248.0 eq 3478 
access-list 110 extended permit udp host 128.107.87.53 171.71.224.0 255.255.248.0 eq 3478 
access-list 110 extended permit udp host 128.107.87.53 171.71.232.0 255.255.255.0 eq 3478 
access-list 110 extended permit tcp host 128.107.87.53 171.71.216.0 255.255.248.0 eq 3478 
access-list 110 extended permit tcp host 128.107.87.53 171.71.224.0 255.255.248.0 eq 3478 
access-list 110 extended permit tcp host 128.107.87.53 171.71.232.0 255.255.255.0 eq 3478 
access-list 110 extended permit udp host 128.107.87.52 128.107.138.240 255.255.255.240 eq 3478 
access-list 110 extended permit udp host 128.107.87.53 128.107.138.240 255.255.255.240 eq 3478 
access-list 110 extended permit tcp host 128.107.85.175 host 10.32.134.107 eq sip 
access-list 110 extended permit tcp host 128.107.85.175 host 10.32.134.108 eq sip 
access-list 110 extended permit tcp host 128.107.85.175 host 10.34.130.10 eq sip 
access-list 110 extended permit tcp host 128.107.85.175 host 10.32.134.107 eq 8060 
access-list 110 extended permit tcp host 128.107.85.175 host 10.32.134.108 eq 8060 
access-list 110 extended permit tcp host 128.107.85.175 host 10.34.130.10 eq 8060 
access-list 110 extended permit tcp host 128.107.85.132 host 10.32.134.107 eq 5620 
access-list 110 extended permit tcp host 128.107.85.132 host 10.32.134.108 eq 5620 
access-list 110 extended permit tcp host 128.107.85.132 host 10.34.130.10 eq 5620 
access-list 110 extended permit tcp host 128.107.85.133 host 10.32.134.107 eq 5620 
access-list 110 extended permit tcp host 128.107.85.133 host 10.32.134.108 eq 5620 
access-list 110 extended permit tcp host 128.107.85.133 host 10.34.130.10 eq 5620 
access-list 110 extended permit tcp host 128.107.85.175 host 10.35.48.106 eq sip 
access-list 110 extended permit tcp host 128.107.85.175 host 10.35.48.107 eq sip 
access-list 110 extended permit tcp host 128.107.85.175 host 10.35.48.108 eq sip 
access-list 110 extended permit tcp host 128.107.85.175 host 10.35.48.109 eq sip 
access-list 110 extended permit tcp host 128.107.85.175 host 10.35.48.106 eq 5061 
access-list 110 extended permit tcp host 128.107.85.175 host 10.35.48.107 eq 5061 
access-list 110 extended permit tcp host 128.107.85.175 host 10.35.48.108 eq 5061 
access-list 110 extended permit tcp host 128.107.85.175 host 10.35.48.109 eq 5061 
access-list 110 extended permit tcp host 128.107.85.175 host 10.35.48.106 eq 8060 
access-list 110 extended permit tcp host 128.107.85.175 host 10.35.48.107 eq 8060 
access-list 110 extended permit tcp host 128.107.85.175 host 10.35.48.108 eq 8060 
access-list 110 extended permit tcp host 128.107.85.175 host 10.35.48.109 eq 8060 
access-list 110 extended permit tcp host 128.107.85.174 host 10.35.48.106 eq 8060 
access-list 110 extended permit tcp host 128.107.85.174 host 10.35.48.107 eq 8060 
access-list 110 extended permit tcp host 128.107.85.174 host 10.35.48.108 eq 8060 
access-list 110 extended permit tcp host 128.107.85.174 host 10.35.48.109 eq 8060 
access-list 110 extended permit tcp host 128.107.85.132 host 10.35.48.106 eq 5620 
access-list 110 extended permit tcp host 128.107.85.132 host 10.35.48.107 eq 5620 
access-list 110 extended permit tcp host 128.107.85.132 host 10.35.48.108 eq 5620 
access-list 110 extended permit tcp host 128.107.85.132 host 10.35.48.109 eq 5620 
access-list 110 extended permit tcp host 128.107.85.133 host 10.35.48.106 eq 5620 
access-list 110 extended permit tcp host 128.107.85.133 host 10.35.48.107 eq 5620 
access-list 110 extended permit tcp host 128.107.85.133 host 10.35.48.108 eq 5620 
access-list 110 extended permit tcp host 128.107.85.133 host 10.35.48.109 eq 5620 
access-list 110 extended permit tcp 172.17.153.128 255.255.255.240 host 171.68.46.60 eq 27000 
access-list 110 extended permit tcp 172.17.153.144 255.255.255.240 host 171.68.46.60 eq 27000 
access-list 110 extended permit tcp 172.17.153.128 255.255.255.240 host 171.68.46.60 eq 27010 
access-list 110 extended permit tcp 172.17.153.144 255.255.255.240 host 171.68.46.60 eq 27010 
access-list 110 extended permit udp 172.17.153.128 255.255.255.240 host 171.68.46.60 eq 902 
access-list 110 extended permit udp 172.17.153.144 255.255.255.240 host 171.68.46.60 eq 902 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 171.70.178.59 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 171.70.178.53 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 173.36.8.9 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 173.36.8.8 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 173.38.201.71 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 173.38.201.70 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 72.163.192.108 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 72.163.192.107 eq 577 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 64.102.9.231 eq ldap 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 72.163.57.7 eq ldap 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 64.102.9.231 eq ldaps 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 72.163.57.7 eq ldaps 
access-list 110 extended permit tcp 128.107.227.224 255.255.255.240 host 64.102.9.231 eq ldap 
access-list 110 extended permit tcp 128.107.227.224 255.255.255.240 host 72.163.57.7 eq ldap 
access-list 110 extended permit tcp 128.107.227.224 255.255.255.240 host 64.102.9.231 eq ldaps 
access-list 110 extended permit tcp 128.107.227.224 255.255.255.240 host 72.163.57.7 eq ldaps 
access-list 110 extended permit tcp host 198.133.219.38 host 64.102.9.231 eq ldap 
access-list 110 extended permit tcp host 198.133.219.38 host 72.163.57.7 eq ldap 
access-list 110 extended permit tcp host 198.133.219.38 host 64.102.9.231 eq ldaps 
access-list 110 extended permit tcp host 198.133.219.38 host 72.163.57.7 eq ldaps 
access-list 110 extended permit tcp host 198.133.219.41 host 64.102.9.231 eq ldap 
access-list 110 extended permit tcp host 198.133.219.41 host 72.163.57.7 eq ldap 
access-list 110 extended permit tcp host 198.133.219.41 host 64.102.9.231 eq ldaps 
access-list 110 extended permit tcp host 198.133.219.41 host 72.163.57.7 eq ldaps 
access-list 110 extended permit tcp host 128.107.212.162 host 171.68.224.207 eq ldap 
access-list 110 extended permit tcp host 128.107.212.162 host 171.68.224.207 eq ldaps 
access-list 110 extended permit tcp host 128.107.212.162 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp host 128.107.212.162 host 171.71.184.6 eq ldaps 
access-list 110 extended permit tcp host 128.107.212.162 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp host 128.107.212.162 host 64.102.9.230 eq ldaps 
access-list 110 extended permit tcp host 128.107.212.162 host 72.163.57.6 eq ldap 
access-list 110 extended permit tcp host 128.107.212.162 host 72.163.57.6 eq ldaps 
access-list 110 extended permit tcp host 128.107.212.163 host 171.68.224.207 eq ldap 
access-list 110 extended permit tcp host 128.107.212.163 host 171.68.224.207 eq ldaps 
access-list 110 extended permit tcp host 128.107.212.163 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp host 128.107.212.163 host 171.71.184.6 eq ldaps 
access-list 110 extended permit tcp host 128.107.212.163 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp host 128.107.212.163 host 64.102.9.230 eq ldaps 
access-list 110 extended permit tcp host 128.107.212.163 host 72.163.57.6 eq ldap 
access-list 110 extended permit tcp host 128.107.212.163 host 72.163.57.6 eq ldaps 
access-list 110 extended permit udp host 128.107.225.22 host 172.17.153.17 eq snmp 
access-list 110 extended permit udp host 128.107.225.22 host 172.17.153.18 eq snmp 
access-list 110 extended permit udp host 64.102.245.251 173.37.95.192 255.255.255.192 eq snmp 
access-list 110 extended permit udp host 64.102.245.252 173.37.95.192 255.255.255.192 eq snmp 
access-list 110 extended permit udp host 64.102.245.251 eq snmp 173.37.95.192 255.255.255.192 
access-list 110 extended permit udp host 64.102.245.252 eq snmp 173.37.95.192 255.255.255.192 
access-list 110 extended permit tcp any 172.17.153.160 255.255.255.224 eq ssh 
access-list 110 extended permit udp host 64.103.26.92 host 10.52.207.254 eq snmptrap 
access-list 110 extended permit udp host 64.103.26.93 host 10.52.207.254 eq snmptrap 
access-list 110 extended permit udp host 64.103.26.94 host 10.52.207.254 eq snmptrap 
access-list 110 extended permit udp host 64.103.26.92 host 144.254.240.11 eq snmptrap 
access-list 110 extended permit udp host 64.103.26.93 host 144.254.240.11 eq snmptrap 
access-list 110 extended permit udp host 64.103.26.94 host 144.254.240.11 eq snmptrap 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.143.73 
access-list 110 extended permit gre host 64.103.36.241 host 10.144.0.1 
access-list 110 extended permit gre host 64.102.254.10 host 10.83.6.114 
access-list 110 extended permit tcp host 144.254.51.74 host 171.68.47.128 eq 1688 
access-list 110 extended permit udp host 64.104.94.175 any range 1024 65535 
access-list 110 extended permit udp host 128.107.83.77 any range 1024 65535 
access-list 110 extended permit tcp host 128.107.83.76 host 10.35.16.101 eq 2000 
access-list 110 extended permit tcp host 128.107.83.76 host 10.35.16.101 eq 2443 
access-list 110 extended permit tcp host 128.107.83.76 host 10.35.16.101 eq sip 
access-list 110 extended permit tcp host 128.107.83.76 host 10.35.16.101 eq 5061 
access-list 110 extended permit tcp host 128.107.83.75 host 10.35.16.101 eq 3804 
access-list 110 extended permit udp host 128.107.83.75 host 10.35.16.101 eq tftp 
access-list 110 extended permit gre host 128.107.235.30 171.68.144.8 255.255.255.248 
access-list 110 extended permit udp host 128.107.85.180 any range 16384 32768 
access-list 110 extended permit udp host 128.107.85.180 any eq 1967 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.48.151 range sip 5061 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.48.152 range sip 5061 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.48.153 range sip 5061 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.48.154 range sip 5061 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.48.155 range sip 5061 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.48.156 range sip 5061 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.48.117 range sip 5061 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.48.118 range sip 5061 
access-list 110 extended permit tcp 72.163.218.240 255.255.255.240 host 10.76.96.192 eq www 
access-list 110 extended permit tcp 72.163.218.240 255.255.255.240 host 10.76.96.182 eq www 
access-list 110 extended permit tcp 72.163.218.240 255.255.255.240 host 10.76.96.209 eq www 
access-list 110 extended permit tcp 72.163.218.240 255.255.255.240 host 10.76.96.192 eq https 
access-list 110 extended permit tcp 72.163.218.240 255.255.255.240 host 10.76.96.182 eq https 
access-list 110 extended permit tcp 72.163.218.240 255.255.255.240 host 10.76.96.209 eq https 
access-list 110 extended permit tcp any host 171.70.192.77 eq www 
access-list 110 extended permit tcp any host 171.70.192.77 eq https 
access-list 110 extended permit tcp any host 171.70.192.78 eq www 
access-list 110 extended permit tcp any host 171.70.192.78 eq https 
access-list 110 extended permit tcp any host 171.70.192.79 eq www 
access-list 110 extended permit tcp any host 171.70.192.79 eq https 
access-list 110 extended permit tcp host 64.103.37.170 host 173.37.178.201 eq https 
access-list 110 extended permit udp host 128.107.81.144 host 10.35.16.41 eq 2055 
access-list 110 extended permit udp host 128.107.81.145 host 10.35.16.41 eq 2055 
access-list 110 extended permit udp host 128.107.241.119 host 10.35.16.41 eq 2055 
access-list 110 extended permit udp host 128.107.233.36 host 10.35.16.41 eq 2055 
access-list 110 extended permit udp host 128.107.85.130 host 10.35.16.41 eq 2055 
access-list 110 extended permit udp host 128.107.85.196 host 10.35.16.41 eq 2055 
access-list 110 extended permit udp host 64.103.26.170 any range 1024 65535 
access-list 110 extended permit tcp host 128.107.250.226 172.27.204.0 255.255.255.0 eq 5443 
access-list 110 extended permit tcp host 128.107.250.226 172.27.204.0 255.255.255.0 eq 9080 
access-list 110 extended permit tcp host 128.107.250.226 172.27.204.0 255.255.255.0 eq 2195 
access-list 110 extended permit tcp any host 128.107.83.91 eq 5443 
access-list 110 extended permit tcp any host 128.107.83.91 eq 9080 
access-list 110 extended permit tcp any host 128.107.83.91 eq ssh 
access-list 110 extended permit tcp host 128.107.83.123 host 10.35.16.131 eq 5443 
access-list 110 extended permit tcp host 128.107.83.123 host 10.35.16.131 eq 9080 
access-list 110 extended permit tcp host 128.107.234.204 host 171.68.46.129 eq smtp 
access-list 110 extended permit tcp host 128.107.234.205 host 171.68.46.129 eq smtp 
access-list 110 extended permit tcp host 128.107.234.206 host 171.68.46.129 eq smtp 
access-list 110 extended permit tcp host 128.107.234.207 host 171.68.46.129 eq smtp 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.65 eq 5003 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.65 eq 5005 
access-list 110 extended permit tcp host 128.107.83.69 host 171.70.121.65 eq 5003 
access-list 110 extended permit tcp host 128.107.83.69 host 171.70.121.65 eq 5005 
access-list 110 extended permit tcp host 128.107.237.43 host 144.254.15.111 eq 1410 
access-list 110 extended permit tcp host 128.107.237.43 host 144.254.15.111 eq sqlnet 
access-list 110 extended permit tcp host 128.107.237.43 host 144.254.15.111 eq 1526 
access-list 110 extended permit udp any host 144.254.217.132 eq 5246 
access-list 110 extended permit udp any host 144.254.217.132 eq 5247 
access-list 110 extended permit udp any host 144.254.217.133 eq 5246 
access-list 110 extended permit udp any host 144.254.217.133 eq 5247 
access-list 110 extended permit esp host 197.254.42.34 host 64.103.35.189 
access-list 110 extended permit udp host 197.254.42.34 host 64.103.35.189 eq isakmp 
access-list 110 extended permit udp any host 192.118.79.52 eq 5246 
access-list 110 extended permit udp any host 192.118.79.52 eq 5247 
access-list 110 extended permit udp any host 192.118.79.53 eq 5246 
access-list 110 extended permit udp any host 192.118.79.53 eq 5247 
access-list 110 extended permit udp any host 72.163.215.148 eq 5246 
access-list 110 extended permit udp any host 72.163.215.148 eq 5247 
access-list 110 extended permit udp any host 72.163.215.149 eq 5246 
access-list 110 extended permit udp any host 72.163.215.149 eq 5247 
access-list 110 extended permit tcp 10.105.24.64 255.255.255.224 host 72.163.132.92 eq 445 
access-list 110 extended permit udp 10.105.24.64 255.255.255.224 host 72.163.132.92 eq tftp 
access-list 110 extended permit esp host 115.112.60.222 host 64.103.209.131 
access-list 110 extended permit udp host 115.112.60.222 host 64.103.209.131 eq isakmp 
access-list 110 extended permit esp host 115.112.95.246 host 64.103.209.132 
access-list 110 extended permit udp host 115.112.95.246 host 64.103.209.132 eq isakmp 
access-list 110 extended permit udp any host 64.104.1.4 eq 5246 
access-list 110 extended permit udp any host 64.104.1.4 eq 5247 
access-list 110 extended permit udp any host 64.104.1.5 eq 5246 
access-list 110 extended permit udp any host 64.104.1.5 eq 5247 
access-list 110 extended permit tcp any host 128.107.201.217 eq 8000 
access-list 110 extended permit tcp host 64.103.27.100 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp host 64.100.13.188 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp host 64.100.13.196 host 171.71.184.6 eq ldap 
access-list 110 extended permit udp host 64.103.27.100 host 171.71.184.6 eq 389 
access-list 110 extended permit udp host 64.100.13.188 host 171.71.184.6 eq 389 
access-list 110 extended permit udp host 64.100.13.196 host 171.71.184.6 eq 389 
access-list 110 extended permit tcp host 64.103.27.100 host 171.71.184.6 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.188 host 171.71.184.6 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.196 host 171.71.184.6 eq ldaps 
access-list 110 extended permit udp host 64.103.27.100 host 171.71.184.6 eq 636 
access-list 110 extended permit udp host 64.100.13.188 host 171.71.184.6 eq 636 
access-list 110 extended permit udp host 64.100.13.196 host 171.71.184.6 eq 636 
access-list 110 extended permit tcp host 173.39.116.10 object-group ldap_dsx_servers-global-1 eq ldap 
access-list 110 extended permit tcp host 173.39.116.11 object-group ldap_dsx_servers-global-1 eq ldap 
access-list 110 extended permit tcp host 173.39.116.10 object-group ldap_dsx_servers-global-1 eq ldaps 
access-list 110 extended permit tcp host 173.39.116.11 object-group ldap_dsx_servers-global-1 eq ldaps 
access-list 110 extended permit tcp any host 171.70.192.68 eq 8000 
access-list 110 extended permit tcp any host 171.70.192.68 eq www 
access-list 110 extended permit tcp any host 171.70.192.68 eq https 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.151 eq 2000 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.151 eq 2443 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.151 eq sip 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.151 eq 5061 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.152 eq 2000 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.152 eq 2443 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.152 eq sip 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.152 eq 5061 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.153 eq 2000 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.153 eq 2443 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.153 eq sip 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.153 eq 5061 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.154 eq 2000 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.154 eq 2443 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.154 eq sip 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.154 eq 5061 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.155 eq 2000 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.155 eq 2443 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.155 eq sip 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.155 eq 5061 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.156 eq 2000 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.156 eq 2443 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.156 eq sip 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.48.156 eq 5061 
access-list 110 extended permit tcp 172.17.153.128 255.255.255.240 host 171.70.146.140 eq 27000 
access-list 110 extended permit tcp 172.17.153.144 255.255.255.240 host 171.70.146.140 eq 27000 
access-list 110 extended permit tcp 172.17.153.128 255.255.255.240 host 171.70.146.140 eq 27010 
access-list 110 extended permit tcp 172.17.153.144 255.255.255.240 host 171.70.146.140 eq 27010 
access-list 110 extended permit udp 172.17.153.128 255.255.255.240 host 171.70.146.140 eq 902 
access-list 110 extended permit udp 172.17.153.144 255.255.255.240 host 171.70.146.140 eq 902 
access-list 110 extended permit tcp host 128.107.235.138 10.35.176.0 255.255.255.0 eq ftp 
access-list 110 extended permit tcp host 128.107.235.138 10.35.176.0 255.255.255.0 eq 26 
access-list 110 extended permit tcp host 128.107.235.138 10.35.176.0 255.255.255.0 eq www 
access-list 110 extended permit udp host 128.107.235.138 10.35.176.0 255.255.255.0 eq snmp 
access-list 110 extended permit tcp host 128.107.235.138 10.35.176.0 255.255.255.0 eq https 
access-list 110 extended permit udp host 128.107.235.138 10.35.176.0 255.255.255.0 eq syslog 
access-list 110 extended permit tcp host 128.107.235.138 10.35.176.0 255.255.255.0 eq 3128 
access-list 110 extended permit tcp host 128.107.235.138 10.35.176.0 255.255.255.0 eq 5432 
access-list 110 extended permit tcp host 128.107.235.138 10.35.176.0 255.255.255.0 eq 7777 
access-list 110 extended permit tcp host 128.107.235.138 10.35.176.0 255.255.255.0 eq 8080 
access-list 110 extended permit tcp host 128.107.235.138 10.35.176.0 255.255.255.0 eq 8443 
access-list 110 extended permit udp host 128.107.235.138 10.35.176.0 255.255.255.0 eq 9161 
access-list 110 extended permit tcp host 128.107.235.138 10.35.176.0 255.255.255.0 eq 9999 
access-list 110 extended permit tcp host 128.107.235.138 10.35.176.0 255.255.255.0 eq 45001 
access-list 110 extended permit tcp host 128.107.235.138 10.35.173.128 255.255.255.128 eq ftp 
access-list 110 extended permit tcp host 128.107.235.138 10.35.173.128 255.255.255.128 eq 26 
access-list 110 extended permit tcp host 128.107.235.138 10.35.173.128 255.255.255.128 eq www 
access-list 110 extended permit udp host 128.107.235.138 10.35.173.128 255.255.255.128 eq snmp 
access-list 110 extended permit tcp host 128.107.235.138 10.35.173.128 255.255.255.128 eq https 
access-list 110 extended permit udp host 128.107.235.138 10.35.173.128 255.255.255.128 eq syslog 
access-list 110 extended permit tcp host 128.107.235.138 10.35.173.128 255.255.255.128 eq 3128 
access-list 110 extended permit tcp host 128.107.235.138 10.35.173.128 255.255.255.128 eq 5432 
access-list 110 extended permit tcp host 128.107.235.138 10.35.173.128 255.255.255.128 eq 7777 
access-list 110 extended permit tcp host 128.107.235.138 10.35.173.128 255.255.255.128 eq 8080 
access-list 110 extended permit tcp host 128.107.235.138 10.35.173.128 255.255.255.128 eq 8443 
access-list 110 extended permit udp host 128.107.235.138 10.35.173.128 255.255.255.128 eq 9161 
access-list 110 extended permit tcp host 128.107.235.138 10.35.173.128 255.255.255.128 eq 9999 
access-list 110 extended permit tcp host 128.107.235.138 10.35.173.128 255.255.255.128 eq 45001 
access-list 110 extended permit tcp host 128.107.235.139 10.35.176.0 255.255.255.0 eq ftp 
access-list 110 extended permit tcp host 128.107.235.139 10.35.176.0 255.255.255.0 eq 26 
access-list 110 extended permit tcp host 128.107.235.139 10.35.176.0 255.255.255.0 eq www 
access-list 110 extended permit udp host 128.107.235.139 10.35.176.0 255.255.255.0 eq snmp 
access-list 110 extended permit tcp host 128.107.235.139 10.35.176.0 255.255.255.0 eq https 
access-list 110 extended permit udp host 128.107.235.139 10.35.176.0 255.255.255.0 eq syslog 
access-list 110 extended permit tcp host 128.107.235.139 10.35.176.0 255.255.255.0 eq 3128 
access-list 110 extended permit tcp host 128.107.235.139 10.35.176.0 255.255.255.0 eq 5432 
access-list 110 extended permit tcp host 128.107.235.139 10.35.176.0 255.255.255.0 eq 7777 
access-list 110 extended permit tcp host 128.107.235.139 10.35.176.0 255.255.255.0 eq 8080 
access-list 110 extended permit tcp host 128.107.235.139 10.35.176.0 255.255.255.0 eq 8443 
access-list 110 extended permit udp host 128.107.235.139 10.35.176.0 255.255.255.0 eq 9161 
access-list 110 extended permit tcp host 128.107.235.139 10.35.176.0 255.255.255.0 eq 9999 
access-list 110 extended permit tcp host 128.107.235.139 10.35.176.0 255.255.255.0 eq 45001 
access-list 110 extended permit tcp host 128.107.235.139 10.35.173.128 255.255.255.128 eq ftp 
access-list 110 extended permit tcp host 128.107.235.139 10.35.173.128 255.255.255.128 eq 26 
access-list 110 extended permit tcp host 128.107.235.139 10.35.173.128 255.255.255.128 eq www 
access-list 110 extended permit udp host 128.107.235.139 10.35.173.128 255.255.255.128 eq snmp 
access-list 110 extended permit tcp host 128.107.235.139 10.35.173.128 255.255.255.128 eq https 
access-list 110 extended permit udp host 128.107.235.139 10.35.173.128 255.255.255.128 eq syslog 
access-list 110 extended permit tcp host 128.107.235.139 10.35.173.128 255.255.255.128 eq 3128 
access-list 110 extended permit tcp host 128.107.235.139 10.35.173.128 255.255.255.128 eq 5432 
access-list 110 extended permit tcp host 128.107.235.139 10.35.173.128 255.255.255.128 eq 7777 
access-list 110 extended permit tcp host 128.107.235.139 10.35.173.128 255.255.255.128 eq 8080 
access-list 110 extended permit tcp host 128.107.235.139 10.35.173.128 255.255.255.128 eq 8443 
access-list 110 extended permit udp host 128.107.235.139 10.35.173.128 255.255.255.128 eq 9161 
access-list 110 extended permit tcp host 128.107.235.139 10.35.173.128 255.255.255.128 eq 9999 
access-list 110 extended permit tcp host 128.107.235.139 10.35.173.128 255.255.255.128 eq 45001 
access-list 110 extended permit tcp host 128.107.235.140 10.35.176.0 255.255.255.0 eq ftp 
access-list 110 extended permit tcp host 128.107.235.140 10.35.176.0 255.255.255.0 eq 26 
access-list 110 extended permit tcp host 128.107.235.140 10.35.176.0 255.255.255.0 eq www 
access-list 110 extended permit udp host 128.107.235.140 10.35.176.0 255.255.255.0 eq snmp 
access-list 110 extended permit tcp host 128.107.235.140 10.35.176.0 255.255.255.0 eq https 
access-list 110 extended permit udp host 128.107.235.140 10.35.176.0 255.255.255.0 eq syslog 
access-list 110 extended permit tcp host 128.107.235.140 10.35.176.0 255.255.255.0 eq 3128 
access-list 110 extended permit tcp host 128.107.235.140 10.35.176.0 255.255.255.0 eq 5432 
access-list 110 extended permit tcp host 128.107.235.140 10.35.176.0 255.255.255.0 eq 7777 
access-list 110 extended permit tcp host 128.107.235.140 10.35.176.0 255.255.255.0 eq 8080 
access-list 110 extended permit tcp host 128.107.235.140 10.35.176.0 255.255.255.0 eq 8443 
access-list 110 extended permit udp host 128.107.235.140 10.35.176.0 255.255.255.0 eq 9161 
access-list 110 extended permit tcp host 128.107.235.140 10.35.176.0 255.255.255.0 eq 9999 
access-list 110 extended permit tcp host 128.107.235.140 10.35.176.0 255.255.255.0 eq 45001 
access-list 110 extended permit tcp host 128.107.235.140 10.35.173.128 255.255.255.128 eq ftp 
access-list 110 extended permit tcp host 128.107.235.140 10.35.173.128 255.255.255.128 eq 26 
access-list 110 extended permit tcp host 128.107.235.140 10.35.173.128 255.255.255.128 eq www 
access-list 110 extended permit udp host 128.107.235.140 10.35.173.128 255.255.255.128 eq snmp 
access-list 110 extended permit tcp host 128.107.235.140 10.35.173.128 255.255.255.128 eq https 
access-list 110 extended permit udp host 128.107.235.140 10.35.173.128 255.255.255.128 eq syslog 
access-list 110 extended permit tcp host 128.107.235.140 10.35.173.128 255.255.255.128 eq 3128 
access-list 110 extended permit tcp host 128.107.235.140 10.35.173.128 255.255.255.128 eq 5432 
access-list 110 extended permit tcp host 128.107.235.140 10.35.173.128 255.255.255.128 eq 7777 
access-list 110 extended permit tcp host 128.107.235.140 10.35.173.128 255.255.255.128 eq 8080 
access-list 110 extended permit tcp host 128.107.235.140 10.35.173.128 255.255.255.128 eq 8443 
access-list 110 extended permit udp host 128.107.235.140 10.35.173.128 255.255.255.128 eq 9161 
access-list 110 extended permit tcp host 128.107.235.140 10.35.173.128 255.255.255.128 eq 9999 
access-list 110 extended permit tcp host 128.107.235.140 10.35.173.128 255.255.255.128 eq 45001 
access-list 110 extended permit tcp host 128.107.235.141 10.35.176.0 255.255.255.0 eq ftp 
access-list 110 extended permit tcp host 128.107.235.141 10.35.176.0 255.255.255.0 eq 26 
access-list 110 extended permit tcp host 128.107.235.141 10.35.176.0 255.255.255.0 eq www 
access-list 110 extended permit udp host 128.107.235.141 10.35.176.0 255.255.255.0 eq snmp 
access-list 110 extended permit tcp host 128.107.235.141 10.35.176.0 255.255.255.0 eq https 
access-list 110 extended permit udp host 128.107.235.141 10.35.176.0 255.255.255.0 eq syslog 
access-list 110 extended permit tcp host 128.107.235.141 10.35.176.0 255.255.255.0 eq 3128 
access-list 110 extended permit tcp host 128.107.235.141 10.35.176.0 255.255.255.0 eq 5432 
access-list 110 extended permit tcp host 128.107.235.141 10.35.176.0 255.255.255.0 eq 7777 
access-list 110 extended permit tcp host 128.107.235.141 10.35.176.0 255.255.255.0 eq 8080 
access-list 110 extended permit tcp host 128.107.235.141 10.35.176.0 255.255.255.0 eq 8443 
access-list 110 extended permit udp host 128.107.235.141 10.35.176.0 255.255.255.0 eq 9161 
access-list 110 extended permit tcp host 128.107.235.141 10.35.176.0 255.255.255.0 eq 9999 
access-list 110 extended permit tcp host 128.107.235.141 10.35.176.0 255.255.255.0 eq 45001 
access-list 110 extended permit tcp host 128.107.235.141 10.35.173.128 255.255.255.128 eq ftp 
access-list 110 extended permit tcp host 128.107.235.141 10.35.173.128 255.255.255.128 eq 26 
access-list 110 extended permit tcp host 128.107.235.141 10.35.173.128 255.255.255.128 eq www 
access-list 110 extended permit udp host 128.107.235.141 10.35.173.128 255.255.255.128 eq snmp 
access-list 110 extended permit tcp host 128.107.235.141 10.35.173.128 255.255.255.128 eq https 
access-list 110 extended permit udp host 128.107.235.141 10.35.173.128 255.255.255.128 eq syslog 
access-list 110 extended permit tcp host 128.107.235.141 10.35.173.128 255.255.255.128 eq 3128 
access-list 110 extended permit tcp host 128.107.235.141 10.35.173.128 255.255.255.128 eq 5432 
access-list 110 extended permit tcp host 128.107.235.141 10.35.173.128 255.255.255.128 eq 7777 
access-list 110 extended permit tcp host 128.107.235.141 10.35.173.128 255.255.255.128 eq 8080 
access-list 110 extended permit tcp host 128.107.235.141 10.35.173.128 255.255.255.128 eq 8443 
access-list 110 extended permit udp host 128.107.235.141 10.35.173.128 255.255.255.128 eq 9161 
access-list 110 extended permit tcp host 128.107.235.141 10.35.173.128 255.255.255.128 eq 9999 
access-list 110 extended permit tcp host 128.107.235.141 10.35.173.128 255.255.255.128 eq 45001 
access-list 110 extended permit tcp host 128.107.235.142 10.35.176.0 255.255.255.0 eq ftp 
access-list 110 extended permit tcp host 128.107.235.142 10.35.176.0 255.255.255.0 eq 26 
access-list 110 extended permit tcp host 128.107.235.142 10.35.176.0 255.255.255.0 eq www 
access-list 110 extended permit udp host 128.107.235.142 10.35.176.0 255.255.255.0 eq snmp 
access-list 110 extended permit tcp host 128.107.235.142 10.35.176.0 255.255.255.0 eq https 
access-list 110 extended permit udp host 128.107.235.142 10.35.176.0 255.255.255.0 eq syslog 
access-list 110 extended permit tcp host 128.107.235.142 10.35.176.0 255.255.255.0 eq 3128 
access-list 110 extended permit tcp host 128.107.235.142 10.35.176.0 255.255.255.0 eq 5432 
access-list 110 extended permit tcp host 128.107.235.142 10.35.176.0 255.255.255.0 eq 7777 
access-list 110 extended permit tcp host 128.107.235.142 10.35.176.0 255.255.255.0 eq 8080 
access-list 110 extended permit tcp host 128.107.235.142 10.35.176.0 255.255.255.0 eq 8443 
access-list 110 extended permit udp host 128.107.235.142 10.35.176.0 255.255.255.0 eq 9161 
access-list 110 extended permit tcp host 128.107.235.142 10.35.176.0 255.255.255.0 eq 9999 
access-list 110 extended permit tcp host 128.107.235.142 10.35.176.0 255.255.255.0 eq 45001 
access-list 110 extended permit tcp host 128.107.235.142 10.35.173.128 255.255.255.128 eq ftp 
access-list 110 extended permit tcp host 128.107.235.142 10.35.173.128 255.255.255.128 eq 26 
access-list 110 extended permit tcp host 128.107.235.142 10.35.173.128 255.255.255.128 eq www 
access-list 110 extended permit udp host 128.107.235.142 10.35.173.128 255.255.255.128 eq snmp 
access-list 110 extended permit tcp host 128.107.235.142 10.35.173.128 255.255.255.128 eq https 
access-list 110 extended permit udp host 128.107.235.142 10.35.173.128 255.255.255.128 eq syslog 
access-list 110 extended permit tcp host 128.107.235.142 10.35.173.128 255.255.255.128 eq 3128 
access-list 110 extended permit tcp host 128.107.235.142 10.35.173.128 255.255.255.128 eq 5432 
access-list 110 extended permit tcp host 128.107.235.142 10.35.173.128 255.255.255.128 eq 7777 
access-list 110 extended permit tcp host 128.107.235.142 10.35.173.128 255.255.255.128 eq 8080 
access-list 110 extended permit tcp host 128.107.235.142 10.35.173.128 255.255.255.128 eq 8443 
access-list 110 extended permit udp host 128.107.235.142 10.35.173.128 255.255.255.128 eq 9161 
access-list 110 extended permit tcp host 128.107.235.142 10.35.173.128 255.255.255.128 eq 9999 
access-list 110 extended permit tcp host 128.107.235.142 10.35.173.128 255.255.255.128 eq 45001 
access-list 110 extended permit esp host 68.118.31.23 host 171.71.3.14 
access-list 110 extended permit udp host 68.118.31.23 host 171.71.3.14 eq isakmp 
access-list 110 extended permit esp host 68.118.31.23 host 171.71.3.26 
access-list 110 extended permit udp host 68.118.31.23 host 171.71.3.26 eq isakmp 
access-list 110 extended permit esp host 63.148.170.30 host 171.71.3.14 
access-list 110 extended permit udp host 63.148.170.30 host 171.71.3.14 eq isakmp 
access-list 110 extended permit esp host 63.148.170.30 host 171.71.3.26 
access-list 110 extended permit udp host 63.148.170.30 host 171.71.3.26 eq isakmp 
access-list 110 extended permit esp host 64.103.36.18 host 10.61.2.114 
access-list 110 extended permit udp host 64.103.36.18 host 10.61.2.114 eq isakmp 
access-list 110 extended permit esp host 72.163.216.158 host 10.76.45.30 
access-list 110 extended permit udp host 72.163.216.158 host 10.76.45.30 eq isakmp 
access-list 110 extended permit esp host 196.192.6.24 host 144.254.146.9 
access-list 110 extended permit udp host 196.192.6.24 host 144.254.146.9 eq isakmp 
access-list 110 extended permit udp host 196.192.6.24 host 144.254.146.9 eq 4500 
access-list 110 extended permit esp host 196.192.6.28 host 144.254.146.9 
access-list 110 extended permit udp host 196.192.6.28 host 144.254.146.9 eq isakmp 
access-list 110 extended permit udp host 196.192.6.28 host 144.254.146.9 eq 4500 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.2 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.3 
access-list 110 extended permit gre host 64.103.36.241 host 10.54.43.130 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.141.185 
access-list 110 extended permit gre host 64.104.127.65 host 10.74.164.145 
access-list 110 extended permit gre host 72.163.216.158 any 
access-list 110 extended permit gre host 64.104.127.60 any 
access-list 110 extended permit gre host 64.104.252.227 any 
access-list 110 extended permit gre host 64.104.44.33 any 
access-list 110 extended permit gre host 72.163.249.17 any 
access-list 110 extended permit esp host 82.213.2.186 host 144.254.146.9 
access-list 110 extended permit udp host 82.213.2.186 host 144.254.146.9 eq isakmp 
access-list 110 extended permit gre host 128.107.240.24 host 10.68.12.15 
access-list 110 extended permit gre host 128.107.240.170 host 10.68.12.15 
access-list 110 extended permit gre host 10.68.12.15 host 128.107.240.24 
access-list 110 extended permit gre host 10.68.12.15 host 128.107.240.170 
access-list 110 extended permit udp host 128.107.81.84 host 10.92.240.142 eq isakmp 
access-list 110 extended permit esp host 128.107.81.84 host 10.92.240.142 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.31 range 1024 4999 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.31 eq https 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.31 eq 8080 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.16 eq 3337 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.16 range 1024 4999 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.17 eq 3337 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.17 eq 3336 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.17 range 1024 4999 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.62 eq 3337 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.62 eq 3336 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.62 range 1024 4999 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.63 eq 3337 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.63 eq 3336 
access-list 110 extended permit tcp host 128.107.234.216 host 171.68.10.71 eq domain 
access-list 110 extended permit tcp host 128.107.85.170 host 171.70.121.11 range sip 5061 
access-list 110 extended permit tcp host 128.107.85.170 host 171.70.121.12 range sip 5061 
access-list 110 extended permit tcp host 128.107.85.170 host 171.70.121.13 range sip 5061 
access-list 110 extended permit tcp host 128.107.85.170 host 171.70.121.14 range sip 5061 
access-list 110 extended permit tcp host 128.107.85.170 host 10.35.1.15 range sip 5061 
access-list 110 extended permit tcp host 128.107.85.170 host 10.35.1.16 range sip 5061 
access-list 110 extended permit ip host 128.107.77.11 host 64.101.8.21 
access-list 110 extended permit tcp host 128.107.77.19 host 64.101.8.99 eq 7915 
access-list 110 extended permit tcp host 128.107.77.19 host 64.101.8.99 eq www 
access-list 110 extended permit tcp host 128.107.77.19 host 64.101.8.99 eq https 
access-list 110 extended permit tcp host 128.107.77.20 host 64.101.8.99 eq 7915 
access-list 110 extended permit tcp host 128.107.77.20 host 64.101.8.99 eq www 
access-list 110 extended permit tcp host 128.107.77.20 host 64.101.8.99 eq https 
access-list 110 extended permit tcp host 128.107.77.17 host 64.101.8.99 eq 7915 
access-list 110 extended permit tcp host 128.107.77.17 host 64.101.8.99 eq www 
access-list 110 extended permit tcp host 128.107.77.17 host 64.101.8.99 eq https 
access-list 110 extended permit tcp host 128.107.77.18 host 64.101.8.99 eq 7915 
access-list 110 extended permit tcp host 128.107.77.18 host 64.101.8.99 eq www 
access-list 110 extended permit tcp host 128.107.77.18 host 64.101.8.99 eq https 
access-list 110 extended permit udp any host 62.168.39.173 eq 4500 
access-list 110 extended permit udp any host 81.19.10.224 eq 4500 
access-list 110 extended permit udp any host 144.254.146.18 eq 4500 
access-list 110 extended permit udp any host 144.254.146.22 eq 4500 
access-list 110 extended permit esp host 82.159.191.18 host 64.103.35.189 
access-list 110 extended permit udp host 82.159.191.18 host 64.103.35.189 eq isakmp 
access-list 110 extended permit udp any host 64.104.77.181 eq isakmp 
access-list 110 extended permit esp any host 64.104.77.181 
access-list 110 extended permit esp host 211.25.222.186 host 64.104.77.181 
access-list 110 extended permit udp host 211.25.222.186 host 64.104.77.181 eq isakmp 
access-list 110 extended permit udp host 211.25.222.186 host 64.104.77.181 eq 4500 
access-list 110 extended permit esp host 211.25.222.218 host 64.104.77.181 
access-list 110 extended permit udp host 211.25.222.218 host 64.104.77.181 eq isakmp 
access-list 110 extended permit udp host 211.25.222.218 host 64.104.77.181 eq 4500 
access-list 110 extended permit esp host 211.25.222.182 host 64.104.77.181 
access-list 110 extended permit udp host 211.25.222.182 host 64.104.77.181 eq isakmp 
access-list 110 extended permit udp host 211.25.222.182 host 64.104.77.181 eq 4500 
access-list 110 extended permit esp host 211.25.222.190 host 64.104.77.181 
access-list 110 extended permit udp host 211.25.222.190 host 64.104.77.181 eq isakmp 
access-list 110 extended permit udp host 211.25.222.190 host 64.104.77.181 eq 4500 
access-list 110 extended permit esp host 175.139.202.53 host 64.104.77.181 
access-list 110 extended permit udp host 175.139.202.53 host 64.104.77.181 eq isakmp 
access-list 110 extended permit udp host 175.139.202.53 host 64.104.77.181 eq 4500 
access-list 110 extended permit esp host 188.225.178.102 host 144.254.146.9 
access-list 110 extended permit udp host 188.225.178.102 host 144.254.146.9 eq isakmp 
access-list 110 extended permit esp host 217.21.8.90 host 144.254.146.9 
access-list 110 extended permit udp host 217.21.8.90 host 144.254.146.9 eq isakmp 
access-list 110 extended permit esp host 82.45.149.150 host 64.103.35.189 
access-list 110 extended permit udp host 82.45.149.150 host 64.103.35.189 eq isakmp 
access-list 110 extended permit gre host 128.107.235.30 host 10.66.139.124 
access-list 110 extended permit gre host 64.104.95.129 host 10.66.139.124 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.9 
access-list 110 extended permit udp host 12.49.117.253 host 64.101.188.126 eq isakmp 
access-list 110 extended permit esp host 12.49.117.253 host 64.101.188.126 
access-list 110 extended permit udp host 12.49.117.253 host 64.101.188.126 eq 4500 
access-list 110 extended permit udp host 12.49.117.253 host 64.101.188.126 eq 10000 
access-list 110 extended permit ah host 12.49.117.253 host 64.101.188.126 
access-list 110 extended permit esp host 61.118.178.189 host 64.104.14.232 
access-list 110 extended permit udp host 61.118.178.189 host 64.104.14.232 eq isakmp 
access-list 110 extended permit esp host 61.118.178.189 host 64.104.14.233 
access-list 110 extended permit udp host 61.118.178.189 host 64.104.14.233 eq isakmp 
access-list 110 extended permit icmp host 172.17.153.124 host 192.168.140.22 echo-reply 
access-list 110 extended permit icmp host 172.17.153.125 host 192.168.140.22 echo-reply 
access-list 110 extended permit icmp host 172.17.153.126 host 192.168.140.22 echo-reply 
access-list 110 extended permit icmp host 212.183.133.181 10.52.196.0 255.255.255.0 echo-reply 
access-list 110 extended permit icmp host 128.107.250.227 host 172.27.204.107 echo 
access-list 110 extended permit icmp host 128.107.250.228 host 172.27.204.107 echo 
access-list 110 extended permit gre host 172.17.153.65 host 10.61.32.7 
access-list 110 extended permit eigrp 64.103.36.192 255.255.255.224 64.103.36.192 255.255.255.224 
access-list 110 extended permit eigrp 64.103.36.192 255.255.255.224 host 224.0.0.10 
access-list 110 extended permit eigrp 64.104.252.32 255.255.255.224 64.104.252.32 255.255.255.224 
access-list 110 extended permit eigrp 64.104.252.32 255.255.255.224 host 224.0.0.10 
access-list 110 extended permit eigrp 64.102.241.128 255.255.255.224 64.102.241.128 255.255.255.224 
access-list 110 extended permit eigrp 64.102.241.128 255.255.255.224 host 224.0.0.10 
access-list 110 extended permit eigrp 128.107.236.32 255.255.255.224 128.107.236.32 255.255.255.224 
access-list 110 extended permit eigrp 128.107.236.32 255.255.255.224 host 224.0.0.10 
access-list 110 extended permit eigrp 64.104.127.176 255.255.255.240 64.104.127.176 255.255.255.240 
access-list 110 extended permit eigrp 64.104.127.176 255.255.255.240 host 224.0.0.10 
access-list 110 extended permit eigrp 64.104.46.224 255.255.255.240 64.104.46.224 255.255.255.240 
access-list 110 extended permit eigrp 64.104.46.224 255.255.255.240 host 224.0.0.10 
access-list 110 extended permit eigrp 72.163.0.64 255.255.255.240 72.163.0.64 255.255.255.240 
access-list 110 extended permit eigrp 72.163.0.64 255.255.255.240 host 224.0.0.10 
access-list 110 extended permit eigrp 72.163.248.160 255.255.255.240 72.163.248.160 255.255.255.240 
access-list 110 extended permit eigrp 72.163.248.160 255.255.255.240 host 224.0.0.10 
access-list 110 extended permit eigrp 198.135.0.240 255.255.255.240 198.135.0.240 255.255.255.240 
access-list 110 extended permit eigrp 198.135.0.240 255.255.255.240 host 224.0.0.10 
access-list 110 extended permit eigrp 72.163.216.224 255.255.255.240 72.163.216.224 255.255.255.240 
access-list 110 extended permit eigrp 72.163.216.224 255.255.255.240 host 224.0.0.10 
access-list 110 extended permit eigrp 192.118.78.160 255.255.255.240 192.118.76.0 255.255.252.0 
access-list 110 extended permit eigrp 192.118.78.160 255.255.255.240 host 224.0.0.10 
access-list 110 extended permit eigrp 64.104.94.112 255.255.255.240 64.104.94.112 255.255.255.240 
access-list 110 extended permit eigrp 64.104.94.112 255.255.255.240 host 224.0.0.10 
access-list 110 extended permit eigrp 173.37.148.224 255.255.255.240 173.37.148.224 255.255.255.240 
access-list 110 extended permit eigrp 173.37.148.224 255.255.255.240 host 224.0.0.10 
access-list 110 extended permit eigrp 173.36.112.0 255.255.255.240 173.36.112.0 255.255.255.240 
access-list 110 extended permit eigrp 173.36.112.0 255.255.255.240 host 224.0.0.10 
access-list 110 extended permit eigrp 173.38.208.128 255.255.255.240 173.38.208.128 255.255.255.240 
access-list 110 extended permit eigrp 173.38.208.128 255.255.255.240 host 224.0.0.10 
access-list 110 extended permit esp host 72.163.216.158 host 10.76.12.48 
access-list 110 extended permit udp host 72.163.216.158 host 10.76.12.48 eq isakmp 
access-list 110 extended permit esp host 64.104.127.60 host 10.74.69.254 
access-list 110 extended permit udp host 64.104.127.60 host 10.74.69.254 eq isakmp 
access-list 110 extended permit esp host 64.104.127.60 host 10.74.43.26 
access-list 110 extended permit udp host 64.104.127.60 host 10.74.43.26 eq isakmp 
access-list 110 extended permit esp host 64.104.127.60 host 10.74.43.142 
access-list 110 extended permit udp host 64.104.127.60 host 10.74.43.142 eq isakmp 
access-list 110 extended permit tcp host 64.104.126.52 host 10.75.222.110 eq ssh 
access-list 110 extended permit esp host 64.104.127.60 host 10.74.43.38 
access-list 110 extended permit udp host 64.104.127.60 host 10.74.43.38 eq isakmp 
access-list 110 extended permit esp any host 114.112.188.82 
access-list 110 extended permit udp any host 114.112.188.82 eq isakmp 
access-list 110 extended permit esp host 59.46.64.130 host 72.163.247.98 
access-list 110 extended permit udp host 59.46.64.130 host 72.163.247.98 eq isakmp 
access-list 110 extended permit gre host 64.104.127.65 host 10.74.160.145 
access-list 110 extended permit gre host 64.104.127.65 host 10.66.139.124 
access-list 110 extended permit esp host 59.151.117.90 any 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.12.81 
access-list 110 extended permit esp host 64.104.127.60 host 10.74.69.198 
access-list 110 extended permit udp host 64.104.127.60 host 10.74.69.198 eq isakmp 
access-list 110 extended permit tcp any host 72.163.6.11 eq https 
access-list 110 extended permit tcp any host 72.163.6.12 eq https 
access-list 110 extended permit tcp any host 72.163.6.13 eq https 
access-list 110 extended permit tcp any host 72.163.6.14 eq https 
access-list 110 extended permit tcp host 72.163.6.11 host 72.163.56.102 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.12 host 72.163.56.102 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.13 host 72.163.56.102 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.14 host 72.163.56.102 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.11 host 171.68.38.106 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.12 host 171.68.38.106 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.13 host 171.68.38.106 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.14 host 171.68.38.106 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.11 host 171.68.224.6 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.12 host 171.68.224.6 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.13 host 171.68.224.6 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.14 host 171.68.224.6 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.11 host 72.163.62.158 eq https 
access-list 110 extended permit tcp host 72.163.6.12 host 72.163.62.158 eq https 
access-list 110 extended permit tcp host 72.163.6.13 host 72.163.62.158 eq https 
access-list 110 extended permit tcp host 72.163.6.14 host 72.163.62.158 eq https 
access-list 110 extended permit tcp host 72.163.6.11 host 72.163.62.222 eq https 
access-list 110 extended permit tcp host 72.163.6.12 host 72.163.62.222 eq https 
access-list 110 extended permit tcp host 72.163.6.13 host 72.163.62.222 eq https 
access-list 110 extended permit tcp host 72.163.6.14 host 72.163.62.222 eq https 
access-list 110 extended permit tcp host 72.163.6.11 host 72.163.63.30 eq https 
access-list 110 extended permit tcp host 72.163.6.12 host 72.163.63.30 eq https 
access-list 110 extended permit tcp host 72.163.6.13 host 72.163.63.30 eq https 
access-list 110 extended permit tcp host 72.163.6.14 host 72.163.63.30 eq https 
access-list 110 extended permit tcp host 72.163.6.11 host 72.163.129.198 eq https 
access-list 110 extended permit tcp host 72.163.6.12 host 72.163.129.198 eq https 
access-list 110 extended permit tcp host 72.163.6.13 host 72.163.129.198 eq https 
access-list 110 extended permit tcp host 72.163.6.14 host 72.163.129.198 eq https 
access-list 110 extended permit tcp host 72.163.6.11 host 64.104.123.83 eq https 
access-list 110 extended permit tcp host 72.163.6.12 host 64.104.123.83 eq https 
access-list 110 extended permit tcp host 72.163.6.13 host 64.104.123.83 eq https 
access-list 110 extended permit tcp host 72.163.6.14 host 64.104.123.83 eq https 
access-list 110 extended permit tcp host 72.163.6.11 host 144.254.231.90 eq https 
access-list 110 extended permit tcp host 72.163.6.12 host 144.254.231.90 eq https 
access-list 110 extended permit tcp host 72.163.6.13 host 144.254.231.90 eq https 
access-list 110 extended permit tcp host 72.163.6.14 host 144.254.231.90 eq https 
access-list 110 extended permit tcp host 72.163.6.11 host 171.70.151.132 eq https 
access-list 110 extended permit tcp host 72.163.6.12 host 171.70.151.132 eq https 
access-list 110 extended permit tcp host 72.163.6.13 host 171.70.151.132 eq https 
access-list 110 extended permit tcp host 72.163.6.14 host 171.70.151.132 eq https 
access-list 110 extended permit tcp host 72.163.6.11 host 128.107.191.10 eq https 
access-list 110 extended permit tcp host 72.163.6.12 host 128.107.191.10 eq https 
access-list 110 extended permit tcp host 72.163.6.13 host 128.107.191.10 eq https 
access-list 110 extended permit tcp host 72.163.6.14 host 128.107.191.10 eq https 
access-list 110 extended permit esp host 222.82.144.158 host 72.163.247.98 
access-list 110 extended permit udp host 222.82.144.158 host 72.163.247.98 eq isakmp 
access-list 110 extended permit esp host 116.228.21.214 host 72.163.247.99 
access-list 110 extended permit udp host 116.228.21.214 host 72.163.247.99 eq isakmp 
access-list 110 extended permit udp host 116.228.21.214 host 72.163.247.99 eq 4500 
access-list 110 extended permit esp host 64.104.127.60 host 10.74.43.86 
access-list 110 extended permit udp host 64.104.127.60 host 10.74.43.86 eq isakmp 
access-list 110 extended permit esp host 219.144.162.132 host 72.163.247.98 
access-list 110 extended permit udp host 219.144.162.132 host 72.163.247.98 eq isakmp 
access-list 110 extended permit esp host 203.210.210.95 host 64.104.81.209 
access-list 110 extended permit udp host 203.210.210.95 host 64.104.81.209 eq isakmp 
access-list 110 extended permit esp host 219.144.162.134 host 72.163.247.98 
access-list 110 extended permit udp host 219.144.162.134 host 72.163.247.98 eq isakmp 
access-list 110 extended permit esp host 221.226.156.3 host 72.163.247.98 
access-list 110 extended permit esp host 221.226.156.3 host 72.163.247.102 
access-list 110 extended permit udp host 221.226.156.3 host 72.163.247.98 eq isakmp 
access-list 110 extended permit udp host 221.226.156.3 host 72.163.247.102 eq isakmp 
access-list 110 extended permit udp host 64.104.127.236 host 10.75.225.204 eq snmp 
access-list 110 extended permit udp host 64.104.127.236 host 10.75.225.205 eq snmp 
access-list 110 extended permit esp host 61.183.223.42 host 72.163.247.98 
access-list 110 extended permit udp host 61.183.223.42 host 72.163.247.98 eq isakmp 
access-list 110 extended permit esp host 64.104.127.60 host 10.74.43.30 
access-list 110 extended permit udp host 64.104.127.60 host 10.74.43.30 eq isakmp 
access-list 110 extended permit esp host 72.163.216.158 host 10.76.45.26 
access-list 110 extended permit ah host 72.163.216.158 host 10.76.45.26 
access-list 110 extended permit udp host 72.163.216.158 host 10.76.45.26 eq isakmp 
access-list 110 extended permit esp host 120.36.2.74 host 72.163.247.98 
access-list 110 extended permit udp host 120.36.2.74 host 72.163.247.98 eq isakmp 
access-list 110 extended permit esp host 82.45.149.150 host 64.103.35.61 
access-list 110 extended permit udp host 82.45.149.150 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 59.46.172.198 host 72.163.247.99 
access-list 110 extended permit udp host 59.46.172.198 host 72.163.247.99 eq isakmp 
access-list 110 extended permit esp host 221.224.201.178 host 72.163.247.98 
access-list 110 extended permit udp host 221.224.201.178 host 72.163.247.98 eq isakmp 
access-list 110 extended permit esp host 58.211.57.218 host 72.163.247.99 
access-list 110 extended permit udp host 58.211.57.218 host 72.163.247.99 eq isakmp 
access-list 110 extended permit esp host 219.149.10.202 host 72.163.247.99 
access-list 110 extended permit udp host 219.149.10.202 host 72.163.247.99 eq isakmp 
access-list 110 extended permit esp host 64.104.127.60 host 10.74.194.34 
access-list 110 extended permit udp host 64.104.127.60 host 10.74.194.34 eq isakmp 
access-list 110 extended permit tcp host 64.102.244.103 host 10.81.98.169 eq 8015 
access-list 110 extended permit igmp any object-group multicast_networks-global-1 
access-list 110 extended permit gre host 64.103.36.241 host 10.48.101.28 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.133.185 
access-list 110 extended permit gre host 64.103.36.241 host 10.52.22.7 
access-list 110 extended permit gre host 64.103.36.241 host 10.52.22.3 
access-list 110 extended permit esp host 62.68.38.110 host 64.103.35.61 
access-list 110 extended permit udp host 62.68.38.110 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 62.68.39.158 host 64.103.35.61 
access-list 110 extended permit udp host 62.68.39.158 host 64.103.35.61 eq isakmp 
access-list 110 extended permit tcp any host 144.254.221.36 eq https 
access-list 110 extended permit tcp any host 144.254.221.36 eq www 
access-list 110 extended permit tcp any host 144.254.221.43 eq https 
access-list 110 extended permit tcp any host 144.254.221.43 eq www 
access-list 110 extended permit tcp any host 144.254.221.44 eq https 
access-list 110 extended permit tcp any host 144.254.221.44 eq www 
access-list 110 extended permit esp host 62.146.143.22 host 64.103.35.61 
access-list 110 extended permit esp host 62.146.143.22 host 64.103.35.189 
access-list 110 extended permit udp host 62.146.143.22 host 64.103.35.61 eq isakmp 
access-list 110 extended permit udp host 62.146.143.22 host 64.103.35.189 eq isakmp 
access-list 110 extended permit gre host 64.103.36.241 host 216.128.58.185 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.220.225 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.138.113 
access-list 110 extended permit gre host 64.104.44.97 host 10.71.55.193 
access-list 110 extended permit gre host 72.163.216.168 host 10.76.237.96 
access-list 110 extended permit gre host 64.103.36.241 host 10.53.207.241 
access-list 110 extended permit gre host 64.103.36.241 host 10.53.207.253 
access-list 110 extended permit esp host 193.254.166.5 host 144.254.146.9 
access-list 110 extended permit udp host 193.254.166.5 host 144.254.146.9 eq isakmp 
access-list 110 extended permit gre host 72.163.216.168 host 10.76.237.97 
access-list 110 extended permit gre host 72.163.216.168 host 10.77.114.137 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.141.49 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.142.233 
access-list 110 extended permit gre host 64.103.36.241 host 10.54.99.1 
access-list 110 extended permit gre host 64.104.252.65 host 10.67.54.97 
access-list 110 extended permit gre host 64.103.36.241 host 10.53.207.243 
access-list 110 extended permit gre host 64.103.36.241 host 10.53.207.245 
access-list 110 extended permit gre host 64.103.36.241 host 10.53.207.247 
access-list 110 extended permit gre host 64.103.36.241 host 10.53.207.249 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.178.209 
access-list 110 extended permit gre host 64.103.36.241 host 216.128.58.49 
access-list 110 extended permit gre host 64.103.36.241 host 10.113.15.225 
access-list 110 extended permit esp host 80.254.144.140 host 64.103.35.189 
access-list 110 extended permit udp host 80.254.144.140 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 80.254.144.140 host 64.103.35.61 
access-list 110 extended permit udp host 80.254.144.140 host 64.103.35.61 eq isakmp 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.66.97 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.142.57 
access-list 110 extended permit esp host 194.170.166.186 host 216.128.60.197 
access-list 110 extended permit udp host 194.170.166.186 host 216.128.60.197 eq isakmp 
access-list 110 extended permit esp host 194.170.166.186 host 216.128.60.189 
access-list 110 extended permit udp host 194.170.166.186 host 216.128.60.189 eq isakmp 
access-list 110 extended permit esp any host 72.163.215.130 
access-list 110 extended permit udp any host 72.163.215.130 eq isakmp 
access-list 110 extended permit udp any host 72.163.215.130 eq 4500 
access-list 110 extended permit tcp host 64.103.37.68 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.103.37.66 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.103.37.67 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.103.37.68 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.103.37.66 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.103.37.67 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.103.37.68 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 64.103.37.66 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 64.103.37.67 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 64.103.37.68 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.103.37.68 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.103.37.68 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.103.37.66 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.103.37.66 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.103.37.66 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.103.37.67 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.103.37.67 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.103.37.67 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.102.241.34 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.102.241.34 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.102.241.34 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.102.241.35 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.102.241.35 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.102.241.35 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.102.241.36 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.102.241.36 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.102.241.36 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 128.107.224.210 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 128.107.224.210 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 128.107.224.210 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 128.107.224.211 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 128.107.224.211 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 128.107.224.211 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 128.107.224.212 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 128.107.224.212 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 128.107.224.212 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 72.163.217.18 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 72.163.217.18 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 72.163.217.18 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 72.163.217.19 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 72.163.217.19 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 72.163.217.19 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 72.163.217.20 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 72.163.217.20 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 72.163.217.20 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.104.127.114 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.104.127.114 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.104.127.114 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.104.127.115 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.104.127.115 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.104.127.115 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.104.127.116 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.104.127.116 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.104.127.116 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.104.94.66 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.104.94.66 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.104.94.66 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.104.94.67 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.104.94.67 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.104.94.67 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.104.94.68 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.104.94.68 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.104.94.68 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.104.249.130 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.104.249.130 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.104.249.130 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.104.249.131 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.104.249.131 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.104.249.131 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.104.249.132 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.104.249.132 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.104.249.132 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.104.44.2 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.104.44.2 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.104.44.2 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.104.44.3 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.104.44.3 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.104.44.3 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.104.44.4 host 72.163.32.168 eq https 
access-list 110 extended permit tcp host 64.104.44.4 host 72.163.32.154 eq https 
access-list 110 extended permit tcp host 64.104.44.4 host 72.163.32.155 eq https 
access-list 110 extended permit tcp host 64.104.44.131 host 10.68.3.51 eq sip 
access-list 110 extended permit udp host 64.104.44.131 host 10.68.3.51 eq sip 
access-list 110 extended permit tcp host 64.104.44.131 host 10.68.3.51 eq 2000 
access-list 110 extended permit tcp host 64.104.44.131 host 10.68.3.53 eq sip 
access-list 110 extended permit udp host 64.104.44.131 host 10.68.3.53 eq sip 
access-list 110 extended permit tcp host 64.104.44.131 host 10.68.3.53 eq 2000 
access-list 110 extended permit tcp host 64.104.44.131 host 10.68.3.55 eq sip 
access-list 110 extended permit udp host 64.104.44.131 host 10.68.3.55 eq sip 
access-list 110 extended permit tcp host 64.104.44.131 host 10.68.3.55 eq 2000 
access-list 110 extended permit tcp host 64.104.44.131 host 10.68.3.57 eq sip 
access-list 110 extended permit udp host 64.104.44.131 host 10.68.3.57 eq sip 
access-list 110 extended permit tcp host 64.104.44.131 host 10.68.3.57 eq 2000 
access-list 110 extended permit tcp host 64.103.37.170 host 171.70.93.208 eq https 
access-list 110 extended permit tcp host 64.103.37.170 host 64.102.6.182 eq ldap 
access-list 110 extended permit tcp host 10.101.15.243 host 171.68.224.207 eq ldap 
access-list 110 extended permit tcp host 10.101.15.243 host 171.68.224.207 eq ldaps 
access-list 110 extended permit tcp host 10.101.15.243 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp host 10.101.15.243 host 171.71.184.6 eq ldaps 
access-list 110 extended permit tcp host 10.101.15.243 host 72.163.57.6 eq ldap 
access-list 110 extended permit tcp host 10.101.15.243 host 72.163.57.6 eq ldaps 
access-list 110 extended permit tcp host 10.101.15.243 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp host 10.101.15.243 host 64.102.9.230 eq ldaps 
access-list 110 extended permit tcp host 10.101.15.243 host 173.37.114.14 eq 3306 
access-list 110 extended permit tcp host 64.103.37.170 host 171.70.165.234 eq https 
access-list 110 extended permit gre host 64.103.36.241 host 10.59.22.241 
access-list 110 extended permit gre host 64.103.36.241 host 10.66.139.124 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.130.185 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.130.121 
access-list 110 extended permit gre host 64.103.36.241 host 10.53.209.1 
access-list 110 extended permit gre host 64.103.36.241 host 10.62.68.33 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.137.145 
access-list 110 extended permit gre host 10.104.145.4 host 72.163.216.168 
access-list 110 extended permit gre host 72.163.216.168 host 10.105.19.243 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.5 
access-list 110 extended permit gre host 128.107.235.30 10.92.0.0 255.252.0.0 
access-list 110 extended permit gre host 128.107.235.30 10.76.0.0 255.254.0.0 
access-list 110 extended permit gre host 128.107.235.30 172.24.18.0 255.255.254.0 
access-list 110 extended permit gre host 128.107.235.30 10.88.0.0 255.254.0.0 
access-list 110 extended permit gre host 128.107.235.30 10.123.0.0 255.255.0.0 
access-list 110 extended permit gre host 128.107.235.30 192.168.165.0 255.255.255.0 
access-list 110 extended permit gre host 128.107.235.30 171.71.64.0 255.255.255.128 
access-list 110 extended permit gre host 128.107.235.30 10.101.128.0 255.255.224.0 
access-list 110 extended permit gre host 128.107.240.170 host 10.81.255.20 
access-list 110 extended permit gre host 128.107.235.30 host 10.77.116.113 
access-list 110 extended permit gre host 128.107.235.30 10.200.46.0 255.255.255.240 
access-list 110 extended permit gre host 172.17.153.20 host 10.101.206.45 
access-list 110 extended permit gre host 128.107.240.170 host 10.101.206.46 
access-list 110 extended permit gre host 10.101.206.45 host 172.17.153.20 
access-list 110 extended permit gre host 10.101.206.46 host 128.107.240.170 
access-list 110 extended permit gre host 172.17.153.20 host 10.18.228.1 
access-list 110 extended permit gre host 172.17.153.65 host 10.18.228.2 
access-list 110 extended permit gre host 10.123.20.67 host 172.17.153.20 
access-list 110 extended permit gre host 10.123.20.68 host 128.107.240.170 
access-list 110 extended permit gre host 172.17.153.20 host 10.123.20.67 
access-list 110 extended permit gre host 128.107.240.170 host 10.123.20.68 
access-list 110 extended permit gre host 172.17.153.20 host 10.66.129.144 
access-list 110 extended permit gre host 128.107.240.170 host 10.66.129.144 
access-list 110 extended permit gre any host 198.135.3.4 
access-list 110 extended permit gre any host 198.135.3.5 
access-list 110 extended permit gre any host 198.135.3.6 
access-list 110 extended permit udp any host 198.135.3.4 eq isakmp 
access-list 110 extended permit udp any host 198.135.3.5 eq isakmp 
access-list 110 extended permit udp any host 198.135.3.6 eq isakmp 
access-list 110 extended permit udp any host 198.135.3.4 eq 4500 
access-list 110 extended permit udp any host 198.135.3.5 eq 4500 
access-list 110 extended permit udp any host 198.135.3.6 eq 4500 
access-list 110 extended permit gre host 172.17.153.20 host 10.56.109.173 
access-list 110 extended permit gre host 172.17.153.65 host 10.56.109.173 
access-list 110 extended permit gre host 72.163.216.158 host 10.78.224.30 
access-list 110 extended permit tcp 64.102.245.224 255.255.255.224 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp 64.102.245.224 255.255.255.224 host 64.102.9.230 eq ldaps 
access-list 110 extended permit tcp 64.102.245.224 255.255.255.224 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp 64.102.245.224 255.255.255.224 host 171.71.184.6 eq ldaps 
access-list 110 extended permit tcp 64.102.245.224 255.255.255.224 host 171.68.224.207 eq ldap 
access-list 110 extended permit tcp 64.102.245.224 255.255.255.224 host 171.68.224.207 eq ldaps 
access-list 110 extended permit tcp 64.102.245.224 255.255.255.224 host 72.163.57.6 eq ldap 
access-list 110 extended permit tcp 64.102.245.224 255.255.255.224 host 72.163.57.6 eq ldaps 
access-list 110 extended permit esp host 64.103.36.18 host 10.49.215.178 
access-list 110 extended permit udp host 64.103.36.18 host 10.49.215.178 eq isakmp 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.6 
access-list 110 extended deny ip any host 128.107.201.239 
access-list 110 extended permit tcp any 128.107.201.236 255.255.255.252 eq https 
access-list 110 extended permit udp any 128.107.201.236 255.255.255.252 eq 443 
access-list 110 extended permit esp any 128.107.201.236 255.255.255.252 
access-list 110 extended permit udp any 128.107.201.236 255.255.255.252 eq 10000 
access-list 110 extended permit tcp any 128.107.201.236 255.255.255.252 eq 10000 
access-list 110 extended permit udp any 128.107.201.236 255.255.255.252 eq isakmp 
access-list 110 extended permit udp any 128.107.201.236 255.255.255.252 eq 4500 
access-list 110 extended permit gre host 64.103.36.241 host 10.147.100.129 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.12 
access-list 110 extended permit esp host 93.109.251.86 host 64.103.35.61 
access-list 110 extended permit udp host 93.109.251.86 host 64.103.35.61 eq isakmp 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.143.106 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.143.105 
access-list 110 extended permit udp host 128.107.81.144 host 10.35.16.42 eq syslog 
access-list 110 extended permit udp host 128.107.81.145 host 10.35.16.42 eq syslog 
access-list 110 extended permit udp host 128.107.241.119 host 10.35.16.42 eq syslog 
access-list 110 extended permit udp host 128.107.233.36 host 10.35.16.42 eq syslog 
access-list 110 extended permit udp host 128.107.81.144 host 10.35.16.43 eq syslog 
access-list 110 extended permit udp host 128.107.81.145 host 10.35.16.43 eq syslog 
access-list 110 extended permit udp host 128.107.241.119 host 10.35.16.43 eq syslog 
access-list 110 extended permit udp host 128.107.233.36 host 10.35.16.43 eq syslog 
access-list 110 extended permit udp host 128.107.81.144 host 10.35.22.18 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.81.145 host 10.35.22.18 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.241.119 host 10.35.22.18 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.233.36 host 10.35.22.18 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.81.144 host 10.35.22.31 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.81.145 host 10.35.22.31 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.241.119 host 10.35.22.31 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.233.36 host 10.35.22.31 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.81.144 host 171.70.93.61 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.81.145 host 171.70.93.61 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.241.119 host 171.70.93.61 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.233.36 host 171.70.93.61 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.81.144 host 10.35.48.76 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.81.145 host 10.35.48.76 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.241.119 host 10.35.48.76 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.233.36 host 10.35.48.76 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.81.144 host 10.35.48.77 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.81.145 host 10.35.48.77 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.241.119 host 10.35.48.77 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.233.36 host 10.35.48.77 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.81.144 host 10.35.48.78 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.81.145 host 10.35.48.78 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.241.119 host 10.35.48.78 range snmp snmptrap 
access-list 110 extended permit udp host 128.107.233.36 host 10.35.48.78 range snmp snmptrap 
access-list 110 extended permit tcp host 72.163.218.194 host 72.163.128.140 eq domain 
access-list 110 extended permit tcp host 72.163.218.194 host 64.104.123.245 eq domain 
access-list 110 extended permit tcp host 72.163.218.194 host 64.104.76.247 eq domain 
access-list 110 extended permit udp host 72.163.218.194 host 10.35.16.42 eq syslog 
access-list 110 extended permit udp host 72.163.218.194 host 171.68.226.122 eq syslog 
access-list 110 extended permit udp host 72.163.218.194 host 171.70.168.186 eq syslog 
access-list 110 extended permit udp host 72.163.218.194 host 171.70.139.31 eq syslog 
access-list 110 extended permit udp host 72.163.218.194 host 171.70.168.240 eq syslog 
access-list 110 extended permit udp host 72.163.218.194 host 172.25.126.55 eq syslog 
access-list 110 extended permit udp host 72.163.218.194 host 172.25.126.53 eq syslog 
access-list 110 extended permit udp host 72.163.218.194 host 72.163.192.34 eq syslog 
access-list 110 extended permit udp host 72.163.218.194 host 64.104.14.186 eq snmptrap 
access-list 110 extended permit udp host 72.163.218.194 host 171.68.226.122 eq snmptrap 
access-list 110 extended permit udp host 72.163.218.194 host 171.70.168.186 eq snmptrap 
access-list 110 extended permit udp host 72.163.218.194 host 64.104.128.250 eq snmptrap 
access-list 110 extended permit udp host 72.163.218.194 host 72.163.128.157 eq snmptrap 
access-list 110 extended permit udp host 72.163.218.194 host 10.35.22.18 eq snmptrap 
access-list 110 extended permit udp host 72.163.218.194 host 10.35.22.31 eq snmptrap 
access-list 110 extended permit udp host 72.163.218.194 host 10.35.48.76 eq snmptrap 
access-list 110 extended permit udp host 72.163.218.194 host 10.35.48.77 eq snmptrap 
access-list 110 extended permit udp host 72.163.218.194 host 10.35.48.78 eq snmptrap 
access-list 110 extended permit udp host 72.163.218.194 host 10.104.80.12 eq snmptrap 
access-list 110 extended permit udp host 72.163.218.194 host 10.76.101.203 eq 2776 
access-list 110 extended permit udp host 72.163.218.194 host 10.76.101.203 eq 2777 
access-list 110 extended permit tcp host 72.163.218.194 host 10.76.101.203 eq 7001 
access-list 110 extended permit udp any host 198.135.0.196 eq isakmp 
access-list 110 extended permit esp any host 198.135.0.196 
access-list 110 extended permit udp any host 198.135.0.196 eq 4500 
access-list 110 extended permit udp any host 198.135.0.196 eq 10000 
access-list 110 extended permit tcp any host 198.135.0.196 eq 10000 
access-list 110 extended permit udp any host 198.135.0.196 eq 443 
access-list 110 extended permit tcp any host 198.135.0.196 eq https 
access-list 110 extended permit tcp any object-group AnyConnect-Provision-ASAs-SJ eq https 
access-list 110 extended permit tcp any object-group AnyConnect-Provision-ASAs-SJ eq www 
access-list 110 extended permit tcp any host 198.135.0.165 eq https 
access-list 110 extended permit tcp any host 198.135.0.166 eq https 
access-list 110 extended permit tcp any host 198.135.0.167 eq https 
access-list 110 extended permit tcp any host 198.135.0.168 eq https 
access-list 110 extended permit esp 4.53.16.224 255.255.255.252 host 64.102.252.253 
access-list 110 extended permit udp 4.53.16.224 255.255.255.252 host 64.102.252.253 eq isakmp 
access-list 110 extended permit esp 4.79.204.224 255.255.255.252 host 64.102.252.253 
access-list 110 extended permit udp 4.79.204.224 255.255.255.252 host 64.102.252.253 eq isakmp 
access-list 110 extended permit esp 4.71.160.52 255.255.255.252 host 64.102.252.253 
access-list 110 extended permit udp 4.71.160.52 255.255.255.252 host 64.102.252.253 eq isakmp 
access-list 110 extended permit esp 4.71.24.88 255.255.255.252 host 64.102.252.253 
access-list 110 extended permit udp 4.71.24.88 255.255.255.252 host 64.102.252.253 eq isakmp 
access-list 110 extended permit esp 4.59.196.36 255.255.255.252 host 64.102.252.253 
access-list 110 extended permit udp 4.59.196.36 255.255.255.252 host 64.102.252.253 eq isakmp 
access-list 110 extended permit esp 4.71.120.184 255.255.255.252 host 64.102.252.253 
access-list 110 extended permit udp 4.71.120.184 255.255.255.252 host 64.102.252.253 eq isakmp 
access-list 110 extended permit esp 94.103.18.124 255.255.255.252 host 64.102.252.253 
access-list 110 extended permit udp 94.103.18.124 255.255.255.252 host 64.102.252.253 eq isakmp 
access-list 110 extended permit esp 94.103.18.124 255.255.255.252 host 171.71.238.13 
access-list 110 extended permit udp 94.103.18.124 255.255.255.252 host 171.71.238.13 eq isakmp 
access-list 110 extended permit udp host 170.65.129.7 host 161.44.249.84 eq isakmp 
access-list 110 extended permit esp host 170.65.129.7 host 161.44.249.84 
access-list 110 extended permit udp host 170.65.129.7 host 161.44.249.84 eq 4500 
access-list 110 extended permit udp host 170.65.129.7 host 161.44.249.84 eq 10000 
access-list 110 extended permit ah host 170.65.129.7 host 161.44.249.84 
access-list 110 extended permit udp any host 64.102.222.6 eq 4500 
access-list 110 extended permit esp host 64.102.244.53 host 64.102.244.54 
access-list 110 extended permit udp host 64.102.244.53 host 64.102.244.54 eq isakmp 
access-list 110 extended permit udp host 209.47.111.250 host 64.102.253.90 eq 4500 
access-list 110 extended permit esp host 209.47.111.250 host 64.102.253.90 
access-list 110 extended permit udp host 209.47.111.250 host 64.102.253.90 eq isakmp 
access-list 110 extended permit udp host 209.47.111.250 host 64.102.253.94 eq 4500 
access-list 110 extended permit esp host 209.47.111.250 host 64.102.253.94 
access-list 110 extended permit udp host 209.47.111.250 host 64.102.253.94 eq isakmp 
access-list 110 extended permit tcp host 172.18.136.164 host 64.102.254.154 eq sip 
access-list 110 extended permit udp host 172.18.136.164 host 64.102.254.154 range 16384 65535 
access-list 110 extended permit udp host 64.102.249.41 host 64.103.59.23 eq 6011 
access-list 110 extended permit udp host 64.102.249.42 host 64.103.59.23 eq 6011 
access-list 110 extended permit udp host 64.102.249.41 host 64.103.59.24 eq 6011 
access-list 110 extended permit udp host 64.102.249.42 host 64.103.59.24 eq 6011 
access-list 110 extended permit tcp host 64.102.249.41 host 64.103.59.23 eq 7011 
access-list 110 extended permit tcp host 64.102.249.42 host 64.103.59.23 eq 7011 
access-list 110 extended permit tcp host 64.102.249.41 host 64.103.59.24 eq 7011 
access-list 110 extended permit tcp host 64.102.249.42 host 64.103.59.24 eq 7011 
access-list 110 extended permit udp host 64.102.249.41 host 64.103.59.23 eq 2776 
access-list 110 extended permit udp host 64.102.249.42 host 64.103.59.23 eq 2776 
access-list 110 extended permit udp host 64.102.249.41 host 64.103.59.24 eq 2776 
access-list 110 extended permit udp host 64.102.249.42 host 64.103.59.24 eq 2776 
access-list 110 extended permit udp host 64.102.249.41 host 64.103.59.23 eq 2777 
access-list 110 extended permit udp host 64.102.249.42 host 64.103.59.23 eq 2777 
access-list 110 extended permit udp host 64.102.249.41 host 64.103.59.24 eq 2777 
access-list 110 extended permit udp host 64.102.249.42 host 64.103.59.24 eq 2777 
access-list 110 extended permit tcp host 66.163.36.133 host 64.102.223.41 eq 5222 
access-list 110 extended permit tcp host 209.197.204.84 host 64.102.223.41 eq 5222 
access-list 110 extended permit tcp host 66.163.36.123 host 64.102.223.41 eq 5222 
access-list 110 extended permit tcp host 209.197.204.74 host 64.102.223.41 eq 5222 
access-list 110 extended permit tcp host 66.163.36.133 host 64.102.223.41 eq 5269 
access-list 110 extended permit tcp host 209.197.204.84 host 64.102.223.41 eq 5269 
access-list 110 extended permit tcp host 66.163.36.123 host 64.102.223.41 eq 5269 
access-list 110 extended permit tcp host 209.197.204.74 host 64.102.223.41 eq 5269 
access-list 110 extended permit udp host 64.102.244.101 host 172.18.106.169 eq 902 
access-list 110 extended permit udp host 64.102.244.101 eq 902 host 172.18.106.169 
access-list 110 extended permit tcp host 64.102.244.101 host 172.18.107.247 eq www 
access-list 110 extended permit tcp host 64.102.244.101 host 172.18.107.247 eq https 
access-list 110 extended permit tcp host 64.102.244.101 host 172.18.107.247 eq 9084 
access-list 110 extended permit udp 10.105.26.0 255.255.255.0 host 10.61.118.156 eq 902 
access-list 110 extended permit tcp 10.105.26.0 255.255.255.0 host 10.61.118.156 eq www 
access-list 110 extended permit tcp 10.105.26.0 255.255.255.0 host 10.61.118.156 eq https 
access-list 110 extended permit tcp 10.105.26.0 255.255.255.0 host 10.61.118.156 range 9000 9100 
access-list 110 extended permit tcp host 66.163.36.133 host 128.107.200.123 eq 5222 
access-list 110 extended permit tcp host 209.197.204.84 host 128.107.200.123 eq 5222 
access-list 110 extended permit tcp host 66.163.36.123 host 128.107.200.123 eq 5222 
access-list 110 extended permit tcp host 209.197.204.74 host 128.107.200.123 eq 5222 
access-list 110 extended permit tcp host 66.163.36.133 host 128.107.200.123 eq 5269 
access-list 110 extended permit tcp host 209.197.204.84 host 128.107.200.123 eq 5269 
access-list 110 extended permit tcp host 66.163.36.123 host 128.107.200.123 eq 5269 
access-list 110 extended permit tcp host 209.197.204.74 host 128.107.200.123 eq 5269 
access-list 110 extended permit tcp host 64.102.244.136 host 64.102.24.232 eq sip 
access-list 110 extended permit tcp host 64.102.244.136 host 64.102.24.221 eq sip 
access-list 110 extended permit tcp host 64.102.244.136 host 64.102.2.31 eq sip 
access-list 110 extended permit tcp host 64.102.244.136 host 64.102.2.22 eq sip 
access-list 110 extended permit tcp host 64.102.244.136 host 64.102.122.103 eq sip 
access-list 110 extended permit tcp host 64.102.244.136 host 64.102.122.102 eq sip 
access-list 110 extended permit tcp host 64.102.244.136 host 64.100.36.167 eq sip 
access-list 110 extended permit tcp host 64.102.244.136 host 64.100.36.166 eq sip 
access-list 110 extended permit tcp host 64.102.244.136 host 64.100.24.204 eq sip 
access-list 110 extended permit tcp host 64.102.244.136 host 64.100.24.203 eq sip 
access-list 110 extended permit tcp host 64.102.244.136 host 64.100.145.251 eq sip 
access-list 110 extended permit tcp host 64.102.244.136 host 64.100.145.250 eq sip 
access-list 110 extended permit tcp host 64.102.244.137 host 64.102.24.232 eq sip 
access-list 110 extended permit tcp host 64.102.244.137 host 64.102.24.221 eq sip 
access-list 110 extended permit tcp host 64.102.244.137 host 64.102.2.31 eq sip 
access-list 110 extended permit tcp host 64.102.244.137 host 64.102.2.22 eq sip 
access-list 110 extended permit tcp host 64.102.244.137 host 64.102.122.103 eq sip 
access-list 110 extended permit tcp host 64.102.244.137 host 64.102.122.102 eq sip 
access-list 110 extended permit tcp host 64.102.244.137 host 64.100.36.167 eq sip 
access-list 110 extended permit tcp host 64.102.244.137 host 64.100.36.166 eq sip 
access-list 110 extended permit tcp host 64.102.244.137 host 64.100.24.204 eq sip 
access-list 110 extended permit tcp host 64.102.244.137 host 64.100.24.203 eq sip 
access-list 110 extended permit tcp host 64.102.244.137 host 64.100.145.251 eq sip 
access-list 110 extended permit tcp host 64.102.244.137 host 64.100.145.250 eq sip 
access-list 110 extended permit gre host 64.102.254.10 host 10.91.120.62 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.186.145 
access-list 110 extended permit esp host 64.104.44.33 host 10.71.150.62 
access-list 110 extended permit ah host 64.104.44.33 host 10.71.150.62 
access-list 110 extended permit udp host 64.104.44.33 host 10.71.150.62 eq isakmp 
access-list 110 extended permit gre host 64.102.240.233 host 10.66.139.124 
access-list 110 extended permit gre host 64.102.240.234 host 10.66.139.124 
access-list 110 extended permit udp 64.100.0.0 255.255.248.0 any eq isakmp 
access-list 110 extended permit esp 64.100.0.0 255.255.248.0 any 
access-list 110 extended permit udp host 186.73.112.194 host 64.100.172.1 eq isakmp 
access-list 110 extended permit udp host 186.73.112.194 host 64.100.172.1 eq 4500 
access-list 110 extended permit esp host 186.73.112.194 host 64.100.172.1 
access-list 110 extended permit udp host 186.73.112.195 host 64.100.172.13 eq isakmp 
access-list 110 extended permit udp host 186.73.112.195 host 64.100.172.13 eq 4500 
access-list 110 extended permit esp host 186.73.112.195 host 64.100.172.13 
access-list 110 extended permit gre host 172.17.153.20 host 10.101.14.16 
access-list 110 extended permit gre host 172.17.153.20 host 10.101.14.17 
access-list 110 extended permit gre host 10.101.14.16 host 172.17.153.20 
access-list 110 extended permit gre host 10.101.14.17 host 172.17.153.20 
access-list 110 extended permit gre host 172.17.153.65 host 10.101.14.16 
access-list 110 extended permit gre host 172.17.153.65 host 10.101.14.17 
access-list 110 extended permit gre host 10.101.14.16 host 172.17.153.65 
access-list 110 extended permit gre host 10.101.14.17 host 172.17.153.65 
access-list 110 extended permit gre host 172.17.153.20 host 10.86.234.13 
access-list 110 extended permit gre host 128.107.239.78 host 10.86.234.13 
access-list 110 extended permit gre host 10.59.15.229 host 172.17.153.20 
access-list 110 extended permit gre host 172.17.153.20 host 10.59.15.229 
access-list 110 extended permit gre host 128.107.240.24 host 10.75.225.201 
access-list 110 extended permit gre host 10.75.225.201 host 128.107.240.24 
access-list 110 extended permit gre host 172.17.153.20 host 10.75.11.176 
access-list 110 extended permit gre host 172.17.153.65 host 10.75.11.176 
access-list 110 extended permit gre host 10.75.11.176 host 172.17.153.20 
access-list 110 extended permit gre host 10.75.11.176 host 172.17.153.65 
access-list 110 extended permit eigrp 173.39.120.160 255.255.255.240 173.39.120.160 255.255.255.240 
access-list 110 extended permit eigrp 173.39.120.160 255.255.255.240 host 224.0.0.10 
access-list 110 extended permit pim 173.39.120.160 255.255.255.240 173.39.120.160 255.255.255.240 
access-list 110 extended permit pim 173.39.120.160 255.255.255.240 host 224.0.0.13 
access-list 110 extended permit gre host 10.68.12.143 host 128.107.240.24 
access-list 110 extended permit gre host 10.68.12.146 host 128.107.240.170 
access-list 110 extended permit gre host 128.107.240.24 host 10.68.12.143 
access-list 110 extended permit gre host 128.107.240.170 host 10.68.12.146 
access-list 110 extended permit udp host 10.68.12.135 host 171.71.180.202 range 2055 2065 
access-list 110 extended permit udp host 10.68.12.136 host 171.71.180.202 range 2055 2065 
access-list 110 extended permit udp host 64.104.94.84 host 10.68.12.139 eq snmp 
access-list 110 extended permit udp host 64.104.94.84 host 10.68.12.140 eq snmp 
access-list 110 extended permit gre host 173.39.120.60 any 
access-list 110 extended permit gre host 173.39.120.61 any 
access-list 110 extended permit tcp any host 72.163.248.242 eq https 
access-list 110 extended permit tcp any host 72.163.248.242 eq 8000 
access-list 110 extended permit tcp any host 72.163.248.243 eq https 
access-list 110 extended permit tcp any host 72.163.248.243 eq 8000 
access-list 110 extended permit gre host 10.86.234.13 host 172.17.153.20 
access-list 110 extended permit gre host 10.86.234.13 host 128.107.239.78 
access-list 110 extended permit tcp host 128.107.81.140 host 10.32.134.142 eq 5443 
access-list 110 extended permit tcp host 128.107.81.140 host 10.32.134.142 eq 5444 
access-list 110 extended permit tcp host 128.107.81.140 host 10.32.134.142 eq 5445 
access-list 110 extended permit tcp host 128.107.81.140 host 10.32.134.143 eq 5443 
access-list 110 extended permit tcp host 128.107.81.140 host 10.32.134.143 eq 5444 
access-list 110 extended permit tcp host 128.107.81.140 host 10.32.134.143 eq 5445 
access-list 110 extended permit tcp host 64.103.26.19 host 10.53.44.104 eq 5443 
access-list 110 extended permit tcp host 64.103.26.19 host 10.53.44.104 eq 6532 
access-list 110 extended permit tcp host 64.103.26.20 host 10.53.44.109 eq 5443 
access-list 110 extended permit tcp host 64.103.26.20 host 10.53.44.109 eq 6532 
access-list 110 extended permit tcp host 64.103.26.20 host 10.53.44.109 eq 7080 
access-list 110 extended permit tcp host 64.103.26.20 host 10.53.44.109 eq 8080 
access-list 110 extended permit tcp any host 144.254.73.146 eq ssh 
access-list 110 extended permit tcp host 128.107.85.171 host 171.70.121.11 eq sip 
access-list 110 extended permit tcp host 128.107.85.171 host 171.70.121.12 eq sip 
access-list 110 extended permit tcp host 128.107.85.171 host 171.70.121.13 eq sip 
access-list 110 extended permit tcp host 128.107.85.171 host 171.70.121.14 eq sip 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.1.15 eq sip 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.1.16 eq sip 
access-list 110 extended permit tcp host 128.107.85.171 host 171.70.121.11 eq 5061 
access-list 110 extended permit tcp host 128.107.85.171 host 171.70.121.12 eq 5061 
access-list 110 extended permit tcp host 128.107.85.171 host 171.70.121.13 eq 5061 
access-list 110 extended permit tcp host 128.107.85.171 host 171.70.121.14 eq 5061 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.1.15 eq 5061 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.1.16 eq 5061 
access-list 110 extended permit tcp host 128.107.85.170 host 171.70.121.11 eq 8060 
access-list 110 extended permit tcp host 128.107.85.170 host 171.70.121.12 eq 8060 
access-list 110 extended permit tcp host 128.107.85.170 host 171.70.121.13 eq 8060 
access-list 110 extended permit tcp host 128.107.85.170 host 171.70.121.14 eq 8060 
access-list 110 extended permit tcp host 128.107.85.170 host 10.35.1.15 eq 8060 
access-list 110 extended permit tcp host 128.107.85.170 host 10.35.1.16 eq 8060 
access-list 110 extended permit tcp host 128.107.85.171 host 171.70.121.11 eq 8060 
access-list 110 extended permit tcp host 128.107.85.171 host 171.70.121.12 eq 8060 
access-list 110 extended permit tcp host 128.107.85.171 host 171.70.121.13 eq 8060 
access-list 110 extended permit tcp host 128.107.85.171 host 171.70.121.14 eq 8060 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.1.15 eq 8060 
access-list 110 extended permit tcp host 128.107.85.171 host 10.35.1.16 eq 8060 
access-list 110 extended permit tcp host 128.107.85.140 host 171.70.121.11 eq 5620 
access-list 110 extended permit tcp host 128.107.85.140 host 171.70.121.12 eq 5620 
access-list 110 extended permit tcp host 128.107.85.140 host 171.70.121.13 eq 5620 
access-list 110 extended permit tcp host 128.107.85.140 host 171.70.121.14 eq 5620 
access-list 110 extended permit tcp host 128.107.85.140 host 10.35.1.15 eq 5620 
access-list 110 extended permit tcp host 128.107.85.140 host 10.35.1.16 eq 5620 
access-list 110 extended permit tcp host 128.107.85.141 host 171.70.121.11 eq 5620 
access-list 110 extended permit tcp host 128.107.85.141 host 171.70.121.12 eq 5620 
access-list 110 extended permit tcp host 128.107.85.141 host 171.70.121.13 eq 5620 
access-list 110 extended permit tcp host 128.107.85.141 host 171.70.121.14 eq 5620 
access-list 110 extended permit tcp host 128.107.85.141 host 10.35.1.15 eq 5620 
access-list 110 extended permit tcp host 128.107.85.141 host 10.35.1.16 eq 5620 
access-list 110 extended permit tcp host 64.103.39.114 host 171.70.121.11 eq 5061 
access-list 110 extended permit tcp host 64.103.39.114 host 171.70.121.12 eq 5061 
access-list 110 extended permit tcp host 64.103.39.114 host 171.70.121.13 eq 5061 
access-list 110 extended permit tcp host 64.103.39.114 host 171.70.121.14 eq 5061 
access-list 110 extended permit tcp host 64.103.39.113 host 144.254.208.111 eq 8060 
access-list 110 extended permit tcp host 64.103.39.113 host 144.254.208.112 eq 8060 
access-list 110 extended permit tcp host 64.103.39.113 host 144.254.208.113 eq 8060 
access-list 110 extended permit tcp host 64.103.39.113 host 144.254.208.114 eq 8060 
access-list 110 extended permit tcp host 64.103.39.114 host 144.254.208.111 eq 8060 
access-list 110 extended permit tcp host 64.103.39.114 host 144.254.208.112 eq 8060 
access-list 110 extended permit tcp host 64.103.39.114 host 144.254.208.113 eq 8060 
access-list 110 extended permit tcp host 64.103.39.114 host 144.254.208.114 eq 8060 
access-list 110 extended permit tcp host 64.103.39.119 host 144.254.208.111 eq 5620 
access-list 110 extended permit tcp host 64.103.39.119 host 144.254.208.112 eq 5620 
access-list 110 extended permit tcp host 64.103.39.119 host 144.254.208.113 eq 5620 
access-list 110 extended permit tcp host 64.103.39.119 host 144.254.208.114 eq 5620 
access-list 110 extended permit tcp host 64.103.39.120 host 144.254.208.111 eq 5620 
access-list 110 extended permit tcp host 64.103.39.120 host 144.254.208.112 eq 5620 
access-list 110 extended permit tcp host 64.103.39.120 host 144.254.208.113 eq 5620 
access-list 110 extended permit tcp host 64.103.39.120 host 144.254.208.114 eq 5620 
access-list 110 extended permit tcp host 64.104.94.37 host 10.68.3.51 eq sip 
access-list 110 extended permit tcp host 64.104.94.37 host 10.68.3.53 eq sip 
access-list 110 extended permit tcp host 64.104.94.37 host 10.68.3.55 eq sip 
access-list 110 extended permit tcp host 64.104.94.37 host 10.68.3.57 eq sip 
access-list 110 extended permit tcp host 64.104.94.37 host 10.68.3.51 eq 5061 
access-list 110 extended permit tcp host 64.104.94.37 host 10.68.3.53 eq 5061 
access-list 110 extended permit tcp host 64.104.94.37 host 10.68.3.55 eq 5061 
access-list 110 extended permit tcp host 64.104.94.37 host 10.68.3.57 eq 5061 
access-list 110 extended permit tcp host 64.104.94.36 host 10.68.3.51 eq 8060 
access-list 110 extended permit tcp host 64.104.94.36 host 10.68.3.53 eq 8060 
access-list 110 extended permit tcp host 64.104.94.36 host 10.68.3.55 eq 8060 
access-list 110 extended permit tcp host 64.104.94.36 host 10.68.3.57 eq 8060 
access-list 110 extended permit tcp host 64.104.94.37 host 10.68.3.51 eq 8060 
access-list 110 extended permit tcp host 64.104.94.37 host 10.68.3.53 eq 8060 
access-list 110 extended permit tcp host 64.104.94.37 host 10.68.3.55 eq 8060 
access-list 110 extended permit tcp host 64.104.94.37 host 10.68.3.57 eq 8060 
access-list 110 extended permit tcp host 64.104.94.57 host 10.68.3.51 eq 5620 
access-list 110 extended permit tcp host 64.104.94.57 host 10.68.3.53 eq 5620 
access-list 110 extended permit tcp host 64.104.94.57 host 10.68.3.55 eq 5620 
access-list 110 extended permit tcp host 64.104.94.57 host 10.68.3.57 eq 5620 
access-list 110 extended permit tcp host 64.104.94.59 host 10.68.3.51 eq 5620 
access-list 110 extended permit tcp host 64.104.94.59 host 10.68.3.53 eq 5620 
access-list 110 extended permit tcp host 64.104.94.59 host 10.68.3.55 eq 5620 
access-list 110 extended permit tcp host 64.104.94.59 host 10.68.3.57 eq 5620 
access-list 110 extended permit tcp host 64.103.26.141 host 144.254.208.111 eq 8060 
access-list 110 extended permit tcp host 64.103.26.141 host 144.254.208.112 eq 8060 
access-list 110 extended permit tcp host 64.103.26.141 host 144.254.208.113 eq 8060 
access-list 110 extended permit tcp host 64.103.26.141 host 144.254.208.114 eq 8060 
access-list 110 extended permit tcp host 64.103.26.142 host 144.254.208.111 eq 8060 
access-list 110 extended permit tcp host 64.103.26.142 host 144.254.208.112 eq 8060 
access-list 110 extended permit tcp host 64.103.26.142 host 144.254.208.113 eq 8060 
access-list 110 extended permit tcp host 64.103.26.142 host 144.254.208.114 eq 8060 
access-list 110 extended permit tcp host 128.107.85.146 host 171.70.121.11 eq 5620 
access-list 110 extended permit tcp host 128.107.85.146 host 171.70.121.12 eq 5620 
access-list 110 extended permit tcp host 128.107.85.146 host 171.70.121.13 eq 5620 
access-list 110 extended permit tcp host 128.107.85.146 host 171.70.121.14 eq 5620 
access-list 110 extended permit tcp host 128.107.85.146 host 10.35.1.15 eq 5620 
access-list 110 extended permit tcp host 128.107.85.146 host 10.35.1.16 eq 5620 
access-list 110 extended permit tcp host 128.107.85.147 host 171.70.121.11 eq 5620 
access-list 110 extended permit tcp host 128.107.85.147 host 171.70.121.12 eq 5620 
access-list 110 extended permit tcp host 128.107.85.147 host 171.70.121.13 eq 5620 
access-list 110 extended permit tcp host 128.107.85.147 host 171.70.121.14 eq 5620 
access-list 110 extended permit tcp host 128.107.85.147 host 10.35.1.15 eq 5620 
access-list 110 extended permit tcp host 128.107.85.147 host 10.35.1.16 eq 5620 
access-list 110 extended permit tcp host 128.107.85.149 host 171.70.121.11 eq 5620 
access-list 110 extended permit tcp host 128.107.85.149 host 171.70.121.12 eq 5620 
access-list 110 extended permit tcp host 128.107.85.149 host 171.70.121.13 eq 5620 
access-list 110 extended permit tcp host 128.107.85.149 host 171.70.121.14 eq 5620 
access-list 110 extended permit tcp host 128.107.85.149 host 10.35.1.15 eq 5620 
access-list 110 extended permit tcp host 128.107.85.149 host 10.35.1.16 eq 5620 
access-list 110 extended permit tcp host 128.107.85.150 host 171.70.121.11 eq 5620 
access-list 110 extended permit tcp host 128.107.85.150 host 171.70.121.12 eq 5620 
access-list 110 extended permit tcp host 128.107.85.150 host 171.70.121.13 eq 5620 
access-list 110 extended permit tcp host 128.107.85.150 host 171.70.121.14 eq 5620 
access-list 110 extended permit tcp host 128.107.85.150 host 10.35.1.15 eq 5620 
access-list 110 extended permit tcp host 128.107.85.150 host 10.35.1.16 eq 5620 
access-list 110 extended permit tcp host 64.103.39.114 host 144.254.208.111 eq sip 
access-list 110 extended permit tcp host 64.103.39.114 host 144.254.208.112 eq sip 
access-list 110 extended permit tcp host 64.103.39.114 host 144.254.208.113 eq sip 
access-list 110 extended permit tcp host 64.103.39.114 host 144.254.208.114 eq sip 
access-list 110 extended permit tcp host 64.103.39.114 host 144.254.208.111 eq 5061 
access-list 110 extended permit tcp host 64.103.39.114 host 144.254.208.112 eq 5061 
access-list 110 extended permit tcp host 64.103.39.114 host 144.254.208.113 eq 5061 
access-list 110 extended permit tcp host 64.103.39.114 host 144.254.208.114 eq 5061 
access-list 110 extended permit tcp host 64.103.26.20 host 10.53.49.4 eq 5443 
access-list 110 extended permit tcp host 64.103.26.20 host 10.53.49.4 eq 6532 
access-list 110 extended permit tcp host 64.103.26.21 host 10.53.44.103 eq 5443 
access-list 110 extended permit tcp host 64.103.26.21 host 10.53.44.103 eq 6532 
access-list 110 extended permit tcp host 64.103.26.22 host 10.53.44.93 eq 5443 
access-list 110 extended permit tcp host 64.103.26.22 host 10.53.44.93 eq 6532 
access-list 110 extended permit tcp host 64.103.26.23 host 10.53.192.68 eq 5443 
access-list 110 extended permit tcp host 64.103.26.23 host 10.53.192.68 eq 6532 
access-list 110 extended permit tcp host 64.103.36.6 host 144.254.210.37 eq 5443 
access-list 110 extended permit tcp host 64.103.36.6 host 144.254.210.37 eq 9080 
access-list 110 extended permit tcp host 64.103.36.10 host 144.254.210.37 eq 5443 
access-list 110 extended permit tcp host 64.103.36.10 host 144.254.210.37 eq 9080 
access-list 110 extended permit tcp host 128.107.81.196 host 10.32.134.143 eq 5443 
access-list 110 extended permit tcp host 128.107.81.196 host 10.32.134.143 eq 9080 
access-list 110 extended permit tcp host 128.107.81.197 host 10.32.134.142 eq 5443 
access-list 110 extended permit tcp host 128.107.81.197 host 10.32.134.142 eq 9080 
access-list 110 extended permit tcp host 128.107.81.133 host 10.32.134.108 eq 2000 
access-list 110 extended permit tcp host 128.107.81.133 host 10.32.134.108 eq 2443 
access-list 110 extended permit tcp host 128.107.81.133 host 10.32.134.108 eq sip 
access-list 110 extended permit tcp host 128.107.81.133 host 10.32.134.108 eq 5061 
access-list 110 extended permit tcp host 128.107.81.137 host 10.32.134.100 eq 3804 
access-list 110 extended permit udp host 128.107.81.138 host 10.32.157.160 eq 3804 
access-list 110 extended permit tcp host 128.107.81.135 host 10.32.157.161 eq 2000 
access-list 110 extended permit tcp host 128.107.81.135 host 10.32.157.161 eq 2443 
access-list 110 extended permit tcp host 128.107.81.135 host 10.32.157.161 eq sip 
access-list 110 extended permit tcp host 128.107.81.135 host 10.32.157.161 eq 5061 
access-list 110 extended permit udp host 128.107.81.137 host 10.32.134.100 eq tftp 
access-list 110 extended permit udp host 128.107.81.138 host 10.32.157.160 eq tftp 
access-list 110 extended permit esp any host 64.102.253.74 
access-list 110 extended permit udp any host 64.102.253.74 eq isakmp 
access-list 110 extended permit udp any host 64.102.253.74 eq 4500 
access-list 110 extended permit tcp host 128.107.81.138 host 10.32.134.160 eq 3804 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 72.163.33.109 eq 15100 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 72.163.33.80 eq 15100 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 72.163.33.81 eq 15100 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 72.163.33.109 eq 15200 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 72.163.33.80 eq 15200 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 72.163.33.81 eq 15200 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 72.163.33.109 eq 15480 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 72.163.33.80 eq 15480 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 72.163.33.81 eq 15480 
access-list 110 extended permit tcp any host 64.103.27.171 eq ssh 
access-list 110 extended permit tcp host 64.103.39.114 host 171.70.121.11 eq sip 
access-list 110 extended permit tcp host 64.103.39.114 host 171.70.121.12 eq sip 
access-list 110 extended permit tcp host 64.103.39.114 host 171.70.121.13 eq sip 
access-list 110 extended permit tcp host 64.103.39.114 host 171.70.121.14 eq sip 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.131 eq sip 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.132 eq sip 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.133 eq sip 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.134 eq sip 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.135 eq sip 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.136 eq sip 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.131 eq 5061 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.132 eq 5061 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.133 eq 5061 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.134 eq 5061 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.135 eq 5061 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.136 eq 5061 
access-list 110 extended permit tcp host 128.107.85.177 host 10.35.48.131 eq 8060 
access-list 110 extended permit tcp host 128.107.85.177 host 10.35.48.132 eq 8060 
access-list 110 extended permit tcp host 128.107.85.177 host 10.35.48.133 eq 8060 
access-list 110 extended permit tcp host 128.107.85.177 host 10.35.48.134 eq 8060 
access-list 110 extended permit tcp host 128.107.85.177 host 10.35.48.135 eq 8060 
access-list 110 extended permit tcp host 128.107.85.177 host 10.35.48.136 eq 8060 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.131 eq 8060 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.132 eq 8060 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.133 eq 8060 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.134 eq 8060 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.135 eq 8060 
access-list 110 extended permit tcp host 128.107.85.178 host 10.35.48.136 eq 8060 
access-list 110 extended permit tcp host 128.107.85.214 host 10.35.48.131 eq 5620 
access-list 110 extended permit tcp host 128.107.85.214 host 10.35.48.132 eq 5620 
access-list 110 extended permit tcp host 128.107.85.214 host 10.35.48.133 eq 5620 
access-list 110 extended permit tcp host 128.107.85.214 host 10.35.48.134 eq 5620 
access-list 110 extended permit tcp host 128.107.85.214 host 10.35.48.135 eq 5620 
access-list 110 extended permit tcp host 128.107.85.214 host 10.35.48.136 eq 5620 
access-list 110 extended permit tcp host 128.107.85.215 host 10.35.48.131 eq 5620 
access-list 110 extended permit tcp host 128.107.85.215 host 10.35.48.132 eq 5620 
access-list 110 extended permit tcp host 128.107.85.215 host 10.35.48.133 eq 5620 
access-list 110 extended permit tcp host 128.107.85.215 host 10.35.48.134 eq 5620 
access-list 110 extended permit tcp host 128.107.85.215 host 10.35.48.135 eq 5620 
access-list 110 extended permit tcp host 128.107.85.215 host 10.35.48.136 eq 5620 
access-list 110 extended permit udp host 128.107.83.68 host 171.70.121.17 range 18000 19000 
access-list 110 extended permit udp host 128.107.83.68 host 171.70.121.62 range 18000 19000 
access-list 110 extended permit udp host 128.107.83.68 host 171.70.121.63 range 18000 19000 
access-list 110 extended permit udp host 128.107.83.68 host 171.70.121.16 range 18000 18200 
access-list 110 extended permit udp host 128.107.83.68 host 171.70.121.63 range 19000 19100 
access-list 110 extended permit udp host 128.107.83.68 host 171.70.121.17 range 19000 19100 
access-list 110 extended permit udp host 128.107.83.68 host 171.70.121.62 range 19000 19100 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.31 eq 3336 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.62 eq h323 
access-list 110 extended permit tcp host 128.107.83.68 host 171.70.121.62 range 1024 1100 
access-list 110 extended permit udp host 128.107.83.68 host 171.70.121.31 eq 1719 
access-list 110 extended permit tcp host 128.107.81.199 host 10.32.134.108 eq 2000 
access-list 110 extended permit tcp host 128.107.81.199 host 10.32.134.108 eq 2443 
access-list 110 extended permit tcp host 128.107.81.199 host 10.32.134.108 eq sip 
access-list 110 extended permit tcp host 128.107.81.199 host 10.32.134.108 eq 5061 
access-list 110 extended permit tcp host 128.107.81.198 host 10.34.130.10 eq 2000 
access-list 110 extended permit tcp host 128.107.81.198 host 10.34.130.10 eq 2443 
access-list 110 extended permit tcp host 128.107.81.198 host 10.34.130.10 eq sip 
access-list 110 extended permit tcp host 128.107.81.198 host 10.34.130.10 eq 5061 
access-list 110 extended permit tcp host 128.107.81.204 host 10.32.134.100 eq 3804 
access-list 110 extended permit udp host 128.107.81.204 host 10.32.134.100 eq tftp 
access-list 110 extended permit udp any host 171.70.192.77 eq 443 
access-list 110 extended permit udp any host 171.70.192.78 eq 443 
access-list 110 extended permit udp any host 171.70.192.79 eq 443 
access-list 110 extended permit esp any host 72.163.215.46 
access-list 110 extended permit udp any host 72.163.215.46 eq isakmp 
access-list 110 extended permit udp any host 72.163.215.46 eq 4500 
access-list 110 extended permit udp any host 144.254.221.37 eq 443 
access-list 110 extended permit udp any host 144.254.221.38 eq 443 
access-list 110 extended permit udp any host 144.254.221.39 eq 443 
access-list 110 extended permit udp any host 144.254.221.40 eq 443 
access-list 110 extended permit udp any host 144.254.221.41 eq 443 
access-list 110 extended permit udp any host 144.254.221.42 eq 443 
access-list 110 extended permit udp any host 144.254.221.45 eq 443 
access-list 110 extended permit udp any host 144.254.221.46 eq 443 
access-list 110 extended permit tcp host 128.107.246.231 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.231 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.228 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.228 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.229 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.229 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.230 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.230 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.233 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.233 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.234 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.234 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.235 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.235 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.236 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.236 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.237 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.237 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.238 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.238 host 171.68.155.30 eq www 
access-list 110 extended permit udp any host 128.107.200.99 eq 8000 
access-list 110 extended permit udp any host 128.107.200.99 eq 443 
access-list 110 extended deny ip any host 128.107.201.231 
access-list 110 extended permit tcp any 128.107.201.228 255.255.255.252 eq https 
access-list 110 extended permit udp any 128.107.201.228 255.255.255.252 eq 443 
access-list 110 extended permit tcp any host 128.107.201.217 eq https 
access-list 110 extended permit udp any host 128.107.201.217 eq 443 
access-list 110 extended permit esp any 128.107.201.218 255.255.255.254 
access-list 110 extended permit tcp any 128.107.201.218 255.255.255.254 eq 10000 
access-list 110 extended permit udp any 128.107.201.218 255.255.255.254 eq 10000 
access-list 110 extended permit udp any 128.107.201.218 255.255.255.254 eq isakmp 
access-list 110 extended permit udp any 128.107.201.218 255.255.255.254 eq 4500 
access-list 110 extended permit tcp any host 128.107.201.199 eq https 
access-list 110 extended permit udp any host 128.107.201.199 eq 443 
access-list 110 extended permit tcp any host 128.107.201.200 eq https 
access-list 110 extended permit udp any host 128.107.201.200 eq 443 
access-list 110 extended permit tcp any host 128.107.201.201 eq https 
access-list 110 extended permit udp any host 128.107.201.201 eq 443 
access-list 110 extended permit tcp host 128.107.236.38 any eq domain 
access-list 110 extended permit icmp host 128.107.236.38 any echo 
access-list 110 extended permit udp any host 72.163.57.76 eq domain 
access-list 110 extended permit gre host 128.107.235.30 10.101.0.0 255.255.128.0 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.11 
access-list 110 extended permit gre host 64.102.254.10 any 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.10 
access-list 110 extended permit gre host 72.163.216.168 host 10.76.244.3 
access-list 110 extended permit gre any host 171.69.237.149 
access-list 110 extended permit gre any host 171.69.237.150 
access-list 110 extended permit gre any host 171.69.237.152 
access-list 110 extended permit gre any host 171.69.237.153 
access-list 110 extended permit udp any host 171.69.237.149 eq isakmp 
access-list 110 extended permit udp any host 171.69.237.150 eq isakmp 
access-list 110 extended permit udp any host 171.69.237.152 eq isakmp 
access-list 110 extended permit udp any host 171.69.237.153 eq isakmp 
access-list 110 extended permit udp any host 171.69.237.149 eq 4500 
access-list 110 extended permit udp any host 171.69.237.150 eq 4500 
access-list 110 extended permit udp any host 171.69.237.152 eq 4500 
access-list 110 extended permit udp any host 171.69.237.153 eq 4500 
access-list 110 extended permit tcp host 128.107.246.70 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.71 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.72 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.73 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.74 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.75 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.76 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.77 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.78 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.79 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.80 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.70 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.71 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.72 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.73 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.74 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.75 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.76 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.77 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.78 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.79 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.80 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.70 host 172.17.45.64 eq www 
access-list 110 extended permit tcp host 128.107.246.71 host 172.17.45.64 eq www 
access-list 110 extended permit tcp host 128.107.246.72 host 172.17.45.64 eq www 
access-list 110 extended permit tcp host 128.107.246.73 host 172.17.45.64 eq www 
access-list 110 extended permit tcp host 128.107.246.70 host 172.17.45.64 eq https 
access-list 110 extended permit tcp host 128.107.246.71 host 172.17.45.64 eq https 
access-list 110 extended permit tcp host 128.107.246.72 host 172.17.45.64 eq https 
access-list 110 extended permit tcp host 128.107.246.73 host 172.17.45.64 eq https 
access-list 110 extended permit tcp host 128.107.246.70 host 171.71.181.6 eq www 
access-list 110 extended permit tcp host 128.107.246.71 host 171.71.181.6 eq www 
access-list 110 extended permit tcp host 128.107.246.72 host 171.71.181.6 eq www 
access-list 110 extended permit tcp host 128.107.246.73 host 171.71.181.6 eq www 
access-list 110 extended permit tcp host 128.107.246.70 host 171.71.181.6 eq https 
access-list 110 extended permit tcp host 128.107.246.71 host 171.71.181.6 eq https 
access-list 110 extended permit tcp host 128.107.246.72 host 171.71.181.6 eq https 
access-list 110 extended permit tcp host 128.107.246.73 host 171.71.181.6 eq https 
access-list 110 extended permit tcp host 128.107.246.70 host 171.71.181.7 eq www 
access-list 110 extended permit tcp host 128.107.246.71 host 171.71.181.7 eq www 
access-list 110 extended permit tcp host 128.107.246.72 host 171.71.181.7 eq www 
access-list 110 extended permit tcp host 128.107.246.73 host 171.71.181.7 eq www 
access-list 110 extended permit tcp host 128.107.246.70 host 171.71.181.7 eq https 
access-list 110 extended permit tcp host 128.107.246.71 host 171.71.181.7 eq https 
access-list 110 extended permit tcp host 128.107.246.72 host 171.71.181.7 eq https 
access-list 110 extended permit tcp host 128.107.246.73 host 171.71.181.7 eq https 
access-list 110 extended permit tcp host 128.107.246.70 host 171.71.181.4 eq www 
access-list 110 extended permit tcp host 128.107.246.71 host 171.71.181.4 eq www 
access-list 110 extended permit tcp host 128.107.246.72 host 171.71.181.4 eq www 
access-list 110 extended permit tcp host 128.107.246.73 host 171.71.181.4 eq www 
access-list 110 extended permit tcp host 128.107.246.70 host 171.71.181.4 eq https 
access-list 110 extended permit tcp host 128.107.246.71 host 171.71.181.4 eq https 
access-list 110 extended permit tcp host 128.107.246.72 host 171.71.181.4 eq https 
access-list 110 extended permit tcp host 128.107.246.73 host 171.71.181.4 eq https 
access-list 110 extended permit tcp host 128.107.246.70 host 171.71.181.44 eq www 
access-list 110 extended permit tcp host 128.107.246.71 host 171.71.181.44 eq www 
access-list 110 extended permit tcp host 128.107.246.72 host 171.71.181.44 eq www 
access-list 110 extended permit tcp host 128.107.246.73 host 171.71.181.44 eq www 
access-list 110 extended permit tcp host 128.107.246.70 host 171.71.181.44 eq https 
access-list 110 extended permit tcp host 128.107.246.71 host 171.71.181.44 eq https 
access-list 110 extended permit tcp host 128.107.246.72 host 171.71.181.44 eq https 
access-list 110 extended permit tcp host 128.107.246.73 host 171.71.181.44 eq https 
access-list 110 extended permit tcp host 128.107.246.70 host 172.17.45.8 eq www 
access-list 110 extended permit tcp host 128.107.246.71 host 172.17.45.8 eq www 
access-list 110 extended permit tcp host 128.107.246.72 host 172.17.45.8 eq www 
access-list 110 extended permit tcp host 128.107.246.73 host 172.17.45.8 eq www 
access-list 110 extended permit tcp host 128.107.246.70 host 172.17.45.8 eq https 
access-list 110 extended permit tcp host 128.107.246.71 host 172.17.45.8 eq https 
access-list 110 extended permit tcp host 128.107.246.72 host 172.17.45.8 eq https 
access-list 110 extended permit tcp host 128.107.246.73 host 172.17.45.8 eq https 
access-list 110 extended permit tcp host 128.107.246.70 host 172.17.45.9 eq www 
access-list 110 extended permit tcp host 128.107.246.71 host 172.17.45.9 eq www 
access-list 110 extended permit tcp host 128.107.246.72 host 172.17.45.9 eq www 
access-list 110 extended permit tcp host 128.107.246.73 host 172.17.45.9 eq www 
access-list 110 extended permit tcp host 128.107.246.70 host 172.17.45.9 eq https 
access-list 110 extended permit tcp host 128.107.246.71 host 172.17.45.9 eq https 
access-list 110 extended permit tcp host 128.107.246.72 host 172.17.45.9 eq https 
access-list 110 extended permit tcp host 128.107.246.73 host 172.17.45.9 eq https 
access-list 110 extended permit tcp host 128.107.246.70 host 172.18.100.41 eq www 
access-list 110 extended permit tcp host 128.107.246.71 host 172.18.100.41 eq www 
access-list 110 extended permit tcp host 128.107.246.72 host 172.18.100.41 eq www 
access-list 110 extended permit tcp host 128.107.246.73 host 172.18.100.41 eq www 
access-list 110 extended permit tcp host 128.107.246.70 host 172.21.113.31 eq www 
access-list 110 extended permit tcp host 128.107.246.71 host 172.21.113.31 eq www 
access-list 110 extended permit tcp host 128.107.246.72 host 172.21.113.31 eq www 
access-list 110 extended permit tcp host 128.107.246.73 host 172.21.113.31 eq www 
access-list 110 extended permit tcp host 128.107.246.70 host 172.21.113.25 eq www 
access-list 110 extended permit tcp host 128.107.246.71 host 172.21.113.25 eq www 
access-list 110 extended permit tcp host 128.107.246.72 host 172.21.113.25 eq www 
access-list 110 extended permit tcp host 128.107.246.73 host 172.21.113.25 eq www 
access-list 110 extended permit tcp host 128.107.246.70 host 172.18.100.41 eq https 
access-list 110 extended permit tcp host 128.107.246.71 host 172.18.100.41 eq https 
access-list 110 extended permit tcp host 128.107.246.72 host 172.18.100.41 eq https 
access-list 110 extended permit tcp host 128.107.246.73 host 172.18.100.41 eq https 
access-list 110 extended permit tcp host 128.107.246.70 host 172.21.113.31 eq https 
access-list 110 extended permit tcp host 128.107.246.71 host 172.21.113.31 eq https 
access-list 110 extended permit tcp host 128.107.246.72 host 172.21.113.31 eq https 
access-list 110 extended permit tcp host 128.107.246.73 host 172.21.113.31 eq https 
access-list 110 extended permit tcp host 128.107.246.70 host 172.21.113.25 eq https 
access-list 110 extended permit tcp host 128.107.246.71 host 172.21.113.25 eq https 
access-list 110 extended permit tcp host 128.107.246.72 host 172.21.113.25 eq https 
access-list 110 extended permit tcp host 128.107.246.73 host 172.21.113.25 eq https 
access-list 110 extended permit tcp host 128.107.246.89 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.90 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.91 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.89 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.90 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.91 host 171.68.155.30 eq https 
access-list 110 extended permit tcp any host 128.107.200.65 eq https 
access-list 110 extended permit tcp any host 144.254.208.74 eq https 
access-list 110 extended permit udp any host 144.254.208.74 eq 443 
access-list 110 extended permit tcp any host 144.254.208.75 eq https 
access-list 110 extended permit udp any host 144.254.208.75 eq 443 
access-list 110 extended permit tcp any host 144.254.208.76 eq https 
access-list 110 extended permit udp any host 144.254.208.76 eq 443 
access-list 110 extended permit tcp any 128.107.201.244 255.255.255.252 eq https 
access-list 110 extended permit udp any 128.107.201.244 255.255.255.252 eq 443 
access-list 110 extended permit tcp any host 128.107.201.248 eq https 
access-list 110 extended permit udp any host 128.107.201.248 eq 443 
access-list 110 extended permit tcp any host 128.107.201.252 eq https 
access-list 110 extended permit udp any host 128.107.201.252 eq 443 
access-list 110 extended permit tcp any host 128.107.201.249 eq https 
access-list 110 extended permit udp any host 128.107.201.249 eq 443 
access-list 110 extended permit tcp any host 128.107.201.250 eq https 
access-list 110 extended permit udp any host 128.107.201.250 eq 443 
access-list 110 extended permit tcp any host 128.107.201.251 eq https 
access-list 110 extended permit udp any host 128.107.201.251 eq 443 
access-list 110 extended permit tcp any host 128.107.201.253 eq https 
access-list 110 extended permit udp any host 128.107.201.253 eq 443 
access-list 110 extended permit tcp host 128.107.85.174 host 10.35.48.106 eq sip 
access-list 110 extended permit tcp host 128.107.85.174 host 10.35.48.106 eq 5061 
access-list 110 extended permit tcp host 128.107.85.174 host 10.35.48.107 eq sip 
access-list 110 extended permit tcp host 128.107.85.174 host 10.35.48.107 eq 5061 
access-list 110 extended permit tcp host 128.107.85.174 host 10.35.48.108 eq sip 
access-list 110 extended permit tcp host 128.107.85.174 host 10.35.48.108 eq 5061 
access-list 110 extended permit tcp host 128.107.85.174 host 10.35.48.109 eq sip 
access-list 110 extended permit tcp host 128.107.85.174 host 10.35.48.109 eq 5061 
access-list 110 extended permit tcp host 128.107.85.174 host 10.32.134.108 eq sip 
access-list 110 extended permit tcp host 128.107.85.174 host 10.32.134.108 eq 5061 
access-list 110 extended permit tcp host 128.107.85.174 host 10.32.134.109 eq sip 
access-list 110 extended permit tcp host 128.107.85.174 host 10.32.134.109 eq 5061 
access-list 110 extended permit tcp host 128.107.85.174 host 10.34.130.10 eq sip 
access-list 110 extended permit tcp host 128.107.85.174 host 10.34.130.10 eq 5061 
access-list 110 extended permit udp any host 128.107.201.216 eq isakmp 
access-list 110 extended permit esp any host 128.107.201.216 
access-list 110 extended permit udp any host 128.107.201.216 eq 4500 
access-list 110 extended permit udp any host 128.107.201.216 eq 10000 
access-list 110 extended permit tcp any host 128.107.201.216 eq 10000 
access-list 110 extended permit esp any host 171.71.3.42 
access-list 110 extended permit gre any host 171.71.3.42 
access-list 110 extended permit tcp any host 171.71.3.42 eq 10000 
access-list 110 extended permit udp any host 171.71.3.42 eq 10000 
access-list 110 extended permit udp any host 171.71.3.42 eq isakmp 
access-list 110 extended permit udp any host 171.71.3.42 eq 4500 
access-list 110 extended permit esp host 161.225.176.10 host 64.101.65.46 
access-list 110 extended permit udp host 161.225.176.10 host 64.101.65.46 eq isakmp 
access-list 110 extended permit esp any host 72.163.215.128 
access-list 110 extended permit udp any host 72.163.215.128 eq isakmp 
access-list 110 extended permit udp any host 72.163.215.128 eq 4500 
access-list 110 extended permit esp any host 72.163.215.129 
access-list 110 extended permit udp any host 72.163.215.129 eq isakmp 
access-list 110 extended permit udp any host 72.163.215.129 eq 4500 
access-list 110 extended permit tcp host 128.107.74.167 host 64.100.21.69 eq https 
access-list 110 extended permit tcp host 128.107.74.168 host 64.100.21.69 eq https 
access-list 110 extended permit tcp host 64.100.13.129 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp host 64.100.13.129 host 171.71.184.6 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.130 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp host 64.100.13.130 host 171.71.184.6 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.131 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp host 64.100.13.131 host 171.71.184.6 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.132 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp host 64.100.13.132 host 171.71.184.6 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.228 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp host 64.100.13.228 host 171.71.184.6 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.230 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp host 64.100.13.230 host 171.71.184.6 eq ldaps 
access-list 110 extended permit tcp host 128.107.242.170 host 171.68.225.26 eq ldap 
access-list 110 extended permit tcp host 128.107.242.180 host 171.68.225.26 eq ldap 
access-list 110 extended permit tcp host 128.107.74.167 host 172.17.44.11 eq 7222 
access-list 110 extended permit tcp host 128.107.74.167 host 172.17.44.5 eq 7222 
access-list 110 extended permit tcp host 128.107.74.168 host 172.17.44.11 eq 7222 
access-list 110 extended permit tcp host 128.107.74.168 host 172.17.44.5 eq 7222 
access-list 110 extended permit tcp host 144.254.51.114 host 10.50.165.32 eq 5061 
access-list 110 extended permit gre host 72.163.216.156 host 10.65.166.34 
access-list 110 extended permit tcp host 64.104.94.55 host 10.68.3.80 eq 5443 
access-list 110 extended permit tcp host 64.104.94.55 host 10.68.3.80 eq 5444 
access-list 110 extended permit tcp host 64.104.94.55 host 10.68.3.80 eq 5445 
access-list 110 extended permit tcp host 128.107.243.30 host 171.70.149.200 eq www 
access-list 110 extended permit tcp host 128.107.243.30 host 171.70.149.200 eq https 
access-list 110 extended permit tcp host 128.107.243.30 host 171.70.145.46 eq www 
access-list 110 extended permit tcp host 64.103.37.170 host 171.70.93.236 eq https 
access-list 110 extended permit tcp host 128.107.243.30 host 171.70.188.26 eq https 
access-list 110 extended permit tcp host 128.107.243.30 host 171.70.188.26 range 50120 50121 
access-list 110 extended permit tcp host 128.107.227.212 host 171.71.160.145 eq 13724 
access-list 110 extended permit tcp host 128.107.227.212 host 171.71.160.145 eq 3916 
access-list 110 extended permit tcp host 128.107.227.212 host 171.71.160.145 eq 4001 
access-list 110 extended permit tcp host 128.107.241.75 host 171.71.160.145 eq 13724 
access-list 110 extended permit tcp host 128.107.241.75 host 171.71.160.145 eq 3916 
access-list 110 extended permit tcp host 128.107.241.75 host 171.71.160.145 eq 4001 
access-list 110 extended permit udp host 128.107.227.212 host 72.163.32.152 eq 13724 
access-list 110 extended permit tcp host 128.107.227.212 host 72.163.32.152 eq 13724 
access-list 110 extended permit udp host 128.107.227.212 host 72.163.32.152 eq 1556 
access-list 110 extended permit tcp host 128.107.227.212 host 72.163.32.152 eq 1556 
access-list 110 extended permit udp host 128.107.241.75 host 72.163.32.152 eq 13724 
access-list 110 extended permit tcp host 128.107.241.75 host 72.163.32.152 eq 13724 
access-list 110 extended permit udp host 128.107.241.75 host 72.163.32.152 eq 1556 
access-list 110 extended permit tcp host 128.107.241.75 host 72.163.32.152 eq 1556 
access-list 110 extended permit udp host 171.68.222.80 host 72.163.32.152 eq 13724 
access-list 110 extended permit tcp host 171.68.222.80 host 72.163.32.152 eq 13724 
access-list 110 extended permit udp host 171.68.222.80 host 72.163.32.152 eq 1556 
access-list 110 extended permit tcp host 171.68.222.80 host 72.163.32.152 eq 1556 
access-list 110 extended permit tcp host 128.107.227.212 host 72.163.32.152 eq 3916 
access-list 110 extended permit tcp host 128.107.227.212 host 72.163.32.152 eq 4001 
access-list 110 extended permit tcp host 128.107.241.75 host 72.163.32.152 eq 3916 
access-list 110 extended permit tcp host 128.107.241.75 host 72.163.32.152 eq 4001 
access-list 110 extended permit tcp host 171.68.222.80 host 72.163.32.152 eq 3916 
access-list 110 extended permit tcp host 171.68.222.80 host 72.163.32.152 eq 4001 
access-list 110 extended permit tcp host 64.103.38.71 host 128.107.243.30 eq www 
access-list 110 extended permit tcp host 64.103.38.28 host 128.107.243.30 eq www 
access-list 110 extended permit tcp host 64.103.38.72 host 128.107.243.30 eq www 
access-list 110 extended permit tcp host 64.103.38.71 host 128.107.243.30 eq https 
access-list 110 extended permit tcp host 64.103.38.28 host 128.107.243.30 eq https 
access-list 110 extended permit tcp host 64.103.38.72 host 128.107.243.30 eq https 
access-list 110 extended permit gre host 64.104.95.129 host 10.68.170.177 
access-list 110 extended permit tcp any host 171.70.192.51 eq https 
access-list 110 extended permit esp any host 171.70.192.51 
access-list 110 extended permit udp any host 171.70.192.51 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.51 eq 4500 
access-list 110 extended permit udp any host 171.70.192.51 eq 8000 
access-list 110 extended permit esp host 128.107.81.84 host 10.92.241.210 
access-list 110 extended permit ah host 128.107.81.84 host 10.92.241.210 
access-list 110 extended permit udp host 128.107.81.84 host 10.92.241.210 eq isakmp 
access-list 110 extended permit esp host 62.160.254.30 host 144.254.146.9 
access-list 110 extended permit udp host 62.160.254.30 host 144.254.146.9 eq isakmp 
access-list 110 extended permit ah host 206.112.117.35 host 128.107.156.155 
access-list 110 extended permit esp host 128.107.156.155 host 206.112.117.35 
access-list 110 extended permit udp host 128.107.156.155 host 206.112.117.35 eq isakmp 
access-list 110 extended permit udp host 206.112.117.35 host 171.71.129.43 eq isakmp 
access-list 110 extended permit esp host 206.112.117.35 host 171.71.129.43 
access-list 110 extended permit udp host 206.112.117.35 host 171.71.129.43 eq 4500 
access-list 110 extended permit udp host 206.112.117.35 host 171.71.129.43 eq 10000 
access-list 110 extended permit ah host 206.112.117.35 host 171.71.129.43 
access-list 110 extended permit udp host 63.81.120.147 host 171.71.9.61 eq isakmp 
access-list 110 extended permit esp host 63.81.120.147 host 171.71.9.61 
access-list 110 extended permit udp host 63.81.120.147 host 171.71.9.61 eq 4500 
access-list 110 extended permit udp host 63.81.120.147 host 171.71.9.61 eq 10000 
access-list 110 extended permit ah host 63.81.120.147 host 171.71.9.61 
access-list 110 extended permit udp host 206.112.117.35 host 171.71.9.61 eq isakmp 
access-list 110 extended permit esp host 206.112.117.35 host 171.71.9.61 
access-list 110 extended permit udp host 206.112.117.35 host 171.71.9.61 eq 4500 
access-list 110 extended permit udp host 206.112.117.35 host 171.71.9.61 eq 10000 
access-list 110 extended permit ah host 206.112.117.35 host 171.71.9.61 
access-list 110 extended permit esp 4.53.16.224 255.255.255.252 host 171.71.238.13 
access-list 110 extended permit udp 4.53.16.224 255.255.255.252 host 171.71.238.13 eq isakmp 
access-list 110 extended permit esp 4.79.204.224 255.255.255.252 host 171.71.238.13 
access-list 110 extended permit udp 4.79.204.224 255.255.255.252 host 171.71.238.13 eq isakmp 
access-list 110 extended permit esp 4.59.196.36 255.255.255.252 host 171.71.238.13 
access-list 110 extended permit udp 4.59.196.36 255.255.255.252 host 171.71.238.13 eq isakmp 
access-list 110 extended permit esp 4.71.24.88 255.255.255.252 host 171.71.238.13 
access-list 110 extended permit udp 4.71.24.88 255.255.255.252 host 171.71.238.13 eq isakmp 
access-list 110 extended permit esp 4.71.160.52 255.255.255.252 host 171.71.238.13 
access-list 110 extended permit udp 4.71.160.52 255.255.255.252 host 171.71.238.13 eq isakmp 
access-list 110 extended permit esp 4.71.120.184 255.255.255.252 host 171.71.238.13 
access-list 110 extended permit udp 4.71.120.184 255.255.255.252 host 171.71.238.13 eq isakmp 
access-list 110 extended permit esp host 128.107.81.84 host 10.88.170.102 
access-list 110 extended permit udp host 128.107.81.84 host 10.88.170.102 eq isakmp 
access-list 110 extended permit esp any host 171.70.192.164 
access-list 110 extended permit udp any host 171.70.192.164 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.164 eq 4500 
access-list 110 extended permit esp any host 171.70.192.165 
access-list 110 extended permit udp any host 171.70.192.165 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.165 eq 4500 
access-list 110 extended permit esp host 194.170.166.186 host 64.103.35.189 
access-list 110 extended permit udp host 194.170.166.186 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 194.170.166.186 host 64.103.35.61 
access-list 110 extended permit udp host 194.170.166.186 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 85.154.235.170 host 64.103.35.189 
access-list 110 extended permit udp host 85.154.235.170 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 82.178.19.74 host 64.103.35.61 
access-list 110 extended permit udp host 82.178.19.74 host 64.103.35.61 eq isakmp 
access-list 110 extended permit udp object-group proxy_servers-global-1 object-group aaa_spa_servers-global-1 eq 1812 
access-list 110 extended permit tcp object-group proxy_servers-rtp-1 object-group aaa_spa_servers-global-1 eq 5031 
access-list 110 extended permit tcp host 64.103.36.133 object-group aaa_spa_servers-global-1 eq 5031 
access-list 110 extended permit gre host 172.17.153.35 any 
access-list 110 extended permit tcp host 64.102.240.14 host 172.26.172.170 eq 9080 
access-list 110 extended permit tcp host 64.102.240.14 host 172.26.172.170 eq 5443 
access-list 110 extended permit tcp host 64.100.8.229 host 172.18.106.58 range sip 5061 
access-list 110 extended permit tcp host 64.100.8.229 host 172.18.106.59 range sip 5061 
access-list 110 extended permit tcp host 64.100.8.229 host 172.18.106.60 range sip 5061 
access-list 110 extended permit tcp host 64.100.8.229 host 161.44.248.50 range sip 5061 
access-list 110 extended permit tcp 64.102.243.128 255.255.255.128 host 171.70.130.6 eq 1081 
access-list 110 extended permit tcp 64.102.243.128 255.255.255.128 host 171.70.130.7 eq 1531 
access-list 110 extended permit udp any host 64.102.222.4 eq 4500 
access-list 110 extended permit udp any host 64.102.222.5 eq 4500 
access-list 110 extended permit udp any host 64.102.222.7 eq 4500 
access-list 110 extended permit udp any host 64.102.222.8 eq 4500 
access-list 110 extended permit udp any host 64.102.222.9 eq 4500 
access-list 110 extended permit udp any host 64.102.222.10 eq 4500 
access-list 110 extended permit udp any host 64.102.222.11 eq 4500 
access-list 110 extended permit udp any host 64.102.222.12 eq 4500 
access-list 110 extended permit udp any host 64.102.222.13 eq 4500 
access-list 110 extended permit udp any host 64.102.222.14 eq 4500 
access-list 110 extended permit esp any host 64.102.222.7 
access-list 110 extended permit udp any host 64.102.222.7 eq isakmp 
access-list 110 extended permit udp any host 64.102.222.7 eq 10000 
access-list 110 extended permit tcp any host 64.102.222.7 eq https 
access-list 110 extended permit tcp any host 64.102.222.7 eq ssh 
access-list 110 extended permit esp any host 64.102.222.8 
access-list 110 extended permit udp any host 64.102.222.8 eq isakmp 
access-list 110 extended permit udp any host 64.102.222.8 eq 10000 
access-list 110 extended permit tcp any host 64.102.222.8 eq https 
access-list 110 extended permit tcp any host 64.102.222.8 eq ssh 
access-list 110 extended permit esp any host 64.102.222.9 
access-list 110 extended permit udp any host 64.102.222.9 eq isakmp 
access-list 110 extended permit udp any host 64.102.222.9 eq 10000 
access-list 110 extended permit tcp any host 64.102.222.9 eq https 
access-list 110 extended permit tcp any host 64.102.222.9 eq ssh 
access-list 110 extended permit esp any host 64.102.222.10 
access-list 110 extended permit udp any host 64.102.222.10 eq isakmp 
access-list 110 extended permit udp any host 64.102.222.10 eq 10000 
access-list 110 extended permit tcp any host 64.102.222.10 eq https 
access-list 110 extended permit tcp any host 64.102.222.10 eq ssh 
access-list 110 extended permit esp any host 64.102.222.11 
access-list 110 extended permit udp any host 64.102.222.11 eq isakmp 
access-list 110 extended permit udp any host 64.102.222.11 eq 10000 
access-list 110 extended permit tcp any host 64.102.222.11 eq https 
access-list 110 extended permit tcp any host 64.102.222.11 eq ssh 
access-list 110 extended permit esp any host 64.102.222.12 
access-list 110 extended permit udp any host 64.102.222.12 eq isakmp 
access-list 110 extended permit udp any host 64.102.222.12 eq 10000 
access-list 110 extended permit tcp any host 64.102.222.12 eq https 
access-list 110 extended permit tcp any host 64.102.222.12 eq ssh 
access-list 110 extended permit esp any host 64.102.222.13 
access-list 110 extended permit udp any host 64.102.222.13 eq isakmp 
access-list 110 extended permit udp any host 64.102.222.13 eq 10000 
access-list 110 extended permit tcp any host 64.102.222.13 eq https 
access-list 110 extended permit tcp any host 64.102.222.13 eq ssh 
access-list 110 extended permit esp any host 64.102.222.14 
access-list 110 extended permit udp any host 64.102.222.14 eq isakmp 
access-list 110 extended permit udp any host 64.102.222.14 eq 10000 
access-list 110 extended permit tcp any host 64.102.222.14 eq https 
access-list 110 extended permit tcp any host 64.102.222.14 eq ssh 
access-list 110 extended permit tcp host 64.102.241.52 host 172.18.172.49 eq 5443 
access-list 110 extended permit tcp host 64.102.241.52 host 172.18.172.49 eq 9080 
access-list 110 extended permit tcp host 64.102.241.52 host 172.18.172.49 eq 9443 
access-list 110 extended permit tcp host 64.102.241.52 host 172.18.172.49 eq https 
access-list 110 extended permit tcp host 64.102.241.53 host 172.18.172.177 eq 5443 
access-list 110 extended permit tcp host 64.102.241.53 host 172.18.172.177 eq 9080 
access-list 110 extended permit tcp host 64.102.241.53 host 172.18.172.177 eq 9443 
access-list 110 extended permit tcp host 64.102.241.53 host 172.18.172.177 eq https 
access-list 110 extended permit tcp host 64.100.8.106 host 64.102.124.15 eq smtp 
access-list 110 extended permit tcp 64.102.255.128 255.255.255.224 host 64.102.124.15 eq smtp 
access-list 110 extended deny tcp host 198.137.202.18 host 64.102.8.172 eq ssh 
access-list 110 extended permit tcp any host 64.102.8.172 eq ssh 
access-list 110 extended permit tcp host 64.100.8.227 host 172.18.106.71 eq 9080 
access-list 110 extended permit tcp host 64.100.8.227 host 172.18.106.71 eq 5443 
access-list 110 extended permit tcp host 64.100.8.227 host 172.18.106.71 eq 9443 
access-list 110 extended permit tcp host 64.100.8.226 172.18.106.0 255.255.255.0 eq www 
access-list 110 extended permit tcp any host 64.102.252.8 eq www 
access-list 110 extended permit tcp any host 64.102.252.8 eq https 
access-list 110 extended permit udp any host 64.102.252.8 eq 443 
access-list 110 extended permit tcp any host 64.102.252.9 eq www 
access-list 110 extended permit tcp any host 64.102.252.9 eq https 
access-list 110 extended permit udp any host 64.102.252.9 eq 443 
access-list 110 extended permit tcp any host 64.102.252.49 eq www 
access-list 110 extended permit tcp any host 64.102.252.49 eq https 
access-list 110 extended permit tcp any host 64.102.252.49 eq 8000 
access-list 110 extended deny tcp host 198.137.202.18 host 64.100.32.216 eq ssh 
access-list 110 extended permit tcp any host 64.100.32.216 eq ssh 
access-list 110 extended permit tcp 64.102.243.128 255.255.255.128 host 171.70.171.68 eq 1433 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 171.70.113.29 eq 1081 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 171.70.113.30 eq 1531 
access-list 110 extended permit tcp 64.102.243.128 255.255.255.128 host 171.70.113.29 eq 1081 
access-list 110 extended permit tcp 64.102.243.128 255.255.255.128 host 171.70.113.30 eq 1531 
access-list 110 extended permit gre host 64.104.127.65 10.74.42.0 255.255.255.128 
access-list 110 extended permit pim host 171.69.10.13 any 
access-list 110 extended permit pim 64.103.36.192 255.255.255.224 64.103.36.192 255.255.255.224 
access-list 110 extended permit pim 64.103.36.192 255.255.255.224 host 224.0.0.13 
access-list 110 extended permit pim 64.104.252.32 255.255.255.224 64.104.252.32 255.255.255.224 
access-list 110 extended permit pim 64.104.252.32 255.255.255.224 host 224.0.0.13 
access-list 110 extended permit pim 64.102.241.128 255.255.255.224 64.102.241.128 255.255.255.224 
access-list 110 extended permit pim 64.102.241.128 255.255.255.224 host 224.0.0.13 
access-list 110 extended permit pim 128.107.236.32 255.255.255.224 128.107.236.32 255.255.255.224 
access-list 110 extended permit pim 128.107.236.32 255.255.255.224 host 224.0.0.13 
access-list 110 extended permit pim 198.135.0.240 255.255.255.240 198.135.0.240 255.255.255.240 
access-list 110 extended permit pim 198.135.0.240 255.255.255.240 host 224.0.0.13 
access-list 110 extended permit pim 64.104.94.112 255.255.255.240 64.104.94.112 255.255.255.240 
access-list 110 extended permit pim 64.104.94.112 255.255.255.240 host 224.0.0.13 
access-list 110 extended permit pim 173.37.148.224 255.255.255.240 173.37.148.224 255.255.255.240 
access-list 110 extended permit pim 173.37.148.224 255.255.255.240 host 224.0.0.13 
access-list 110 extended permit ip host 171.69.10.13 object-group multicast_networks-global-1 
access-list 110 extended permit udp any object-group multicast_networks-global-1 gt 1023 
access-list 110 extended permit udp host 171.69.10.13 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit 113 any object-group multicast_networks-global-1 
access-list 110 extended permit tcp host 64.103.36.150 host 171.71.160.145 eq 13724 
access-list 110 extended permit tcp host 64.103.36.150 host 171.71.160.145 eq 3916 
access-list 110 extended permit tcp host 64.103.36.150 host 171.71.160.145 eq 4001 
access-list 110 extended permit tcp host 64.103.36.150 host 72.163.32.152 eq 13724 
access-list 110 extended permit udp host 64.103.36.150 host 72.163.32.152 eq 13724 
access-list 110 extended permit tcp host 64.103.36.150 host 72.163.32.152 eq 1556 
access-list 110 extended permit udp host 64.103.36.150 host 72.163.32.152 eq 1556 
access-list 110 extended permit tcp host 64.103.36.150 host 72.163.32.152 eq 3916 
access-list 110 extended permit tcp host 64.103.36.150 host 72.163.32.152 eq 4001 
access-list 110 extended permit tcp host 64.103.26.171 host 144.254.208.113 eq 2000 
access-list 110 extended permit tcp host 64.103.26.171 host 144.254.208.113 eq 2443 
access-list 110 extended permit tcp host 64.103.26.171 host 144.254.208.113 eq sip 
access-list 110 extended permit tcp host 64.103.26.171 host 144.254.208.113 eq 5061 
access-list 110 extended permit tcp host 64.103.26.170 host 144.254.208.111 eq 3804 
access-list 110 extended permit udp host 64.103.26.170 host 144.254.208.112 eq tftp 
access-list 110 extended permit icmp 10.81.52.0 255.255.255.240 64.102.14.0 255.255.255.192 
access-list 110 extended permit tcp host 64.102.241.134 any eq domain 
access-list 110 extended permit tcp host 64.102.241.135 any eq domain 
access-list 110 extended permit icmp host 64.102.241.135 any echo 
access-list 110 extended permit icmp host 64.102.241.134 any echo 
access-list 110 extended permit tcp host 64.102.246.5 any eq domain 
access-list 110 extended permit udp host 64.102.246.5 any eq domain 
access-list 110 extended permit icmp host 64.102.246.5 any echo 
access-list 110 extended permit tcp 10.81.52.0 255.255.255.240 host 64.102.14.8 eq ssh 
access-list 110 extended permit tcp 10.81.52.0 255.255.255.240 host 64.102.14.8 range 900 910 
access-list 110 extended permit udp 10.81.52.0 255.255.255.240 host 64.102.14.8 range 900 910 
access-list 110 extended permit tcp 10.81.52.0 255.255.255.240 host 64.102.14.8 eq www 
access-list 110 extended permit tcp 10.81.52.0 255.255.255.240 host 64.102.14.8 eq https 
access-list 110 extended permit tcp 10.81.52.0 255.255.255.240 host 64.102.14.8 eq 27000 
access-list 110 extended permit tcp 10.89.255.192 255.255.255.192 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 10.89.255.192 255.255.255.192 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 10.101.14.0 255.255.254.0 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 10.101.14.0 255.255.254.0 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 10.101.206.0 255.255.254.0 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 10.101.206.0 255.255.254.0 host 64.104.193.35 eq tacacs 
access-list 110 extended permit udp 10.89.255.192 255.255.255.192 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 10.101.14.0 255.255.254.0 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 10.101.206.0 255.255.254.0 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 12.5.186.0 255.255.255.248 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 12.5.186.8 255.255.255.252 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 12.5.186.12 255.255.255.252 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 12.5.186.16 255.255.255.248 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 12.5.186.24 255.255.255.248 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 12.5.186.48 255.255.255.252 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 12.5.186.52 255.255.255.252 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 12.5.186.56 255.255.255.252 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 12.5.186.60 255.255.255.252 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 12.5.187.0 255.255.255.252 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 12.5.187.64 255.255.255.252 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 12.5.187.80 255.255.255.252 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 12.5.187.248 255.255.255.248 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 12.46.104.0 255.255.254.0 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 72.163.0.0 255.255.240.0 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 173.37.192.0 255.255.224.0 host 171.71.180.220 eq syslog 
access-list 110 extended permit udp 173.37.144.0 255.255.248.0 host 171.71.180.220 eq syslog 
access-list 110 extended permit tcp 12.5.186.0 255.255.255.248 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 12.5.186.0 255.255.255.248 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 12.5.186.8 255.255.255.252 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 12.5.186.8 255.255.255.252 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 12.5.186.12 255.255.255.252 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 12.5.186.12 255.255.255.252 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 12.5.186.16 255.255.255.248 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 12.5.186.16 255.255.255.248 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 12.5.186.24 255.255.255.248 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 12.5.186.24 255.255.255.248 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 12.5.186.48 255.255.255.252 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 12.5.186.48 255.255.255.252 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 12.5.186.52 255.255.255.252 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 12.5.186.52 255.255.255.252 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 12.5.186.56 255.255.255.252 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 12.5.186.56 255.255.255.252 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 12.5.186.60 255.255.255.252 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 12.5.186.60 255.255.255.252 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 12.5.187.0 255.255.255.252 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 12.5.187.0 255.255.255.252 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 12.5.187.64 255.255.255.252 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 12.5.187.64 255.255.255.252 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 12.5.187.80 255.255.255.252 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 12.5.187.80 255.255.255.252 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 12.5.187.248 255.255.255.248 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 12.5.187.248 255.255.255.248 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 12.46.104.0 255.255.254.0 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 12.46.104.0 255.255.254.0 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 72.163.0.0 255.255.240.0 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 72.163.0.0 255.255.240.0 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 173.37.192.0 255.255.224.0 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 173.37.192.0 255.255.224.0 host 64.104.193.35 eq tacacs 
access-list 110 extended permit tcp 173.37.144.0 255.255.248.0 host 144.254.74.144 eq tacacs 
access-list 110 extended permit tcp 173.37.144.0 255.255.248.0 host 64.104.193.35 eq tacacs 
access-list 110 extended deny icmp any object-group multicast_networks-global-1 
access-list 110 extended deny ip object-group multicast_networks-global-1 any 
access-list 110 extended permit tcp any host 171.70.192.81 eq www 
access-list 110 extended permit tcp 128.107.81.224 255.255.255.224 host 171.70.188.63 eq www 
access-list 110 extended permit udp any host 171.70.192.84 eq 443 
access-list 110 extended permit udp any host 171.70.192.85 eq 443 
access-list 110 extended permit esp object-group cclc_external-sjc-1 object-group cclc_internal-sjc-1 
access-list 110 extended permit tcp object-group cclc_external-sjc-1 object-group cclc_internal-sjc-1 eq 10000 
access-list 110 extended permit udp object-group cclc_external-sjc-1 object-group cclc_internal-sjc-1 eq isakmp 
access-list 110 extended permit udp object-group cclc_external-sjc-1 object-group cclc_internal-sjc-1 eq 62514 
access-list 110 extended permit esp host 65.74.0.194 host 64.101.31.6 
access-list 110 extended permit esp host 65.74.0.194 host 64.101.31.10 
access-list 110 extended permit udp host 65.74.0.194 host 64.101.31.6 eq isakmp 
access-list 110 extended permit udp host 65.74.0.194 host 64.101.31.10 eq isakmp 
access-list 110 extended permit esp host 125.215.161.66 host 64.104.123.9 
access-list 110 extended permit udp host 125.215.161.66 host 64.104.123.9 eq isakmp 
access-list 110 extended permit udp host 125.215.161.66 host 64.104.123.9 eq 4500 
access-list 110 extended permit gre host 64.104.127.65 host 10.79.181.195 
access-list 110 extended permit udp any host 171.70.192.91 eq 443 
access-list 110 extended permit tcp any host 171.70.35.114 eq https 
access-list 110 extended permit tcp any host 171.70.35.115 eq https 
access-list 110 extended permit udp any host 171.70.35.114 eq 443 
access-list 110 extended permit udp any host 171.70.35.115 eq 443 
access-list 110 extended permit udp any object-group ncbu_vpn-sjc-1 eq isakmp 
access-list 110 extended permit esp any object-group ncbu_vpn-sjc-1 
access-list 110 extended permit udp any object-group ncbu_vpn-sjc-1 eq 4500 
access-list 110 extended permit udp any object-group ncbu_vpn-sjc-1 eq 10000 
access-list 110 extended permit tcp any object-group ncbu_vpn-sjc-1 eq 10000 
access-list 110 extended permit udp host 64.102.240.212 host 10.81.255.1 eq snmp 
access-list 110 extended permit udp host 64.102.240.213 host 10.81.255.1 eq snmp 
access-list 110 extended permit udp host 64.102.240.214 host 10.81.255.1 eq snmp 
access-list 110 extended permit udp host 64.102.240.215 host 10.81.255.1 eq snmp 
access-list 110 extended permit udp host 64.102.240.212 host 10.81.255.2 eq snmp 
access-list 110 extended permit udp host 64.102.240.213 host 10.81.255.2 eq snmp 
access-list 110 extended permit udp host 64.102.240.214 host 10.81.255.2 eq snmp 
access-list 110 extended permit udp host 64.102.240.215 host 10.81.255.2 eq snmp 
access-list 110 extended permit tcp any host 64.100.25.127 eq smtp 
access-list 110 extended permit udp any host 171.70.192.180 eq 5246 
access-list 110 extended permit udp any host 171.70.192.180 eq 5247 
access-list 110 extended permit udp any host 171.70.192.181 eq 5246 
access-list 110 extended permit udp any host 171.70.192.181 eq 5247 
access-list 110 extended permit udp any host 64.102.223.98 eq 5246 
access-list 110 extended permit udp any host 64.102.223.98 eq 12222 
access-list 110 extended permit tcp host 64.102.248.4 host 64.102.223.36 eq sip 
access-list 110 extended permit tcp host 64.102.248.4 host 64.102.223.37 eq sip 
access-list 110 extended permit tcp host 64.102.248.4 host 64.102.223.38 eq sip 
access-list 110 extended permit tcp host 64.102.248.4 host 64.102.223.36 eq 5061 
access-list 110 extended permit tcp host 64.102.248.4 host 64.102.223.37 eq 5061 
access-list 110 extended permit tcp host 64.102.248.4 host 64.102.223.38 eq 5061 
access-list 110 extended permit tcp host 64.102.248.4 host 64.102.223.36 range sip 5061 
access-list 110 extended permit tcp host 64.102.248.4 host 64.102.223.37 range sip 5061 
access-list 110 extended permit tcp host 64.102.248.4 host 64.102.223.38 range sip 5061 
access-list 110 extended permit tcp host 72.163.4.6 host 171.71.160.145 eq 13724 
access-list 110 extended permit tcp host 72.163.4.6 host 171.71.160.145 eq 3916 
access-list 110 extended permit tcp host 72.163.4.6 host 171.71.160.145 eq 4001 
access-list 110 extended permit tcp host 72.163.4.6 host 72.163.32.152 eq 13724 
access-list 110 extended permit udp host 72.163.4.6 host 72.163.32.152 eq 13724 
access-list 110 extended permit tcp host 72.163.4.6 host 72.163.32.152 eq 1556 
access-list 110 extended permit udp host 72.163.4.6 host 72.163.32.152 eq 1556 
access-list 110 extended permit tcp host 72.163.4.6 host 72.163.32.152 eq 3916 
access-list 110 extended permit tcp host 72.163.4.6 host 72.163.32.152 eq 4001 
access-list 110 extended permit udp 10.101.14.0 255.255.254.0 host 171.68.226.94 eq 2055 
access-list 110 extended permit udp 10.101.14.0 255.255.254.0 host 72.163.42.114 eq 2055 
access-list 110 extended permit udp host 10.101.206.39 host 171.71.180.202 range 2055 2065 
access-list 110 extended permit udp host 10.101.206.40 host 171.71.180.202 range 2055 2065 
access-list 110 extended permit esp host 59.17.183.46 host 64.104.14.232 
access-list 110 extended permit udp host 59.17.183.46 host 64.104.14.232 eq isakmp 
access-list 110 extended permit esp host 59.17.183.46 host 64.104.14.233 
access-list 110 extended permit udp host 59.17.183.46 host 64.104.14.233 eq isakmp 
access-list 110 extended permit tcp 10.101.15.128 255.255.255.192 host 171.70.168.154 range ftp-data ftp 
access-list 110 extended permit tcp 10.101.206.0 255.255.254.0 host 171.70.168.154 range ftp-data ftp 
access-list 110 extended permit tcp host 192.208.44.36 host 173.38.201.9 eq 4080 
access-list 110 extended permit tcp host 192.208.44.36 host 173.38.201.16 eq 4080 
access-list 110 extended permit tcp host 192.208.44.36 host 173.38.201.14 eq 4080 
access-list 110 extended permit udp host 144.254.51.2 10.54.64.0 255.255.224.0 eq 3478 
access-list 110 extended permit tcp 72.163.4.128 255.255.255.128 171.68.11.64 255.255.255.192 eq 6021 
access-list 110 extended permit tcp 72.163.5.128 255.255.255.192 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp 72.163.5.128 255.255.255.192 host 171.68.224.207 eq ldap 
access-list 110 extended permit tcp 72.163.5.128 255.255.255.192 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp 72.163.5.128 255.255.255.192 host 171.68.226.148 eq 7222 
access-list 110 extended permit tcp 72.163.5.128 255.255.255.192 host 171.68.226.149 eq 7222 
access-list 110 extended permit tcp 72.163.5.32 255.255.255.224 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp 72.163.5.32 255.255.255.224 host 171.68.224.207 eq ldap 
access-list 110 extended permit tcp 72.163.5.32 255.255.255.224 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 171.71.182.156 eq www 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 72.163.46.57 eq www 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 64.101.140.97 eq netbios-ssn 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 64.101.140.97 eq 445 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 171.68.46.115 eq 445 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 171.68.46.115 eq netbios-ssn 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 171.68.46.115 eq 402 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 171.68.46.115 eq 415 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 171.68.46.115 eq 4300 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 72.163.42.112 eq bootps 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 72.163.42.113 eq bootps 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 72.163.42.112 eq bootpc 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 72.163.42.113 eq bootpc 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 64.101.128.22 eq domain 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 64.101.128.23 eq domain 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 72.163.47.13 eq domain 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 72.163.47.14 eq domain 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 72.163.47.11 eq domain 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 64.101.140.238 eq netbios-ns 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 10.81.254.131 eq ntp 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 10.81.254.202 eq ntp 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 171.68.10.150 eq ntp 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 171.68.10.80 eq ntp 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 64.101.140.97 eq tftp 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 gt 1023 host 64.101.140.97 gt 1023 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 171.70.168.183 eq domain 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 host 171.68.226.120 eq domain 
access-list 110 extended permit tcp host 64.128.43.194 host 72.163.26.138 eq www 
access-list 110 extended permit tcp host 64.128.43.194 host 72.163.26.138 eq https 
access-list 110 extended permit udp 10.101.164.0 255.255.255.0 host 173.37.115.19 eq 902 
access-list 110 extended permit tcp 10.101.164.0 255.255.255.0 host 173.37.115.19 eq www 
access-list 110 extended permit tcp 10.101.164.0 255.255.255.0 host 173.37.115.19 eq https 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 171.71.182.156 eq https 
access-list 110 extended permit tcp host 72.163.4.6 host 72.163.32.168 eq 27463 
access-list 110 extended permit tcp host 72.163.4.6 host 72.163.32.168 eq 27464 
access-list 110 extended permit tcp host 72.163.4.6 host 173.37.92.5 eq 27463 
access-list 110 extended permit tcp host 72.163.4.6 host 173.37.92.5 eq 27464 
access-list 110 extended permit tcp host 72.163.5.71 host 72.163.41.78 eq 6021 
access-list 110 extended permit tcp host 72.163.5.72 host 72.163.41.78 eq 6021 
access-list 110 extended permit tcp host 72.163.5.73 host 72.163.41.78 eq 6021 
access-list 110 extended permit tcp host 72.163.5.74 host 72.163.41.78 eq 6021 
access-list 110 extended permit tcp host 72.163.5.71 host 72.163.41.79 eq 6021 
access-list 110 extended permit tcp host 72.163.5.72 host 72.163.41.79 eq 6021 
access-list 110 extended permit tcp host 72.163.5.73 host 72.163.41.79 eq 6021 
access-list 110 extended permit tcp host 72.163.5.74 host 72.163.41.79 eq 6021 
access-list 110 extended permit tcp host 72.163.5.71 host 72.163.41.80 eq 6021 
access-list 110 extended permit tcp host 72.163.5.72 host 72.163.41.80 eq 6021 
access-list 110 extended permit tcp host 72.163.5.73 host 72.163.41.80 eq 6021 
access-list 110 extended permit tcp host 72.163.5.74 host 72.163.41.80 eq 6021 
access-list 110 extended permit tcp host 72.163.5.71 host 72.163.41.81 eq 6021 
access-list 110 extended permit tcp host 72.163.5.72 host 72.163.41.81 eq 6021 
access-list 110 extended permit tcp host 72.163.5.73 host 72.163.41.81 eq 6021 
access-list 110 extended permit tcp host 72.163.5.74 host 72.163.41.81 eq 6021 
access-list 110 extended permit tcp host 72.163.5.71 host 72.163.41.82 eq 6021 
access-list 110 extended permit tcp host 72.163.5.72 host 72.163.41.82 eq 6021 
access-list 110 extended permit tcp host 72.163.5.73 host 72.163.41.82 eq 6021 
access-list 110 extended permit tcp host 72.163.5.74 host 72.163.41.82 eq 6021 
access-list 110 extended permit tcp host 72.163.5.71 host 72.163.41.83 eq 6021 
access-list 110 extended permit tcp host 72.163.5.72 host 72.163.41.83 eq 6021 
access-list 110 extended permit tcp host 72.163.5.73 host 72.163.41.83 eq 6021 
access-list 110 extended permit tcp host 72.163.5.74 host 72.163.41.83 eq 6021 
access-list 110 extended permit tcp host 72.163.5.71 host 72.163.41.84 eq 6021 
access-list 110 extended permit tcp host 72.163.5.72 host 72.163.41.84 eq 6021 
access-list 110 extended permit tcp host 72.163.5.73 host 72.163.41.84 eq 6021 
access-list 110 extended permit tcp host 72.163.5.74 host 72.163.41.84 eq 6021 
access-list 110 extended permit tcp host 72.163.5.71 host 72.163.41.85 eq 6021 
access-list 110 extended permit tcp host 72.163.5.72 host 72.163.41.85 eq 6021 
access-list 110 extended permit tcp host 72.163.5.73 host 72.163.41.85 eq 6021 
access-list 110 extended permit tcp host 72.163.5.74 host 72.163.41.85 eq 6021 
access-list 110 extended permit tcp host 72.163.5.71 host 171.68.11.80 eq 6021 
access-list 110 extended permit tcp host 72.163.5.72 host 171.68.11.80 eq 6021 
access-list 110 extended permit tcp host 72.163.5.73 host 171.68.11.80 eq 6021 
access-list 110 extended permit tcp host 72.163.5.74 host 171.68.11.80 eq 6021 
access-list 110 extended permit tcp host 72.163.5.71 host 171.68.11.81 eq 6021 
access-list 110 extended permit tcp host 72.163.5.72 host 171.68.11.81 eq 6021 
access-list 110 extended permit tcp host 72.163.5.73 host 171.68.11.81 eq 6021 
access-list 110 extended permit tcp host 72.163.5.74 host 171.68.11.81 eq 6021 
access-list 110 extended permit tcp host 72.163.5.71 host 171.68.11.82 eq 6021 
access-list 110 extended permit tcp host 72.163.5.72 host 171.68.11.82 eq 6021 
access-list 110 extended permit tcp host 72.163.5.73 host 171.68.11.82 eq 6021 
access-list 110 extended permit tcp host 72.163.5.74 host 171.68.11.82 eq 6021 
access-list 110 extended permit tcp host 72.163.5.71 host 171.68.11.83 eq 6021 
access-list 110 extended permit tcp host 72.163.5.72 host 171.68.11.83 eq 6021 
access-list 110 extended permit tcp host 72.163.5.73 host 171.68.11.83 eq 6021 
access-list 110 extended permit tcp host 72.163.5.74 host 171.68.11.83 eq 6021 
access-list 110 extended permit tcp host 72.163.5.71 host 171.68.11.84 eq 6021 
access-list 110 extended permit tcp host 72.163.5.72 host 171.68.11.84 eq 6021 
access-list 110 extended permit tcp host 72.163.5.73 host 171.68.11.84 eq 6021 
access-list 110 extended permit tcp host 72.163.5.74 host 171.68.11.84 eq 6021 
access-list 110 extended permit tcp host 72.163.5.71 host 171.68.11.85 eq 6021 
access-list 110 extended permit tcp host 72.163.5.72 host 171.68.11.85 eq 6021 
access-list 110 extended permit tcp host 72.163.5.73 host 171.68.11.85 eq 6021 
access-list 110 extended permit tcp host 72.163.5.74 host 171.68.11.85 eq 6021 
access-list 110 extended permit gre host 10.101.14.26 host 10.89.128.74 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.7 
access-list 110 extended permit esp any host 72.163.19.145 
access-list 110 extended permit udp any host 72.163.19.145 eq isakmp 
access-list 110 extended permit udp any host 72.163.19.145 eq 4500 
access-list 110 extended permit tcp any host 72.163.19.146 eq https 
access-list 110 extended permit tcp any host 72.163.19.146 eq 8000 
access-list 110 extended permit tcp any host 72.163.19.147 eq https 
access-list 110 extended permit tcp any host 72.163.19.147 eq 8000 
access-list 110 extended permit esp any host 72.163.19.132 
access-list 110 extended permit udp any host 72.163.19.132 eq isakmp 
access-list 110 extended permit udp any host 72.163.19.132 eq 4500 
access-list 110 extended permit udp any host 72.163.19.132 eq 10000 
access-list 110 extended permit tcp any host 72.163.19.132 eq https 
access-list 110 extended permit tcp any host 72.163.19.132 eq ssh 
access-list 110 extended permit esp any host 72.163.19.133 
access-list 110 extended permit udp any host 72.163.19.133 eq isakmp 
access-list 110 extended permit udp any host 72.163.19.133 eq 4500 
access-list 110 extended permit udp any host 72.163.19.133 eq 10000 
access-list 110 extended permit tcp any host 72.163.19.133 eq https 
access-list 110 extended permit tcp any host 72.163.19.133 eq ssh 
access-list 110 extended permit esp any host 72.163.19.134 
access-list 110 extended permit udp any host 72.163.19.134 eq isakmp 
access-list 110 extended permit udp any host 72.163.19.134 eq 4500 
access-list 110 extended permit udp any host 72.163.19.134 eq 10000 
access-list 110 extended permit tcp any host 72.163.19.134 eq https 
access-list 110 extended permit tcp any host 72.163.19.134 eq ssh 
access-list 110 extended permit esp any host 72.163.19.135 
access-list 110 extended permit udp any host 72.163.19.135 eq isakmp 
access-list 110 extended permit udp any host 72.163.19.135 eq 4500 
access-list 110 extended permit udp any host 72.163.19.135 eq 10000 
access-list 110 extended permit tcp any host 72.163.19.135 eq https 
access-list 110 extended permit tcp any host 72.163.19.135 eq ssh 
access-list 110 extended permit esp any host 72.163.19.136 
access-list 110 extended permit udp any host 72.163.19.136 eq isakmp 
access-list 110 extended permit udp any host 72.163.19.136 eq 4500 
access-list 110 extended permit udp any host 72.163.19.136 eq 10000 
access-list 110 extended permit tcp any host 72.163.19.136 eq https 
access-list 110 extended permit tcp any host 72.163.19.136 eq ssh 
access-list 110 extended permit esp any host 171.70.192.2 
access-list 110 extended permit udp any host 171.70.192.2 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.2 eq 4500 
access-list 110 extended permit tcp host 173.37.193.2 host 10.88.12.71 eq sip 
access-list 110 extended permit tcp host 173.37.193.2 host 10.88.12.71 eq 5061 
access-list 110 extended permit tcp host 173.37.193.2 host 10.88.12.72 eq sip 
access-list 110 extended permit tcp host 173.37.193.2 host 10.88.12.72 eq 5061 
access-list 110 extended permit tcp 12.46.104.0 255.255.255.0 object-group dmz_smtp-global-1 eq smtp 
access-list 110 extended permit tcp 12.5.187.192 255.255.255.252 object-group dmz_smtp-global-1 eq smtp 
access-list 110 extended permit tcp host 128.107.234.208 host 171.71.177.236 eq smtp 
access-list 110 extended permit tcp host 128.107.234.209 host 171.71.177.236 eq smtp 
access-list 110 extended permit tcp host 128.107.227.231 host 171.70.144.188 eq smtp 
access-list 110 extended permit tcp host 128.107.227.232 host 171.70.144.188 eq smtp 
access-list 110 extended permit tcp host 128.107.227.233 host 171.70.144.188 eq smtp 
access-list 110 extended permit tcp host 128.107.227.234 host 171.70.144.188 eq smtp 
access-list 110 extended permit tcp host 128.107.234.216 host 128.107.234.204 eq smtp 
access-list 110 extended permit tcp host 128.107.234.216 host 128.107.234.206 eq smtp 
access-list 110 extended permit tcp host 128.107.234.216 host 171.68.223.136 eq smtp 
access-list 110 extended permit tcp host 128.107.234.216 host 171.71.177.236 eq smtp 
access-list 110 extended permit tcp host 128.107.234.216 host 64.102.124.15 eq smtp 
access-list 110 extended permit esp host 64.102.245.77 host 64.101.73.215 
access-list 110 extended permit udp host 64.102.245.77 host 64.101.73.215 eq isakmp 
access-list 110 extended permit esp host 64.100.8.163 host 172.23.81.197 
access-list 110 extended permit ah host 64.100.8.163 host 172.23.81.197 
access-list 110 extended permit udp host 64.100.8.163 host 172.23.81.197 eq isakmp 
access-list 110 extended permit udp host 64.100.8.163 host 172.23.81.197 eq 4500 
access-list 110 extended permit tcp host 128.107.234.70 host 171.68.10.148 range 44441 44443 
access-list 110 extended permit tcp host 128.107.81.200 host 171.70.121.28 eq 5443 
access-list 110 extended permit tcp host 128.107.81.200 host 171.70.121.28 eq 5444 
access-list 110 extended permit tcp host 128.107.81.200 host 171.70.121.28 eq 5445 
access-list 110 extended permit esp any host 72.163.130.100 
access-list 110 extended permit esp any host 72.163.215.41 
access-list 110 extended permit udp any host 72.163.130.100 eq isakmp 
access-list 110 extended permit udp any host 72.163.215.41 eq isakmp 
access-list 110 extended permit udp any host 72.163.130.100 eq 4500 
access-list 110 extended permit udp any host 72.163.215.41 eq 4500 
access-list 110 extended permit tcp any host 72.163.215.42 eq https 
access-list 110 extended permit tcp any host 72.163.215.42 eq 8000 
access-list 110 extended permit udp any host 72.163.198.194 eq 5247 
access-list 110 extended permit udp any host 72.163.198.195 eq 5246 
access-list 110 extended permit udp any host 72.163.198.195 eq 5247 
access-list 110 extended permit udp any host 72.163.198.194 eq 5246 
access-list 110 extended permit udp any host 72.163.198.194 eq 12222 
access-list 110 extended permit tcp any host 12.5.186.1 eq https 
access-list 110 extended permit tcp any host 12.5.186.1 eq 8000 
access-list 110 extended permit esp any host 12.5.186.2 
access-list 110 extended permit udp any host 12.5.186.2 eq isakmp 
access-list 110 extended permit udp any host 12.5.186.2 eq 4500 
access-list 110 extended permit esp any host 12.5.186.3 
access-list 110 extended permit udp any host 12.5.186.3 eq isakmp 
access-list 110 extended permit udp any host 12.5.186.3 eq 4500 
access-list 110 extended permit udp host 10.89.255.200 host 64.102.12.51 range 2055 2065 
access-list 110 extended permit udp object-group dmz_networks-ams-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-aus-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-japan-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-rtp-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-rich-1 object-group tftp_servers-global-1 eq tftp 
	      access-list 110 extended permit udp object-group dmz_networks-sjc-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-bgl-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-vancouver-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-rcdn9-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-shanghai-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-bxb-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-singapore-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-hk-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-isr-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-brnt-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp host 64.104.94.84 host 10.68.12.11 eq snmp 
access-list 110 extended permit udp host 64.104.94.84 host 10.68.12.12 eq snmp 
access-list 110 extended permit esp host 128.107.81.84 host 10.89.46.254 
access-list 110 extended permit udp host 128.107.81.84 host 10.89.46.254 eq isakmp 
access-list 110 extended permit gre host 192.133.211.33 host 10.81.255.11 
access-list 110 extended permit gre host 192.133.211.34 host 10.81.255.20 
access-list 110 extended permit gre host 10.81.255.11 host 192.133.211.33 
access-list 110 extended permit gre host 10.81.255.20 host 192.133.211.34 
access-list 110 extended permit udp host 64.104.252.100 host 10.66.129.139 eq snmp 
access-list 110 extended permit udp host 64.104.252.100 host 10.66.129.140 eq snmp 
access-list 110 extended permit tcp host 173.37.192.204 host 72.163.53.248 eq 6021 
access-list 110 extended permit tcp host 173.37.192.204 host 72.163.53.249 eq 6021 
access-list 110 extended permit tcp host 173.37.192.204 host 72.163.53.250 eq 6021 
access-list 110 extended permit tcp host 173.37.192.204 host 72.163.53.251 eq 6021 
access-list 110 extended permit tcp host 173.37.192.204 host 173.37.117.166 eq 6021 
access-list 110 extended permit tcp host 173.37.192.204 host 173.37.117.167 eq 6021 
access-list 110 extended permit tcp host 173.37.192.204 host 173.37.117.168 eq 6021 
access-list 110 extended permit tcp host 173.37.192.204 host 173.37.117.169 eq 6021 
access-list 110 extended permit tcp host 173.37.192.204 host 172.17.55.106 eq 6021 
access-list 110 extended permit tcp host 173.37.192.204 host 172.17.55.107 eq 6021 
access-list 110 extended permit tcp host 173.37.192.204 host 172.17.55.108 eq 6021 
access-list 110 extended permit tcp host 173.37.192.204 host 172.17.55.109 eq 6021 
access-list 110 extended permit tcp host 173.37.192.204 host 172.17.55.106 eq 6022 
access-list 110 extended permit tcp host 173.37.192.204 host 172.17.55.106 eq 6023 
access-list 110 extended permit tcp host 173.37.192.204 host 172.17.55.106 eq 6024 
access-list 110 extended permit tcp any host 72.163.6.6 eq https 
access-list 110 extended permit tcp any host 72.163.6.7 eq https 
access-list 110 extended permit tcp host 72.163.6.6 host 72.163.56.102 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.7 host 72.163.56.102 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.6 host 171.68.38.106 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.7 host 171.68.38.106 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.6 host 171.68.224.6 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.7 host 171.68.224.6 eq ldaps 
access-list 110 extended permit tcp host 72.163.6.6 host 72.163.62.158 eq https 
access-list 110 extended permit tcp host 72.163.6.7 host 72.163.62.158 eq https 
access-list 110 extended permit tcp host 72.163.6.6 host 72.163.62.222 eq https 
access-list 110 extended permit tcp host 72.163.6.7 host 72.163.62.222 eq https 
access-list 110 extended permit tcp host 72.163.6.6 host 72.163.63.30 eq https 
access-list 110 extended permit tcp host 72.163.6.7 host 72.163.63.30 eq https 
access-list 110 extended permit tcp host 72.163.6.6 host 72.163.129.198 eq https 
access-list 110 extended permit tcp host 72.163.6.7 host 72.163.129.198 eq https 
access-list 110 extended permit tcp host 72.163.6.6 host 64.104.123.83 eq https 
access-list 110 extended permit tcp host 72.163.6.7 host 64.104.123.83 eq https 
access-list 110 extended permit tcp host 72.163.6.6 host 144.254.231.90 eq https 
access-list 110 extended permit tcp host 72.163.6.7 host 144.254.231.90 eq https 
access-list 110 extended permit tcp host 72.163.6.6 host 171.70.151.132 eq https 
access-list 110 extended permit tcp host 72.163.6.7 host 171.70.151.132 eq https 
access-list 110 extended permit tcp host 72.163.6.6 host 128.107.191.10 eq https 
access-list 110 extended permit tcp host 72.163.6.7 host 128.107.191.10 eq https 
access-list 110 extended permit udp host 10.66.129.135 host 171.71.180.230 range 2055 2070 
access-list 110 extended permit udp host 10.66.129.136 host 171.71.180.230 range 2055 2070 
access-list 110 extended permit esp any host 12.5.186.5 
access-list 110 extended permit udp any host 12.5.186.5 eq isakmp 
access-list 110 extended permit udp any host 12.5.186.5 eq 4500 
access-list 110 extended permit esp any host 12.159.148.27 
access-list 110 extended permit udp any host 12.159.148.27 eq isakmp 
access-list 110 extended permit udp any host 12.159.148.27 eq 4500 
access-list 110 extended permit udp host 65.221.127.67 any eq isakmp 
access-list 110 extended permit udp host 65.221.127.68 any eq isakmp 
access-list 110 extended permit esp host 65.221.127.67 any 
access-list 110 extended permit esp host 65.221.127.68 any 
access-list 110 extended permit udp host 63.117.49.4 any eq isakmp 
access-list 110 extended permit esp host 63.117.49.4 any 
access-list 110 extended permit tcp any host 12.5.186.4 eq https 
access-list 110 extended permit tcp any host 12.5.186.4 eq 8000 
access-list 110 extended permit tcp any host 144.254.220.149 eq https 
access-list 110 extended permit tcp any host 144.254.220.149 eq 8000 
access-list 110 extended permit tcp any host 192.118.79.36 eq https 
access-list 110 extended permit tcp any host 192.118.79.36 eq 8000 
access-list 110 extended permit esp any object-group ect-stld-1 
access-list 110 extended permit udp any object-group ect-stld-1 eq isakmp 
access-list 110 extended permit udp any object-group ect-stld-1 eq 4500 
access-list 110 extended permit tcp any host 64.104.229.3 eq 8000 
access-list 110 extended permit tcp any host 64.104.229.3 eq https 
access-list 110 extended permit esp host 64.104.252.227 host 10.66.33.2 
access-list 110 extended permit esp host 202.95.97.78 host 64.104.235.9 
access-list 110 extended permit esp host 202.95.84.204 host 64.104.235.9 
access-list 110 extended permit udp host 64.104.252.227 host 10.66.125.6 eq isakmp 
access-list 110 extended permit esp host 64.104.252.227 host 10.66.125.6 
access-list 110 extended permit tcp any host 64.104.82.6 eq https 
access-list 110 extended permit tcp any host 64.104.82.6 eq 8000 
access-list 110 extended permit tcp any host 64.104.15.228 eq https 
access-list 110 extended permit tcp any host 64.104.15.228 eq 8000 
access-list 110 extended permit tcp any host 64.104.123.18 eq https 
access-list 110 extended permit tcp any host 64.104.123.18 eq 8000 
access-list 110 extended permit tcp host 64.104.127.182 any eq domain 
access-list 110 extended permit icmp host 64.104.127.182 any echo 
access-list 110 extended permit tcp any host 64.104.229.4 eq https 
access-list 110 extended permit tcp any host 64.104.229.4 eq 8000 
access-list 110 extended permit tcp host 64.104.249.180 host 10.66.170.61 eq 5620 
access-list 110 extended permit tcp host 64.104.249.181 host 10.66.170.61 eq 5620 
access-list 110 extended permit tcp host 64.104.249.164 host 10.66.170.61 eq sip 
access-list 110 extended permit tcp host 64.104.249.173 host 10.66.170.61 eq sip 
access-list 110 extended permit tcp host 64.104.249.164 host 10.66.170.61 eq 8060 
access-list 110 extended permit tcp host 64.104.249.173 host 10.66.170.61 eq 8060 
access-list 110 extended permit tcp host 64.104.249.180 host 10.66.132.22 eq 5620 
access-list 110 extended permit tcp host 64.104.249.180 host 10.66.132.23 eq 5620 
access-list 110 extended permit tcp host 64.104.249.180 host 10.66.6.21 eq 5620 
access-list 110 extended permit tcp host 64.104.249.180 host 10.66.6.22 eq 5620 
access-list 110 extended permit tcp host 64.104.249.180 host 10.66.108.132 eq 5620 
access-list 110 extended permit tcp host 64.104.249.181 host 10.66.132.22 eq 5620 
access-list 110 extended permit tcp host 64.104.249.181 host 10.66.132.23 eq 5620 
access-list 110 extended permit tcp host 64.104.249.181 host 10.66.6.21 eq 5620 
access-list 110 extended permit tcp host 64.104.249.181 host 10.66.6.22 eq 5620 
access-list 110 extended permit tcp host 64.104.249.181 host 10.66.108.132 eq 5620 
access-list 110 extended permit tcp host 64.104.249.164 host 10.66.132.22 eq sip 
access-list 110 extended permit tcp host 64.104.249.164 host 10.66.132.23 eq sip 
access-list 110 extended permit tcp host 64.104.249.173 host 10.66.132.22 eq sip 
access-list 110 extended permit tcp host 64.104.249.173 host 10.66.132.23 eq sip 
access-list 110 extended permit tcp host 64.104.249.164 host 10.66.132.22 eq 8060 
access-list 110 extended permit tcp host 64.104.249.164 host 10.66.132.23 eq 8060 
access-list 110 extended permit tcp host 64.104.249.173 host 10.66.132.22 eq 8060 
access-list 110 extended permit tcp host 64.104.249.173 host 10.66.132.23 eq 8060 
access-list 110 extended permit tcp host 64.104.249.164 host 10.66.6.21 eq sip 
access-list 110 extended permit tcp host 64.104.249.164 host 10.66.6.22 eq sip 
access-list 110 extended permit tcp host 64.104.249.173 host 10.66.6.21 eq sip 
access-list 110 extended permit tcp host 64.104.249.173 host 10.66.6.22 eq sip 
access-list 110 extended permit tcp host 64.104.249.164 host 10.66.108.132 eq sip 
access-list 110 extended permit tcp host 64.104.249.164 host 10.66.108.134 eq sip 
access-list 110 extended permit tcp host 64.104.249.173 host 10.66.108.132 eq sip 
access-list 110 extended permit tcp host 64.104.249.173 host 10.66.108.134 eq sip 
access-list 110 extended permit tcp host 64.104.249.164 host 10.66.6.21 eq 8060 
access-list 110 extended permit tcp host 64.104.249.164 host 10.66.6.22 eq 8060 
access-list 110 extended permit tcp host 64.104.249.173 host 10.66.6.21 eq 8060 
access-list 110 extended permit tcp host 64.104.249.173 host 10.66.6.22 eq 8060 
access-list 110 extended permit tcp host 64.104.249.164 host 10.66.108.132 eq 8060 
access-list 110 extended permit tcp host 64.104.249.164 host 10.66.108.134 eq 8060 
access-list 110 extended permit tcp host 64.104.249.173 host 10.66.108.132 eq 8060 
access-list 110 extended permit tcp host 64.104.249.173 host 10.66.108.134 eq 8060 
access-list 110 extended permit esp 128.107.226.192 255.255.255.192 any 
access-list 110 extended permit gre 128.107.226.192 255.255.255.192 any 
access-list 110 extended permit udp 128.107.226.192 255.255.255.192 any eq isakmp 
access-list 110 extended permit udp 128.107.226.192 255.255.255.192 any eq 4500 
access-list 110 extended permit esp 128.107.237.192 255.255.255.192 any 
access-list 110 extended permit gre 128.107.237.192 255.255.255.192 any 
access-list 110 extended permit udp 128.107.237.192 255.255.255.192 any eq isakmp 
access-list 110 extended permit udp 128.107.237.192 255.255.255.192 any eq 4500 
access-list 110 extended permit gre host 128.107.235.30 host 10.77.114.97 
access-list 110 extended permit tcp host 128.107.80.77 host 10.194.106.90 range 6532 6537 
access-list 110 extended permit tcp host 128.107.80.77 host 10.194.106.91 range 6532 6537 
access-list 110 extended permit tcp host 64.102.240.12 host 10.89.242.3 eq 5443 
access-list 110 extended permit tcp host 64.102.240.12 host 10.89.242.3 eq 9080 
access-list 110 extended permit tcp host 128.107.86.98 host 10.194.106.181 range 6532 6537 
access-list 110 extended permit tcp host 128.107.86.98 host 10.194.106.182 range 6532 6537 
access-list 110 extended permit tcp host 128.107.86.99 host 10.194.106.183 range 6532 6537 
access-list 110 extended permit tcp host 128.107.86.99 host 10.194.106.184 range 6532 6537 
access-list 110 extended permit tcp host 128.107.86.100 host 10.194.107.180 range 6532 6537 
access-list 110 extended permit tcp host 128.107.86.100 host 10.194.107.181 range 6532 6537 
access-list 110 extended permit tcp host 128.107.86.101 host 10.194.107.182 range 6532 6537 
access-list 110 extended permit tcp host 128.107.86.101 host 10.194.107.183 range 6532 6537 
access-list 110 extended permit tcp host 128.107.86.102 host 10.194.107.184 range 6532 6537 
access-list 110 extended permit tcp host 128.107.86.102 host 10.194.107.185 range 6532 6537 
access-list 110 extended permit tcp host 128.107.80.73 host 172.27.204.150 range 5001 5008 
access-list 110 extended permit tcp host 128.107.80.73 host 172.27.204.151 range 5001 5008 
access-list 110 extended permit tcp host 128.107.80.73 host 172.27.204.152 range 5001 5008 
access-list 110 extended permit tcp host 128.107.80.73 host 172.27.204.153 range 5001 5008 
access-list 110 extended permit tcp host 128.107.80.73 host 172.27.204.150 range 6532 6539 
access-list 110 extended permit tcp host 128.107.80.73 host 172.27.204.151 range 6532 6539 
access-list 110 extended permit tcp host 128.107.80.73 host 172.27.204.152 range 6532 6539 
access-list 110 extended permit tcp host 128.107.80.73 host 172.27.204.153 range 6532 6539 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 5001 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 5002 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 5003 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 5004 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 5005 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 5006 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 5007 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 5008 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 6532 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 6533 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 6534 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 6535 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 6536 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 6537 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 6538 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 6539 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 5443 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 9080 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 15443 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 16532 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 19080 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 25443 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 26532 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 29080 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 35443 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 36532 
access-list 110 extended permit tcp host 128.107.80.73 object-group CUMA_internal-sjc-1 eq 39080 
access-list 110 extended permit esp 128.107.208.0 255.255.240.0 any 
access-list 110 extended permit esp 128.107.64.0 255.255.248.0 any 
access-list 110 extended permit esp 128.107.88.0 255.255.248.0 any 
access-list 110 extended permit udp host 128.107.225.26 host 172.17.153.17 eq snmp 
access-list 110 extended permit udp host 128.107.225.26 host 172.17.153.18 eq snmp 
access-list 110 extended permit udp host 64.104.252.101 host 10.66.129.35 eq snmp 
access-list 110 extended permit udp host 64.104.252.101 host 10.66.129.34 eq snmp 
access-list 110 extended permit udp host 64.103.38.4 host 10.61.32.8 eq snmp 
access-list 110 extended permit udp host 64.103.38.4 host 10.61.32.9 eq snmp 
access-list 110 extended permit udp host 64.103.38.5 host 10.61.32.8 eq snmp 
access-list 110 extended permit udp host 64.103.38.5 host 10.61.32.9 eq snmp 
access-list 110 extended permit udp host 192.118.76.50 host 10.56.223.129 eq snmp 
access-list 110 extended permit udp host 192.118.76.50 host 10.56.223.130 eq snmp 
access-list 110 extended permit udp host 192.118.76.51 host 10.56.223.129 eq snmp 
access-list 110 extended permit udp host 192.118.76.51 host 10.56.223.130 eq snmp 
access-list 110 extended permit udp object-group ispgw_loopbacks-tokyo-1 host 10.70.225.143 eq snmptrap 
access-list 110 extended permit udp object-group ispgw_loopbacks-tokyo-1 host 10.70.225.144 eq snmptrap 
access-list 110 extended permit udp object-group ispgw_loopbacks-tokyo-1 host 10.70.225.143 eq snmp 
access-list 110 extended permit udp object-group ispgw_loopbacks-tokyo-1 host 10.70.225.144 eq snmp 
access-list 110 extended permit tcp object-group ispgw_loopbacks-tokyo-1 host 10.70.225.144 eq bgp 
access-list 110 extended permit udp object-group ispgw_loopbacks-tokyo-1 host 10.70.225.143 eq 2055 
access-list 110 extended permit udp host 10.70.225.143 object-group ispgw_loopbacks-tokyo-1 eq snmp 
access-list 110 extended permit udp host 10.70.225.144 object-group ispgw_loopbacks-tokyo-1 eq snmp 
access-list 110 extended permit udp host 64.104.46.244 host 10.70.225.119 eq snmp 
access-list 110 extended permit udp host 64.104.46.244 host 10.70.225.120 eq snmp 
access-list 110 extended permit esp host 211.122.197.174 host 64.104.14.247 
access-list 110 extended permit udp host 211.122.197.174 host 64.104.14.247 eq isakmp 
access-list 110 extended permit esp host 114.179.84.158 host 64.104.14.247 
access-list 110 extended permit udp host 114.179.84.158 host 64.104.14.247 eq isakmp 
access-list 110 extended permit esp host 114.179.84.158 host 64.104.14.248 
access-list 110 extended permit udp host 114.179.84.158 host 64.104.14.248 eq isakmp 
access-list 110 extended permit udp host 10.70.225.115 host 171.71.180.230 range 2055 2065 
access-list 110 extended permit udp host 10.70.225.116 host 171.71.180.230 range 2055 2065 
access-list 110 extended permit udp host 173.37.148.188 host 10.101.206.43 eq snmp 
access-list 110 extended permit udp host 173.37.148.188 host 10.101.206.44 eq snmp 
access-list 110 extended permit udp host 173.37.148.189 host 10.101.206.43 eq snmp 
access-list 110 extended permit udp host 173.37.148.189 host 10.101.206.44 eq snmp 
access-list 110 extended permit udp host 173.36.112.68 host 10.123.20.65 eq snmp 
access-list 110 extended permit udp host 173.36.112.68 host 10.123.20.66 eq snmp 
access-list 110 extended permit udp host 10.64.63.24 host 72.163.192.111 eq 9995 
access-list 110 extended permit udp host 10.64.63.24 host 171.70.178.114 eq snmp 
access-list 110 extended permit udp host 10.64.63.24 host 171.70.178.109 eq snmp 
access-list 110 extended permit udp host 10.64.63.24 host 171.70.178.111 eq snmp 
access-list 110 extended permit udp host 10.64.63.24 host 171.70.178.110 eq snmp 
access-list 110 extended permit udp host 10.64.63.24 host 171.70.178.118 eq snmp 
access-list 110 extended permit udp host 10.64.63.24 host 173.37.114.201 eq snmp 
access-list 110 extended permit udp host 10.64.63.24 host 144.254.227.20 eq snmp 
access-list 110 extended permit udp host 10.64.63.24 host 144.254.68.9 eq snmp 
access-list 110 extended permit udp host 10.64.63.24 host 173.37.114.200 eq snmp 
access-list 110 extended permit udp host 10.64.63.24 host 72.163.192.53 eq snmp 
access-list 110 extended permit udp host 10.64.63.1 host 171.70.178.114 eq snmp 
access-list 110 extended permit udp host 10.64.63.1 host 171.70.178.109 eq snmp 
access-list 110 extended permit udp host 10.64.63.1 host 171.70.178.111 eq snmp 
access-list 110 extended permit udp host 10.64.63.1 host 171.70.178.110 eq snmp 
access-list 110 extended permit udp host 10.64.63.1 host 171.70.178.118 eq snmp 
access-list 110 extended permit udp host 10.64.63.1 host 173.37.114.201 eq snmp 
access-list 110 extended permit udp host 10.64.63.1 host 144.254.227.20 eq snmp 
access-list 110 extended permit udp host 10.64.63.1 host 144.254.68.9 eq snmp 
access-list 110 extended permit udp host 10.64.63.1 host 173.37.114.200 eq snmp 
access-list 110 extended permit udp host 10.64.63.1 host 72.163.192.53 eq snmp 
access-list 110 extended permit udp host 10.64.63.2 host 171.70.178.114 eq snmp 
access-list 110 extended permit udp host 10.64.63.2 host 171.70.178.109 eq snmp 
access-list 110 extended permit udp host 10.64.63.2 host 171.70.178.111 eq snmp 
access-list 110 extended permit udp host 10.64.63.2 host 171.70.178.110 eq snmp 
access-list 110 extended permit udp host 10.64.63.2 host 171.70.178.118 eq snmp 
access-list 110 extended permit udp host 10.64.63.2 host 173.37.114.201 eq snmp 
access-list 110 extended permit udp host 10.64.63.2 host 144.254.227.20 eq snmp 
access-list 110 extended permit udp host 10.64.63.2 host 144.254.68.9 eq snmp 
access-list 110 extended permit udp host 10.64.63.2 host 173.37.114.200 eq snmp 
access-list 110 extended permit udp host 10.64.63.2 host 72.163.192.53 eq snmp 
access-list 110 extended permit esp host 64.104.44.33 host 10.71.150.34 
access-list 110 extended permit udp host 64.104.44.33 host 10.71.150.34 eq isakmp 
access-list 110 extended permit gre host 64.104.44.97 host 10.66.139.124 
access-list 110 extended permit gre host 10.60.4.18 host 64.103.36.18 
access-list 110 extended permit esp host 125.209.121.42 host 64.103.35.61 
access-list 110 extended permit udp host 125.209.121.42 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 85.154.235.170 host 216.128.60.189 
access-list 110 extended permit udp host 85.154.235.170 host 216.128.60.189 eq isakmp 
access-list 110 extended permit esp host 64.104.44.33 host 10.71.150.58 
access-list 110 extended permit udp host 64.104.44.33 host 10.71.150.58 eq isakmp 
access-list 110 extended permit esp host 114.143.5.154 host 64.104.14.247 
access-list 110 extended permit udp host 114.143.5.154 host 64.104.14.247 eq isakmp 
access-list 110 extended permit udp host 114.143.5.154 host 64.104.14.247 eq 4500 
access-list 110 extended permit tcp host 10.75.225.8 host 128.107.239.93 eq bgp 
access-list 110 extended permit tcp host 10.68.1.7 host 128.107.239.93 eq bgp 
access-list 110 extended permit tcp host 64.104.159.129 host 128.107.239.93 eq bgp 
access-list 110 extended permit tcp host 10.56.72.33 host 128.107.239.93 eq bgp 
access-list 110 extended permit tcp host 10.70.65.103 host 128.107.239.93 eq bgp 
access-list 110 extended permit tcp host 10.86.230.65 host 128.107.239.93 eq bgp 
access-list 110 extended permit tcp host 128.107.239.93 host 10.70.65.103 eq bgp 
access-list 110 extended permit tcp host 128.107.239.93 host 10.56.72.33 eq bgp 
access-list 110 extended permit tcp host 128.107.239.93 host 10.86.230.65 eq bgp 
access-list 110 extended permit tcp host 128.107.239.93 host 10.75.225.8 eq bgp 
access-list 110 extended permit tcp host 128.107.239.93 host 64.104.159.129 eq bgp 
access-list 110 extended permit tcp host 128.107.239.93 host 10.68.1.7 eq bgp 
access-list 110 extended permit tcp host 128.107.239.93 host 10.58.15.225 eq bgp 
access-list 110 extended permit tcp host 128.107.239.93 host 10.59.15.225 eq bgp 
access-list 110 extended permit tcp host 10.59.15.225 host 128.107.239.93 eq bgp 
access-list 110 extended permit tcp host 128.107.239.102 host 10.32.0.254 eq bgp 
access-list 110 extended permit tcp host 128.107.239.102 host 172.26.242.10 eq bgp 
access-list 110 extended permit udp host 128.107.225.24 host 172.17.153.17 eq snmp 
access-list 110 extended permit udp host 128.107.225.24 host 172.17.153.18 eq snmp 
access-list 110 extended permit udp host 72.163.0.116 host 10.101.14.10 eq snmp 
access-list 110 extended permit udp host 72.163.0.116 host 10.101.14.11 eq snmp 
access-list 110 extended permit udp host 72.163.0.117 host 10.101.14.10 eq snmp 
access-list 110 extended permit udp host 72.163.0.117 host 10.101.14.11 eq snmp 
access-list 110 extended permit tcp 172.17.153.0 255.255.255.0 172.24.109.240 255.255.255.248 eq bgp 
access-list 110 extended permit tcp 172.17.153.0 255.255.255.0 172.24.109.232 255.255.255.248 eq bgp 
access-list 110 extended permit tcp 172.17.153.0 255.255.255.0 172.24.115.68 255.255.255.252 eq bgp 
access-list 110 extended permit tcp 172.17.153.0 255.255.255.0 172.24.112.196 255.255.255.252 eq bgp 
access-list 110 extended permit tcp 10.81.255.0 255.255.255.0 172.24.109.240 255.255.255.248 eq bgp 
access-list 110 extended permit tcp 10.81.255.0 255.255.255.0 172.24.109.232 255.255.255.248 eq bgp 
access-list 110 extended permit tcp 10.81.255.0 255.255.255.0 172.24.115.68 255.255.255.252 eq bgp 
access-list 110 extended permit tcp 10.81.255.0 255.255.255.0 172.24.112.196 255.255.255.252 eq bgp 
access-list 110 extended permit tcp host 192.168.203.201 host 172.17.153.63 eq bgp 
access-list 110 extended permit tcp host 10.56.72.33 host 172.17.153.63 eq bgp 
access-list 110 extended permit tcp host 10.59.15.225 host 172.17.153.63 eq bgp 
access-list 110 extended permit tcp host 64.104.159.129 host 172.17.153.63 eq bgp 
access-list 110 extended permit tcp host 64.104.159.131 host 172.17.153.63 eq bgp 
access-list 110 extended permit tcp host 10.75.225.8 host 172.17.153.63 eq bgp 
access-list 110 extended permit tcp host 10.75.225.193 host 172.17.153.63 eq bgp 
access-list 110 extended permit tcp host 10.75.225.194 host 172.17.153.63 eq bgp 
access-list 110 extended permit tcp host 10.68.1.7 host 172.17.153.63 eq bgp 
access-list 110 extended permit tcp host 10.86.230.65 host 172.17.153.63 eq bgp 
access-list 110 extended permit tcp host 10.70.65.103 host 172.17.153.63 eq bgp 
access-list 110 extended permit tcp host 172.17.153.63 object-group oer_bgp_gw-global-1 eq bgp 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.134.249 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.66.99 
access-list 110 extended permit gre host 64.103.36.18 host 10.49.217.250 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.66.101 
access-list 110 extended permit tcp host 64.104.252.229 host 10.66.129.10 eq bgp 
access-list 110 extended permit tcp object-group dmz_loopbacks-rich-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit icmp object-group dmz_loopbacks-isr-1 object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp object-group dmz_loopbacks-isr-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_loopbacks-isr-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_loopbacks-isr-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-isr-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-isr-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit icmp object-group dmz_loopbacks-singapore-1 object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp object-group dmz_loopbacks-singapore-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_loopbacks-singapore-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_loopbacks-singapore-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-singapore-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-singapore-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit icmp object-group dmz_loopbacks-hk-1 object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp object-group dmz_loopbacks-hk-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_loopbacks-hk-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_loopbacks-hk-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-hk-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-hk-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit icmp object-group dmz_loopbacks-bgl-1 object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp object-group dmz_loopbacks-bgl-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_loopbacks-bgl-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_loopbacks-bgl-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-bgl-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-bgl-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit icmp object-group dmz_loopbacks-japan-1 object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp object-group dmz_loopbacks-japan-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_loopbacks-japan-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_loopbacks-japan-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-japan-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-japan-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit icmp object-group dmz_loopbacks-aus-1 object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp object-group dmz_loopbacks-aus-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_loopbacks-aus-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_loopbacks-aus-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-aus-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-aus-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit icmp object-group dmz_loopbacks-ams-1 object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp object-group dmz_loopbacks-ams-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_loopbacks-ams-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_loopbacks-ams-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-ams-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-ams-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit icmp object-group ext_loopbacks_rtp object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp object-group ext_loopbacks_rtp object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group ext_loopbacks_rtp object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group ext_loopbacks_rtp object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-rtp-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group ext_loopbacks_rtp object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit icmp object-group dmz_loopbacks-global-1 object-group raex_subnets-global-1 
access-list 110 extended permit icmp object-group dmz_loopbacks-bxb-1 object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp object-group dmz_loopbacks-bxb-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_loopbacks-bxb-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_loopbacks-bxb-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-bxb-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-bxb-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-bxb-1 host 198.135.0.212 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-bxb-1 host 198.135.0.213 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-bxb-1 host 172.18.185.68 eq 2061 
access-list 110 extended permit icmp object-group dmz_loopbacks-rich-1 object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp object-group dmz_loopbacks-rich-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_loopbacks-rich-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_loopbacks-rich-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-rich-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-rich-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit icmp object-group dmz_loopbacks-brnt-1 object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp object-group dmz_loopbacks-brnt-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_loopbacks-brnt-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_loopbacks-brnt-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-brnt-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-brnt-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit icmp object-group dmz_loopbacks-sjc-1 object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp object-group dmz_loopbacks-sjc-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_loopbacks-sjc-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_loopbacks-sjc-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-sjc-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-sjc-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit icmp object-group dmz_loopbacks-vancouver-1 object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp object-group dmz_loopbacks-vancouver-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_loopbacks-vancouver-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_loopbacks-vancouver-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-vancouver-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-vancouver-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit icmp object-group dmz_loopbacks-rcdn9-1 object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp object-group dmz_loopbacks-rcdn9-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_loopbacks-rcdn9-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_loopbacks-rcdn9-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-rcdn9-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-rcdn9-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_networks-alln-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit icmp object-group dmz_loopbacks-alln-1 object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp object-group dmz_loopbacks-alln-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_loopbacks-alln-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_loopbacks-alln-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-alln-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-alln-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit icmp object-group dmz_loopbacks-shanghai-1 object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp object-group dmz_loopbacks-shanghai-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_loopbacks-shanghai-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_loopbacks-shanghai-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit udp object-group dmz_networks-shanghai-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp object-group dmz_loopbacks-shanghai-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit tcp object-group dmz_loopbacks-shanghai-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit tcp object-group dmz_networks-shanghai-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit udp object-group dmz_networks-aer01-1 object-group netflow_hosts-global-1 eq 2055 
access-list 110 extended permit udp 172.17.153.0 255.255.255.0 172.19.61.0 255.255.255.128 range 2055 2065 
access-list 110 extended permit udp 172.17.153.0 255.255.255.0 host 171.71.180.202 range 2055 2065 
access-list 110 extended permit udp host 10.68.12.7 host 171.71.180.202 range 2055 2065 
access-list 110 extended permit udp host 10.68.12.8 host 171.71.180.202 range 2055 2065 
access-list 110 extended permit udp host 10.68.1.7 host 10.68.3.177 eq 2055 
access-list 110 extended permit udp host 10.68.1.7 host 10.68.3.177 eq snmp 
access-list 110 extended permit udp host 10.68.1.7 host 10.68.3.179 eq snmp 
access-list 110 extended permit tcp host 10.68.1.7 host 10.68.3.179 eq bgp 
access-list 110 extended permit tcp host 128.107.233.108 host 10.81.242.247 eq 1710 
access-list 110 extended permit tcp host 128.107.233.108 host 10.81.242.247 eq h323 
access-list 110 extended permit tcp host 128.107.248.83 host 171.68.224.207 eq ldap 
access-list 110 extended permit tcp host 128.107.248.83 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp host 128.107.248.83 host 72.163.57.6 eq ldap 
access-list 110 extended permit tcp host 128.107.248.83 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp host 128.107.248.83 host 171.68.224.207 eq ldaps 
access-list 110 extended permit tcp host 128.107.248.83 host 171.71.184.6 eq ldaps 
access-list 110 extended permit tcp host 128.107.248.83 host 72.163.57.6 eq ldaps 
access-list 110 extended permit tcp host 128.107.248.83 host 64.102.9.230 eq ldaps 
access-list 110 extended permit tcp host 64.100.12.23 object-group ldap_dsx_servers-global-1 eq ldap 
access-list 110 extended permit tcp host 64.100.12.23 object-group ldap_dsx_servers-global-1 eq ldaps 
access-list 110 extended permit tcp host 64.100.12.24 object-group ldap_dsx_servers-global-1 eq ldap 
access-list 110 extended permit tcp host 64.100.12.24 object-group ldap_dsx_servers-global-1 eq ldaps 
access-list 110 extended permit tcp host 173.38.218.10 object-group ldap_dsx_servers-global-1 eq ldap 
access-list 110 extended permit tcp host 173.38.218.11 object-group ldap_dsx_servers-global-1 eq ldap 
access-list 110 extended permit tcp host 173.38.218.10 object-group ldap_dsx_servers-global-1 eq ldaps 
access-list 110 extended permit tcp host 173.38.218.11 object-group ldap_dsx_servers-global-1 eq ldaps 
access-list 110 extended permit tcp host 128.107.227.74 host 171.68.224.207 eq ldap 
access-list 110 extended permit tcp host 128.107.227.76 host 171.68.224.207 eq ldap 
access-list 110 extended permit tcp host 128.107.227.73 host 171.68.224.207 eq ldap 
access-list 110 extended permit tcp host 64.102.242.40 host 171.68.224.207 eq ldap 
access-list 110 extended permit tcp object-group mp_dmzdc-sjc-1 object-group mp_int_ldap-global-1 eq ldap 
access-list 110 extended permit tcp host 64.102.242.42 object-group mp_int_ldap-global-1 eq ldap 
access-list 110 extended permit tcp host 64.102.242.44 object-group mp_int_ldap-global-1 eq ldap 
access-list 110 extended permit tcp host 64.102.242.47 object-group mp_int_ldap-global-1 eq ldap 
access-list 110 extended permit tcp host 64.102.242.48 object-group mp_int_ldap-global-1 eq ldap 
access-list 110 extended permit tcp host 128.107.228.109 object-group mp_int_ldap-global-1 eq ldap 
access-list 110 extended permit tcp host 128.107.228.110 object-group mp_int_ldap-global-1 eq ldap 
access-list 110 extended permit tcp host 128.107.228.113 object-group mp_int_ldap-global-1 eq ldap 
access-list 110 extended permit tcp host 128.107.228.114 object-group mp_int_ldap-global-1 eq ldap 
access-list 110 extended permit tcp host 128.107.227.77 object-group mp_int_ldap-global-1 eq ldap 
access-list 110 extended permit tcp host 128.107.227.78 object-group mp_int_ldap-global-1 eq ldap 
access-list 110 extended permit tcp host 192.135.250.12 host 64.102.125.5 eq 13724 
access-list 110 extended permit tcp host 192.135.250.12 host 64.102.125.6 eq 13724 
access-list 110 extended permit tcp host 192.135.250.12 host 64.102.120.12 eq 13724 
access-list 110 extended permit tcp host 192.135.250.12 host 64.102.125.5 eq 13783 
access-list 110 extended permit tcp host 192.135.250.12 host 64.102.125.6 eq 13783 
access-list 110 extended permit tcp host 192.135.250.12 host 64.102.120.12 eq 13783 
access-list 110 extended permit tcp host 64.102.242.50 object-group mp_int_ldap-global-1 eq ldap 
access-list 110 extended permit tcp host 64.102.242.51 object-group mp_int_ldap-global-1 eq ldap 
access-list 110 extended permit esp host 64.100.9.36 any 
access-list 110 extended permit udp host 65.221.127.67 any eq 10000 
access-list 110 extended permit udp host 65.221.127.68 any eq 10000 
access-list 110 extended permit udp host 63.117.49.4 any eq 10000 
access-list 110 extended permit tcp host 65.221.127.67 any eq 10000 
access-list 110 extended permit tcp host 65.221.127.68 any eq 10000 
access-list 110 extended permit tcp host 63.117.49.4 any eq 10000 
access-list 110 extended permit tcp host 65.221.127.67 any eq 4500 
access-list 110 extended permit tcp host 65.221.127.68 any eq 4500 
access-list 110 extended permit tcp host 63.117.49.4 any eq 4500 
access-list 110 extended permit udp any host 64.102.223.98 eq 5247 
access-list 110 extended permit udp any host 64.102.223.99 eq 5246 
access-list 110 extended permit udp any host 64.102.223.99 eq 5247 
access-list 110 extended permit esp any object-group tac_vpn_concentrators-rtp-1 
access-list 110 extended permit udp any object-group tac_vpn_concentrators-rtp-1 eq isakmp 
access-list 110 extended permit udp any object-group tac_vpn_concentrators-rtp-1 eq 4500 
access-list 110 extended permit esp any host 64.102.156.97 
access-list 110 extended permit udp any host 64.102.156.97 eq isakmp 
access-list 110 extended permit udp any host 64.102.156.97 eq 4500 
access-list 110 extended permit gre any object-group tac_vpn_concentrators-rtp-1 
access-list 110 extended permit esp host 211.129.153.46 host 128.107.132.57 
access-list 110 extended permit udp host 211.129.153.46 host 128.107.132.57 eq isakmp 
access-list 110 extended permit esp host 211.129.153.46 host 128.107.130.212 
access-list 110 extended permit udp host 211.129.153.46 host 128.107.130.212 eq isakmp 
access-list 110 extended permit esp any 64.102.26.128 255.255.255.224 
access-list 110 extended permit gre any 64.102.26.128 255.255.255.224 
access-list 110 extended permit udp any 64.102.26.128 255.255.255.224 eq isakmp 
access-list 110 extended permit udp any 64.102.26.128 255.255.255.224 eq 10000 
access-list 110 extended permit udp any 64.102.26.128 255.255.255.224 eq 2746 
access-list 110 extended permit udp any 64.102.26.128 255.255.255.224 eq 4500 
access-list 110 extended permit tcp any 64.102.26.128 255.255.255.224 eq 4500 
access-list 110 extended permit tcp any 64.102.26.128 255.255.255.224 eq pptp 
access-list 110 extended permit tcp any host 64.100.53.240 eq smtp 
access-list 110 extended permit gre any 64.102.26.32 255.255.255.224 
access-list 110 extended permit esp any 64.102.26.32 255.255.255.224 
access-list 110 extended permit udp any 64.102.26.32 255.255.255.224 eq isakmp 
access-list 110 extended permit udp any 64.102.26.32 255.255.255.224 eq 10000 
access-list 110 extended permit udp any 64.102.26.32 255.255.255.224 eq 2746 
access-list 110 extended permit udp any 64.102.26.32 255.255.255.224 eq 4500 
access-list 110 extended permit tcp any 64.102.26.32 255.255.255.224 eq 4500 
access-list 110 extended permit tcp any 64.102.26.32 255.255.255.224 eq pptp 
access-list 110 extended permit gre host 64.102.240.233 10.97.0.0 255.255.0.0 
access-list 110 extended permit esp 64.100.13.0 255.255.255.0 any 
access-list 110 extended permit udp 64.100.13.0 255.255.255.0 any eq isakmp 
access-list 110 extended permit udp 64.100.13.0 255.255.255.0 any eq 4500 
access-list 110 extended permit esp host 64.102.255.129 any 
access-list 110 extended permit udp host 64.102.255.129 any eq isakmp 
access-list 110 extended permit udp host 64.102.255.129 any eq 4500 
access-list 110 extended permit esp 64.100.12.0 255.255.255.0 any 
access-list 110 extended permit udp 64.100.12.0 255.255.255.0 any eq isakmp 
access-list 110 extended permit udp 64.100.12.0 255.255.255.0 any eq 4500 
access-list 110 extended permit esp host 167.206.7.6 host 64.102.148.31 
access-list 110 extended permit esp host 74.128.1.100 host 64.102.148.31 
access-list 110 extended permit udp host 167.206.7.6 host 64.102.148.31 eq isakmp 
access-list 110 extended permit udp host 74.128.1.100 host 64.102.148.31 eq isakmp 
access-list 110 extended permit esp host 70.151.45.80 host 64.102.44.39 
access-list 110 extended permit udp host 70.151.45.80 host 64.102.44.39 eq isakmp 
access-list 110 extended permit esp 64.100.12.0 255.255.255.224 host 10.76.181.226 
access-list 110 extended permit udp 64.100.12.0 255.255.255.224 host 10.76.181.226 eq isakmp 
access-list 110 extended permit esp host 144.160.96.132 host 10.56.21.5 
access-list 110 extended permit udp host 144.160.96.132 host 10.56.21.5 eq isakmp 
access-list 110 extended permit udp host 144.160.96.132 host 10.56.21.5 eq 4500 
access-list 110 extended permit udp any host 192.118.79.6 eq 4500 
access-list 110 extended permit udp any host 192.118.79.7 eq 4500 
access-list 110 extended permit udp any host 192.118.79.8 eq 4500 
access-list 110 extended permit udp any host 192.118.79.9 eq 4500 
access-list 110 extended permit udp any host 196.25.175.35 eq 4500 
access-list 110 extended permit esp host 41.251.67.162 host 64.103.35.189 
access-list 110 extended permit udp host 41.251.67.162 host 64.103.35.189 eq isakmp 
access-list 110 extended permit udp host 41.251.67.162 host 64.103.35.189 eq 4500 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.136.104 
access-list 110 extended permit esp host 80.165.21.229 host 64.103.35.189 
access-list 110 extended permit udp host 80.165.21.229 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 80.88.249.25 host 216.128.60.189 
access-list 110 extended permit udp host 80.88.249.25 host 216.128.60.189 eq isakmp 
access-list 110 extended permit esp any host 144.254.220.197 
access-list 110 extended permit udp any host 144.254.220.197 eq isakmp 
access-list 110 extended permit udp any host 144.254.220.197 eq 4500 
access-list 110 extended permit esp any host 144.254.220.198 
access-list 110 extended permit udp any host 144.254.220.198 eq isakmp 
access-list 110 extended permit udp any host 144.254.220.198 eq 4500 
access-list 110 extended permit esp host 80.232.218.192 host 64.103.35.61 
access-list 110 extended permit udp host 80.232.218.192 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 196.207.241.49 host 64.103.35.61 
access-list 110 extended permit udp host 196.207.241.49 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 41.214.8.169 host 64.103.35.189 
access-list 110 extended permit udp host 41.214.8.169 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 62.153.117.154 host 64.103.35.61 
access-list 110 extended permit udp host 62.153.117.154 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 195.14.141.33 host 64.103.35.189 
access-list 110 extended permit udp host 195.14.141.33 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 82.149.94.42 host 64.103.35.61 
access-list 110 extended permit udp host 82.149.94.42 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 86.57.245.254 host 64.103.35.61 
access-list 110 extended permit udp host 86.57.245.254 host 64.103.35.61 eq 4500 
access-list 110 extended permit udp host 86.57.245.254 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 193.253.227.84 host 64.103.35.61 
access-list 110 extended permit udp host 193.253.227.84 host 64.103.35.61 eq isakmp 
access-list 110 extended permit udp host 193.253.227.84 host 64.103.35.61 eq 4500 
access-list 110 extended permit esp host 93.190.253.194 host 64.103.35.61 
access-list 110 extended permit udp host 93.190.253.194 host 64.103.35.61 eq isakmp 
access-list 110 extended permit udp any host 144.254.221.40 eq isakmp 
access-list 110 extended permit esp any host 144.254.221.40 
access-list 110 extended permit udp any host 144.254.221.40 eq 10000 
access-list 110 extended permit tcp any host 144.254.221.40 eq ssh 
access-list 110 extended permit tcp any host 144.254.221.40 eq https 
access-list 110 extended permit tcp host 64.103.39.10 host 10.34.192.10 eq sip 
access-list 110 extended permit tcp host 64.103.39.10 host 10.34.192.10 eq 5061 
access-list 110 extended permit udp host 64.103.39.4 host 10.32.0.46 eq 16384 
access-list 110 extended permit udp host 64.103.39.4 host 10.32.0.46 eq 16388 
access-list 110 extended permit udp host 64.103.39.3 host 10.32.0.46 eq 16384 
access-list 110 extended permit udp host 64.103.39.3 host 10.32.0.46 eq 16388 
access-list 110 extended permit udp host 80.65.75.37 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 80.65.75.37 host 64.103.35.189 
access-list 110 extended permit udp any host 144.254.221.37 eq 4500 
access-list 110 extended permit udp any host 144.254.221.38 eq 4500 
access-list 110 extended permit udp any host 144.254.221.39 eq 4500 
access-list 110 extended permit udp any host 144.254.221.40 eq 4500 
access-list 110 extended permit esp host 62.28.47.246 host 64.103.35.61 
access-list 110 extended permit udp host 62.28.47.246 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp any 144.254.10.160 255.255.255.224 
access-list 110 extended permit gre any 144.254.10.160 255.255.255.224 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.135.185 
access-list 110 extended permit esp host 196.20.69.18 host 64.103.35.189 
access-list 110 extended permit udp host 196.20.69.18 host 64.103.35.189 eq isakmp 
access-list 110 extended permit udp host 196.20.69.18 host 64.103.35.189 eq 4500 
access-list 110 extended permit gre host 64.103.36.241 host 10.48.100.66 
access-list 110 extended permit gre host 64.103.36.241 host 216.128.58.249 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.138.217 
access-list 110 extended permit esp host 89.162.145.2 host 64.103.35.61 
access-list 110 extended permit udp host 89.162.145.2 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 41.209.15.186 host 64.103.35.189 
access-list 110 extended permit udp host 41.209.15.186 host 64.103.35.189 eq isakmp 
access-list 110 extended permit gre host 64.103.36.241 host 216.128.59.121 
access-list 110 extended permit gre host 64.103.36.241 host 216.128.59.153 
access-list 110 extended permit esp host 80.88.240.250 host 216.128.60.189 
access-list 110 extended permit udp host 80.88.240.250 host 216.128.60.189 eq isakmp 
access-list 110 extended permit gre host 64.103.36.241 host 216.128.59.81 
access-list 110 extended permit esp host 195.239.129.234 host 64.103.35.61 
access-list 110 extended permit udp host 195.239.129.234 host 64.103.35.61 eq isakmp 
access-list 110 extended permit tcp host 64.104.249.130 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.104.249.130 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.104.249.130 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 64.104.249.131 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.104.249.131 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.104.249.131 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 64.104.249.132 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.104.249.132 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.104.249.132 host 171.70.144.143 eq https 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.140.249 
access-list 110 extended permit gre host 172.17.153.20 host 10.61.32.7 
access-list 110 extended permit gre host 172.17.153.20 host 10.70.225.102 
access-list 110 extended permit gre host 172.17.153.20 host 10.81.255.11 
access-list 110 extended permit gre host 172.17.153.20 host 10.66.129.17 
access-list 110 extended permit gre host 172.17.153.20 host 10.86.230.73 
access-list 110 extended permit gre host 172.17.153.20 host 10.89.255.196 
access-list 110 extended permit gre host 172.17.153.20 host 10.64.63.16 
access-list 110 extended permit gre host 10.61.32.7 host 172.17.153.20 
access-list 110 extended permit gre host 10.70.225.102 host 172.17.153.20 
access-list 110 extended permit gre host 10.81.255.11 host 172.17.153.20 
access-list 110 extended permit gre host 10.66.129.17 host 172.17.153.20 
access-list 110 extended permit gre host 10.86.230.73 host 172.17.153.20 
access-list 110 extended permit gre host 10.89.255.196 host 172.17.153.20 
access-list 110 extended permit gre host 10.64.63.16 host 172.17.153.20 
access-list 110 extended permit gre host 72.163.216.168 host 10.64.55.9 
access-list 110 extended permit gre host 72.163.216.168 host 10.76.1.21 
access-list 110 extended permit gre host 72.163.216.168 host 10.76.121.1 
access-list 110 extended permit gre host 72.163.216.168 host 10.76.236.1 
access-list 110 extended permit gre host 72.163.216.168 host 10.76.134.3 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.1.81 
access-list 110 extended permit gre host 64.104.127.65 host 10.74.162.129 
access-list 110 extended permit esp host 61.183.120.22 host 72.163.247.98 
access-list 110 extended permit udp host 61.183.120.22 host 72.163.247.98 eq isakmp 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.2.128 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.0.193 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.142.77 
access-list 110 extended permit gre host 72.163.216.168 host 10.64.55.7 
access-list 110 extended permit gre host 72.163.216.168 host 10.64.55.24 
access-list 110 extended permit gre host 72.163.216.168 host 10.104.17.4 
access-list 110 extended permit gre host 72.163.216.168 host 10.77.79.129 
access-list 110 extended permit gre host 72.163.216.168 host 10.78.207.195 
access-list 110 extended permit gre host 72.163.216.168 host 10.77.113.1 
access-list 110 extended permit gre host 72.163.216.168 host 10.77.114.97 
access-list 110 extended permit gre host 72.163.216.168 host 10.77.116.113 
access-list 110 extended permit gre host 72.163.216.168 host 10.77.120.209 
access-list 110 extended permit gre host 72.163.216.168 host 10.77.96.65 
access-list 110 extended permit gre host 72.163.216.168 host 10.77.105.1 
access-list 110 extended permit gre host 10.56.72.37 host 172.17.153.20 
access-list 110 extended permit gre host 172.17.153.20 host 10.56.72.37 
access-list 110 extended permit gre host 10.56.109.173 host 172.17.153.20 
access-list 110 extended permit gre host 10.56.109.173 host 172.17.153.65 
access-list 110 extended permit gre host 64.104.95.129 host 10.68.169.81 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.225.20 
access-list 110 extended permit gre host 64.104.127.65 10.74.65.128 255.255.255.128 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.0.64 
access-list 110 extended permit tcp host 72.163.217.18 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 72.163.217.19 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 72.163.217.20 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 72.163.217.18 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 72.163.217.19 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 72.163.217.20 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 72.163.217.18 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 72.163.217.19 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 72.163.217.20 host 171.70.144.143 eq https 
access-list 110 extended permit gre host 72.163.216.168 host 10.78.49.1 
access-list 110 extended permit gre host 72.163.216.168 host 10.76.112.65 
access-list 110 extended permit gre host 72.163.216.168 host 10.78.64.67 
access-list 110 extended permit gre host 72.163.216.168 host 10.76.144.129 
access-list 110 extended permit gre host 64.104.127.65 host 10.74.98.1 
access-list 110 extended permit gre host 10.75.32.1 host 64.104.127.65 
access-list 110 extended permit gre object-group microsoft_gre_support-sjc-1 host 171.69.86.80 
access-list 110 extended permit gre host 128.107.235.30 10.78.0.0 255.255.0.0 
access-list 110 extended permit gre host 128.107.235.30 10.64.0.0 255.254.0.0 
access-list 110 extended permit gre host 64.104.95.129 host 10.68.80.1 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.8.145 
access-list 110 extended permit gre host 64.104.95.129 host 10.68.97.7 
access-list 110 extended permit gre host 128.107.235.30 host 10.77.120.209 
access-list 110 extended permit gre host 128.107.235.30 host 10.78.207.195 
access-list 110 extended permit gre host 128.107.235.30 10.21.192.0 255.255.192.0 
access-list 110 extended permit gre host 128.107.235.30 host 10.92.96.3 
access-list 110 extended permit gre host 72.163.216.168 host 10.143.8.65 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.10.145 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.135.233 
access-list 110 extended permit gre host 64.103.36.241 host 10.52.245.39 
access-list 110 extended permit gre host 192.84.63.20 host 72.163.98.39 
access-list 110 extended permit gre host 192.58.227.70 host 72.163.98.39 
access-list 110 extended permit gre host 10.81.255.20 host 128.107.240.170 
access-list 110 extended permit gre host 64.104.44.97 host 10.141.3.161 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.128.25 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.139.249 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.140.137 
access-list 110 extended permit esp host 84.124.78.178 host 64.103.35.61 
access-list 110 extended permit udp host 84.124.78.178 host 64.103.35.61 eq isakmp 
access-list 110 extended permit udp host 41.250.250.139 host 64.103.35.189 eq isakmp 
access-list 110 extended permit udp host 41.250.250.139 host 64.103.35.189 eq 4500 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.130.153 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.140.49 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.137.211 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.140.25 
access-list 110 extended permit gre host 64.103.36.241 host 216.128.58.153 
access-list 110 extended permit gre host 64.103.36.241 host 10.113.20.1 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.141.177 
access-list 110 extended permit gre host 64.103.36.241 host 216.128.58.121 
access-list 110 extended permit gre host 64.103.36.241 host 10.50.31.33 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.138.89 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.131.153 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.128.89 
access-list 110 extended permit gre host 64.103.36.241 host 10.52.22.15 
access-list 110 extended permit gre host 64.103.36.241 host 10.51.39.241 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.139.121 
access-list 110 extended permit gre host 64.103.36.241 host 10.48.101.24 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.137.233 
access-list 110 extended permit esp host 195.97.150.221 host 64.103.35.61 
access-list 110 extended permit udp host 195.97.150.221 host 64.103.35.61 eq 4500 
access-list 110 extended permit udp host 195.97.150.221 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 88.43.51.42 host 64.103.35.61 
access-list 110 extended permit udp host 88.43.51.42 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 213.135.235.201 host 64.103.35.61 
access-list 110 extended permit udp host 213.135.235.201 host 64.103.35.61 eq isakmp 
access-list 110 extended permit udp host 213.135.235.201 host 64.103.35.61 eq 4500 
access-list 110 extended permit esp host 83.90.193.122 host 64.103.35.189 
access-list 110 extended permit udp host 83.90.193.122 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 195.222.180.118 host 64.103.35.61 
access-list 110 extended permit udp host 195.222.180.118 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 91.112.142.182 host 64.103.35.61 
access-list 110 extended permit udp host 91.112.142.182 host 64.103.35.61 eq isakmp 
access-list 110 extended permit tcp host 64.103.26.21 host 10.53.52.154 eq 5443 
access-list 110 extended permit tcp host 64.103.26.21 host 10.53.52.154 eq 6532 
access-list 110 extended permit tcp host 64.103.26.22 host 10.53.52.155 eq 5443 
access-list 110 extended permit tcp host 64.103.26.22 host 10.53.52.155 eq 6532 
access-list 110 extended permit tcp host 64.103.26.23 host 10.53.53.102 eq 5443 
access-list 110 extended permit tcp host 64.103.26.23 host 10.53.53.102 eq 6532 
access-list 110 extended permit tcp host 64.103.26.24 host 10.53.53.103 eq 5443 
access-list 110 extended permit tcp host 64.103.26.24 host 10.53.53.103 eq 6532 
access-list 110 extended permit esp 64.103.27.96 255.255.255.224 any 
access-list 110 extended permit esp host 64.103.27.69 any 
access-list 110 extended permit tcp host 64.103.26.98 host 10.53.40.13 eq 5443 
access-list 110 extended permit tcp host 64.103.26.98 host 10.53.40.13 eq 6532 
access-list 110 extended permit tcp host 64.103.26.98 host 10.53.40.13 eq 9443 
access-list 110 extended permit tcp host 64.103.26.98 host 10.53.40.13 eq 9080 
access-list 110 extended permit tcp host 64.103.26.98 host 10.53.40.13 eq 6443 
access-list 110 extended permit tcp host 64.103.26.115 host 10.53.40.13 eq 5443 
access-list 110 extended permit tcp host 64.103.26.115 host 10.53.40.13 eq 6532 
access-list 110 extended permit tcp host 64.103.26.115 host 10.53.40.13 eq 9443 
access-list 110 extended permit tcp host 64.103.26.115 host 10.53.40.13 eq 9080 
access-list 110 extended permit tcp host 64.103.26.115 host 10.53.40.13 eq 6443 
access-list 110 extended permit esp host 202.141.252.211 host 64.103.35.61 
access-list 110 extended permit udp host 202.141.252.211 host 64.103.35.61 eq isakmp 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.137.121 
access-list 110 extended permit tcp any host 64.103.37.210 eq ssh 
access-list 110 extended permit tcp host 64.103.37.170 host 128.107.191.10 eq https 
access-list 110 extended permit tcp host 64.103.37.170 host 128.107.191.32 eq https 
access-list 110 extended permit tcp host 64.103.37.170 host 128.107.191.114 eq https 
access-list 110 extended permit tcp host 64.103.37.170 host 72.163.56.102 eq ldaps 
access-list 110 extended permit tcp host 64.103.37.170 host 72.163.56.103 eq ldaps 
access-list 110 extended permit udp host 67.105.198.21 host 10.52.196.145 eq 36121 
access-list 110 extended permit tcp host 128.107.241.118 host 10.34.130.10 eq 2000 
access-list 110 extended permit udp host 128.107.241.118 host 10.34.130.10 eq tftp 
access-list 110 extended permit udp host 128.107.241.118 host 10.34.130.10 range 20480 32767 
access-list 110 extended permit tcp host 128.107.82.105 host 128.107.201.136 eq 2776 
access-list 110 extended permit tcp host 128.107.82.105 host 128.107.201.136 eq 7006 
access-list 110 extended permit udp host 128.107.82.105 host 128.107.201.136 eq 2776 
access-list 110 extended permit udp host 128.107.82.105 host 128.107.201.136 eq 2777 
access-list 110 extended permit udp host 128.107.82.105 host 128.107.201.136 eq 6006 
access-list 110 extended permit tcp host 128.107.82.105 host 10.35.202.2 eq 2776 
access-list 110 extended permit tcp host 128.107.82.105 host 10.35.202.2 eq 7006 
access-list 110 extended permit udp host 128.107.82.105 host 10.35.202.2 eq 2776 
access-list 110 extended permit udp host 128.107.82.105 host 10.35.202.2 eq 2777 
access-list 110 extended permit udp host 128.107.82.105 host 10.35.202.2 eq 6006 
access-list 110 extended permit udp any host 64.102.252.36 eq 5246 
access-list 110 extended permit udp any host 64.102.252.36 eq 5247 
access-list 110 extended permit udp any host 64.102.252.37 eq 5246 
access-list 110 extended permit udp any host 64.102.252.37 eq 5247 
access-list 110 extended permit udp object-group sj_alpha_vcse object-group sj_alpha_vcs_control eq 2776 
access-list 110 extended permit udp object-group sj_alpha_vcse object-group sj_alpha_vcs_control eq 2777 
access-list 110 extended permit udp object-group sj_alpha_vcse object-group sj_alpha_vcs_control eq 6006 
access-list 110 extended permit tcp object-group sj_alpha_vcse object-group sj_alpha_vcs_control eq 2776 
access-list 110 extended permit tcp object-group sj_alpha_vcse object-group sj_alpha_vcs_control eq 7006 
access-list 110 extended permit object-group VCSE-TO-VCSC object-group sj_alpha_vcs_express object-group sj_alpha_vcs_control 
access-list 110 extended permit udp object-group sj_alpha_vcs_express host 10.35.63.114 eq 902 
access-list 110 extended permit udp object-group sj_alpha_vcs_express host 10.35.63.134 eq 902 
access-list 110 extended permit tcp object-group sj_alpha_vcs_express host 10.35.63.114 eq 902 
access-list 110 extended permit tcp object-group sj_alpha_vcs_express host 10.35.63.134 eq 902 
access-list 110 extended permit tcp host 128.107.85.189 range 40000 49999 host 10.35.126.29 eq ldaps 
access-list 110 extended permit tcp host 128.107.85.181 host 10.35.63.127 eq 5061 
access-list 110 extended permit tcp host 128.107.85.190 host 10.35.63.127 eq 5061 
access-list 110 extended permit tcp any object-group V4-ACE-ORION-SERVERS eq https 
access-list 110 extended permit tcp any object-group V4-ACE-ORION-SERVERS eq www 
access-list 110 extended permit tcp host 128.107.83.81 host 171.70.121.14 eq 2000 
access-list 110 extended permit tcp host 128.107.83.81 host 171.70.121.14 eq 2443 
access-list 110 extended permit tcp host 128.107.83.81 host 171.70.121.14 eq sip 
access-list 110 extended permit tcp host 128.107.83.81 host 171.70.121.14 eq 5061 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.1.15 eq 2000 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.1.15 eq 2443 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.1.15 eq sip 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.1.15 eq 5061 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.1.16 eq 2000 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.1.16 eq 2443 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.1.16 eq sip 
access-list 110 extended permit tcp host 128.107.83.81 host 10.35.1.16 eq 5061 
access-list 110 extended permit tcp host 128.107.83.80 host 171.70.121.11 eq 3804 
access-list 110 extended permit udp host 128.107.83.80 host 171.70.121.12 eq tftp 
access-list 110 extended permit tcp host 128.107.83.81 host 171.70.121.13 eq 2000 
access-list 110 extended permit tcp host 128.107.83.81 host 171.70.121.13 eq 2443 
access-list 110 extended permit tcp host 128.107.83.81 host 171.70.121.13 eq sip 
access-list 110 extended permit tcp host 128.107.83.81 host 171.70.121.13 eq 5061 
access-list 110 extended permit tcp host 64.104.94.171 host 10.68.3.55 eq 2000 
access-list 110 extended permit tcp host 64.104.94.171 host 10.68.3.55 eq 2443 
access-list 110 extended permit tcp host 64.104.94.171 host 10.68.3.55 eq sip 
access-list 110 extended permit tcp host 64.104.94.171 host 10.68.3.55 eq 5061 
access-list 110 extended permit tcp host 64.104.94.170 host 10.68.3.51 eq 3804 
access-list 110 extended permit udp host 64.104.94.170 host 10.68.3.53 eq tftp 
access-list 110 extended permit udp host 64.104.94.62 any range 1024 65535 
access-list 110 extended permit udp host 64.104.94.171 host 10.68.3.57 eq 2000 
access-list 110 extended permit udp host 64.104.94.171 host 10.68.3.57 eq 2443 
access-list 110 extended permit udp host 64.104.94.171 host 10.68.3.57 eq sip 
access-list 110 extended permit udp host 64.104.94.171 host 10.68.3.57 eq 5061 
access-list 110 extended permit tcp host 128.107.235.195 host 10.32.134.145 eq 61004 
access-list 110 extended permit tcp host 128.107.235.197 host 10.32.134.145 eq 61004 
access-list 110 extended permit tcp host 128.107.235.195 host 10.32.134.145 eq 5003 
access-list 110 extended permit tcp host 128.107.235.197 host 10.32.134.145 eq 5003 
access-list 110 extended permit udp host 128.107.235.195 host 10.32.134.145 eq ntp 
access-list 110 extended permit tcp host 128.107.235.198 host 10.35.169.45 eq 61004 
access-list 110 extended permit tcp host 128.107.235.199 host 10.35.169.45 eq 61004 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 72.163.58.103 eq 15100 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 72.163.58.103 eq 15200 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 72.163.58.103 eq 15480 
access-list 110 extended permit tcp any host 171.70.192.1 eq https 
access-list 110 extended permit tcp any host 171.70.192.1 eq 8000 
access-list 110 extended permit tcp any host 12.159.148.26 eq https 
access-list 110 extended permit tcp any host 12.159.148.26 eq 8000 
access-list 110 extended permit tcp host 198.135.3.61 host 10.86.76.97 eq 5443 
access-list 110 extended permit tcp host 198.135.3.61 host 10.86.76.97 eq 9080 
access-list 110 extended permit tcp host 198.135.3.61 host 10.86.76.97 eq 9443 
access-list 110 extended permit tcp host 198.135.3.61 host 10.86.76.97 eq https 
access-list 110 extended permit esp any host 198.135.0.167 
access-list 110 extended permit udp any host 198.135.0.167 eq isakmp 
access-list 110 extended permit udp any host 198.135.0.167 eq 4500 
access-list 110 extended permit udp any host 198.135.0.167 eq 10000 
access-list 110 extended permit tcp any host 198.135.0.167 eq ssh 
access-list 110 extended permit esp any host 198.135.0.168 
access-list 110 extended permit udp any host 198.135.0.168 eq isakmp 
access-list 110 extended permit udp any host 198.135.0.168 eq 4500 
access-list 110 extended permit udp any host 198.135.0.168 eq 10000 
access-list 110 extended permit tcp any host 198.135.0.168 eq ssh 
access-list 110 extended permit tcp any host 64.102.253.75 eq https 
access-list 110 extended permit tcp any host 64.102.253.75 eq 8000 
access-list 110 extended permit tcp host 198.133.219.45 host 64.102.9.123 range 2035 2044 
access-list 110 extended permit tcp host 198.133.219.45 host 64.102.9.124 range 2035 2044 
access-list 110 extended permit tcp host 198.133.219.46 host 64.102.9.123 range 2035 2044 
access-list 110 extended permit tcp host 198.133.219.46 host 64.102.9.124 range 2035 2044 
access-list 110 extended permit tcp host 128.107.74.136 host 72.163.57.38 eq 1600 
access-list 110 extended permit tcp host 128.107.74.137 host 72.163.57.38 eq 1600 
access-list 110 extended permit tcp host 128.107.74.138 host 72.163.57.38 eq 1600 
access-list 110 extended permit tcp host 128.107.233.36 object-group skinny_cm-alpha-1 eq 2000 
access-list 110 extended permit udp host 128.107.233.36 object-group skinny_cm-alpha-1 eq tftp 
access-list 110 extended permit udp host 128.107.233.36 object-group skinny-alpha-1 range 20480 32767 
access-list 110 extended permit udp host 128.107.83.1 host 172.19.61.51 eq 2055 
access-list 110 extended permit udp host 128.107.83.2 host 172.19.61.51 eq 2055 
access-list 110 extended permit tcp 128.107.226.128 255.255.255.224 171.70.170.0 255.255.255.224 eq 8888 
access-list 110 extended permit udp object-group dmz_loopbacks-ams-1 host 10.61.2.140 range 2055 2065 
access-list 110 extended permit udp host 10.66.129.135 host 171.71.180.230 range 2055 2065 
access-list 110 extended permit udp host 10.66.129.136 host 171.71.180.230 range 2055 2065 
access-list 110 extended permit udp 10.61.32.0 255.255.255.224 host 144.254.226.12 range 2055 2065 
access-list 110 extended permit udp host 172.17.251.12 host 144.254.226.12 range 2055 2065 
access-list 110 extended permit udp host 10.59.15.227 host 144.254.226.12 range 2055 2065 
access-list 110 extended permit udp host 10.56.72.35 host 144.254.226.12 range 2055 2065 
access-list 110 extended permit udp 10.61.32.0 255.255.255.224 host 144.254.73.99 range 2055 2065 
access-list 110 extended permit udp host 172.17.251.12 host 144.254.73.99 range 2055 2065 
access-list 110 extended permit udp host 10.59.15.227 host 144.254.73.99 range 2055 2065 
access-list 110 extended permit udp host 10.56.72.35 host 144.254.73.99 range 2055 2065 
access-list 110 extended permit esp host 196.219.213.129 host 144.254.146.9 
access-list 110 extended permit udp host 196.219.213.129 host 144.254.146.9 eq isakmp 
access-list 110 extended permit udp host 196.219.213.129 host 144.254.146.9 eq 4500 
access-list 110 extended permit udp host 10.58.15.227 host 144.254.73.99 range 2055 2065 
access-list 110 extended permit tcp host 128.107.225.166 host 171.68.225.26 eq ldap 
access-list 110 extended permit tcp host 128.107.225.169 host 171.68.225.26 eq ldap 
access-list 110 extended permit tcp host 128.107.225.167 host 171.68.225.26 eq ldap 
access-list 110 extended permit tcp host 128.107.226.134 host 171.68.225.26 eq ldap 
access-list 110 extended permit tcp host 128.107.226.135 host 171.68.225.26 eq ldap 
access-list 110 extended permit tcp host 128.107.226.136 host 171.68.225.26 eq ldap 
access-list 110 extended permit tcp host 128.107.226.164 host 171.68.225.26 eq ldap 
access-list 110 extended permit tcp host 128.107.226.165 host 171.68.225.26 eq ldap 
access-list 110 extended permit tcp host 128.107.226.134 host 64.102.0.192 eq 9010 
access-list 110 extended permit tcp host 128.107.226.134 host 64.102.0.192 eq 9310 
access-list 110 extended permit tcp host 128.107.226.134 host 171.70.145.78 eq 9110 
access-list 110 extended permit tcp host 128.107.226.134 host 171.70.145.78 eq 9310 
access-list 110 extended permit tcp host 128.107.226.135 host 64.102.0.192 eq 9010 
access-list 110 extended permit tcp host 128.107.226.135 host 64.102.0.192 eq 9310 
access-list 110 extended permit tcp host 128.107.226.135 host 171.70.145.78 eq 9110 
access-list 110 extended permit tcp host 128.107.226.135 host 171.70.145.78 eq 9310 
access-list 110 extended permit tcp host 128.107.226.136 host 64.102.0.192 eq 9010 
access-list 110 extended permit tcp host 128.107.226.136 host 64.102.0.192 eq 9310 
access-list 110 extended permit tcp host 128.107.226.136 host 171.70.145.78 eq 9010 
access-list 110 extended permit tcp host 128.107.226.136 host 171.70.145.78 eq 9310 
access-list 110 extended permit tcp host 198.133.219.83 host 171.70.150.190 eq 9678 
access-list 110 extended permit tcp host 198.133.219.83 host 171.70.150.190 eq 9680 
access-list 110 extended permit tcp host 198.133.219.22 host 171.68.225.31 eq 5101 
access-list 110 extended permit tcp host 198.133.219.22 host 171.68.225.31 eq 9678 
access-list 110 extended permit tcp host 198.133.219.22 host 171.68.225.31 eq 9681 
access-list 110 extended permit tcp host 198.133.219.22 host 171.68.225.31 eq 9682 
access-list 110 extended permit tcp host 198.133.219.22 host 171.68.225.43 eq 5101 
access-list 110 extended permit tcp host 198.133.219.22 host 171.68.225.43 eq 9678 
access-list 110 extended permit tcp host 198.133.219.22 host 171.68.225.43 eq 9681 
access-list 110 extended permit tcp host 198.133.219.22 host 171.68.225.43 eq 9682 
access-list 110 extended permit esp host 82.135.246.248 host 64.103.35.61 
access-list 110 extended permit udp host 82.135.246.248 host 64.103.35.61 eq isakmp 
access-list 110 extended permit udp host 62.162.40.202 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 62.162.40.202 host 64.103.35.61 
access-list 110 extended permit gre host 128.107.240.24 host 12.5.186.16 
access-list 110 extended permit icmp host 128.107.240.24 host 12.5.186.16 echo 
access-list 110 extended permit icmp host 128.107.240.24 host 12.5.186.16 echo-reply 
access-list 110 extended permit gre host 12.5.186.16 host 128.107.240.24 
access-list 110 extended permit icmp host 12.5.186.16 host 128.107.240.24 echo 
access-list 110 extended permit icmp host 12.5.186.16 host 128.107.240.24 echo-reply 
access-list 110 extended permit tcp host 128.107.227.197 any eq domain 
access-list 110 extended permit udp host 128.107.227.197 any eq domain 
access-list 110 extended permit icmp host 128.107.227.197 any echo 
access-list 110 extended permit tcp host 72.163.4.28 any eq domain 
access-list 110 extended permit udp host 72.163.4.28 any eq domain 
access-list 110 extended permit icmp host 72.163.4.28 any echo 
access-list 110 extended permit tcp host 173.37.144.100 any eq domain 
access-list 110 extended permit udp host 173.37.144.100 any eq domain 
access-list 110 extended permit icmp host 173.37.144.100 any echo 
access-list 110 extended permit gre host 172.17.153.20 host 10.52.151.25 
access-list 110 extended permit gre host 172.17.153.65 host 10.52.151.26 
access-list 110 extended permit gre host 10.89.255.196 host 128.107.240.170 
access-list 110 extended permit gre host 10.86.230.73 host 128.107.240.170 
access-list 110 extended permit gre host 10.59.15.229 host 128.107.240.170 
access-list 110 extended permit gre host 10.56.72.37 host 128.107.240.170 
access-list 110 extended permit gre host 10.68.1.10 host 128.107.240.170 
access-list 110 extended permit gre host 10.75.225.201 host 128.107.240.170 
access-list 110 extended permit gre host 10.61.32.7 host 128.107.240.170 
access-list 110 extended permit gre host 10.81.255.11 host 128.107.240.170 
access-list 110 extended permit gre host 128.107.240.170 host 10.68.1.10 
access-list 110 extended permit icmp host 128.107.240.170 host 12.5.186.16 echo-reply 
access-list 110 extended permit icmp host 128.107.240.170 host 12.5.186.16 echo 
access-list 110 extended permit gre host 128.107.240.170 host 12.5.186.16 
access-list 110 extended permit gre host 128.107.240.170 host 10.75.225.201 
access-list 110 extended permit gre host 128.107.240.170 host 10.56.72.37 
access-list 110 extended permit gre host 128.107.240.170 host 10.64.63.16 
access-list 110 extended permit gre host 128.107.240.170 host 10.89.255.196 
access-list 110 extended permit gre host 128.107.240.170 host 10.86.230.73 
access-list 110 extended permit gre host 128.107.240.170 host 10.66.129.17 
access-list 110 extended permit gre host 128.107.240.170 host 10.81.255.11 
access-list 110 extended permit gre host 128.107.240.170 host 10.70.225.102 
access-list 110 extended permit gre host 128.107.240.170 host 10.61.32.7 
access-list 110 extended permit gre host 128.107.240.170 host 10.59.15.229 
access-list 110 extended permit gre host 10.64.63.16 host 128.107.240.170 
access-list 110 extended permit gre host 10.75.11.176 host 128.107.240.170 
access-list 110 extended permit gre host 10.70.225.102 host 128.107.240.170 
access-list 110 extended permit gre host 10.66.129.17 host 128.107.240.170 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.222.130 
access-list 110 extended permit gre host 64.104.127.60 host 10.75.222.146 
access-list 110 extended permit gre host 72.163.249.17 host 10.75.222.146 
access-list 110 extended permit esp any host 72.163.248.241 
access-list 110 extended permit udp any host 72.163.248.241 eq isakmp 
access-list 110 extended permit udp any host 72.163.248.241 eq 4500 
access-list 110 extended permit esp host 193.172.10.34 host 144.254.194.93 
access-list 110 extended permit udp host 193.172.10.34 host 144.254.194.93 eq 4500 
access-list 110 extended permit udp host 193.172.10.34 host 144.254.194.93 eq isakmp 
access-list 110 extended permit udp host 193.172.10.34 host 144.254.194.93 eq 10000 
access-list 110 extended permit esp any host 144.254.220.150 
access-list 110 extended permit udp any host 144.254.220.150 eq isakmp 
access-list 110 extended permit udp any host 144.254.220.150 eq 4500 
access-list 110 extended permit esp host 62.149.65.253 host 64.103.35.61 
access-list 110 extended permit udp host 62.149.65.253 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 62.149.65.253 host 64.103.35.189 
access-list 110 extended permit udp host 62.149.65.253 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 86.108.15.21 host 64.103.35.61 
access-list 110 extended permit esp host 86.108.15.21 host 64.103.35.189 
access-list 110 extended permit udp host 86.108.15.21 host 64.103.35.61 eq isakmp 
access-list 110 extended permit udp host 86.108.15.21 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 168.187.152.34 host 64.103.35.61 
access-list 110 extended permit udp host 168.187.152.34 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 212.123.18.140 host 64.103.35.189 
access-list 110 extended permit udp host 212.123.18.140 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 193.95.99.218 host 64.103.35.61 
access-list 110 extended permit udp host 193.95.99.218 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 61.91.245.114 host 64.104.88.231 
access-list 110 extended permit udp host 61.91.245.114 host 64.104.88.231 eq isakmp 
access-list 110 extended permit tcp any host 64.104.88.160 eq https 
access-list 110 extended permit udp any host 64.104.88.160 eq 443 
access-list 110 extended permit tcp host 64.104.94.36 host 10.68.3.51 range sip 5061 
access-list 110 extended permit tcp host 64.104.94.36 host 10.68.3.53 range sip 5061 
access-list 110 extended permit tcp host 64.104.94.36 host 10.68.3.55 range sip 5061 
access-list 110 extended permit tcp host 64.104.94.36 host 10.68.3.57 range sip 5061 
access-list 110 extended permit esp host 122.29.248.175 host 64.104.14.248 
access-list 110 extended permit udp host 122.29.248.175 host 64.104.14.248 eq isakmp 
access-list 110 extended permit esp host 202.139.138.209 host 64.104.14.249 
access-list 110 extended permit udp host 202.139.138.209 host 64.104.14.249 eq isakmp 
access-list 110 extended permit udp host 202.139.138.209 host 64.104.14.249 eq 4500 
access-list 110 extended permit esp object-group cognio_vpn_internal-rtp-1 object-group cognio_vpn_external-rtp-1 
access-list 110 extended permit udp object-group cognio_vpn_internal-rtp-1 object-group cognio_vpn_external-rtp-1 eq isakmp 
access-list 110 extended permit udp object-group cognio_vpn_internal-rtp-1 object-group cognio_vpn_external-rtp-1 eq 10000 
access-list 110 extended permit esp host 217.128.246.207 host 64.103.35.189 
access-list 110 extended permit udp host 217.128.246.207 host 64.103.35.189 eq isakmp 
access-list 110 extended permit gre host 64.104.95.129 host 10.68.178.3 
access-list 110 extended permit esp host 222.127.10.155 host 10.79.31.3 
access-list 110 extended permit udp host 222.127.10.155 host 10.79.31.3 eq isakmp 
access-list 110 extended permit udp host 222.127.10.155 host 10.79.31.3 eq 4500 
access-list 110 extended permit gre host 64.104.252.65 host 10.67.40.65 
access-list 110 extended permit gre host 64.104.252.65 host 10.66.232.81 
access-list 110 extended permit udp host 202.81.18.160 any eq 8889 
access-list 110 extended permit esp host 213.172.74.138 host 64.103.35.61 
access-list 110 extended permit udp host 213.172.74.138 host 64.103.35.61 eq isakmp 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.137.57 
access-list 110 extended permit esp host 213.172.74.138 host 64.103.35.189 
access-list 110 extended permit udp host 213.172.74.138 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 213.206.37.58 host 64.103.35.189 
access-list 110 extended permit udp host 213.206.37.58 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 88.204.128.194 host 64.103.35.189 
access-list 110 extended permit udp host 88.204.128.194 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 159.134.188.38 host 64.103.35.61 
access-list 110 extended permit udp host 159.134.188.38 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 159.134.188.38 host 64.103.35.189 
access-list 110 extended permit udp host 159.134.188.38 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 159.134.188.46 host 64.103.35.61 
access-list 110 extended permit udp host 159.134.188.46 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 159.134.188.46 host 64.103.35.189 
access-list 110 extended permit udp host 159.134.188.46 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 193.77.211.200 host 64.103.35.189 
access-list 110 extended permit udp host 193.77.211.200 host 64.103.35.189 eq isakmp 
access-list 110 extended permit tcp host 171.70.171.68 64.102.243.128 255.255.255.128 eq 1433 
access-list 110 extended permit gre host 128.107.240.24 host 10.68.1.10 
access-list 110 extended permit gre host 10.68.1.10 host 128.107.240.24 
access-list 110 extended permit tcp 128.107.74.16 255.255.255.240 host 171.70.144.188 eq smtp 
access-list 110 extended permit tcp 128.107.74.16 255.255.255.240 host 171.68.10.148 range 44441 44443 
access-list 110 extended permit tcp 128.107.74.16 255.255.255.240 host 64.102.7.21 range 44441 44443 
access-list 110 extended permit udp 128.107.74.16 255.255.255.240 host 171.68.10.150 eq ntp 
access-list 110 extended permit udp 128.107.74.16 255.255.255.240 host 171.68.10.80 eq ntp 
access-list 110 extended permit tcp 128.107.74.160 255.255.255.240 host 171.70.144.188 eq smtp 
access-list 110 extended permit tcp 128.107.74.160 255.255.255.240 host 171.68.10.148 range 44441 44443 
access-list 110 extended permit tcp 128.107.74.160 255.255.255.240 host 64.102.7.21 range 44441 44443 
access-list 110 extended permit udp 128.107.74.160 255.255.255.240 host 171.68.10.150 eq ntp 
access-list 110 extended permit udp 128.107.74.160 255.255.255.240 host 171.68.10.80 eq ntp 
access-list 110 extended permit tcp host 128.107.74.26 host 171.68.10.148 range 44441 44443 
access-list 110 extended permit tcp host 128.107.74.26 host 64.102.7.21 range 44441 44443 
access-list 110 extended permit tcp host 128.107.74.27 host 171.68.10.148 range 44441 44443 
access-list 110 extended permit tcp host 128.107.74.27 host 64.102.7.21 range 44441 44443 
access-list 110 extended permit tcp host 128.107.74.26 host 171.70.144.188 eq smtp 
access-list 110 extended permit tcp host 128.107.74.27 host 171.70.144.188 eq smtp 
access-list 110 extended permit esp host 80.235.29.114 host 64.103.35.189 
access-list 110 extended permit udp host 80.235.29.114 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 212.49.76.247 host 64.103.35.189 
access-list 110 extended permit udp host 212.49.76.247 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 212.49.76.247 host 64.103.35.61 
access-list 110 extended permit udp host 212.49.76.247 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 196.203.29.250 host 64.103.35.61 
access-list 110 extended permit udp host 196.203.29.250 host 64.103.35.61 eq isakmp 
access-list 110 extended permit udp any host 209.82.96.210 eq 4500 
access-list 110 extended permit udp 10.85.148.8 255.255.255.248 host 171.70.89.140 eq 9555 
access-list 110 extended permit esp 193.188.125.80 255.255.255.252 host 171.71.238.13 
access-list 110 extended permit udp 193.188.125.80 255.255.255.252 host 171.71.238.13 eq isakmp 
access-list 110 extended permit udp 193.188.125.80 255.255.255.252 host 171.71.238.13 eq 10000 
access-list 110 extended permit tcp 193.188.125.80 255.255.255.252 host 171.71.238.13 eq 10000 
access-list 110 extended permit gre 193.188.125.80 255.255.255.252 host 171.71.238.13 
access-list 110 extended permit esp 217.17.227.200 255.255.255.248 host 171.71.238.13 
access-list 110 extended permit udp 217.17.227.200 255.255.255.248 host 171.71.238.13 eq isakmp 
access-list 110 extended permit udp 217.17.227.200 255.255.255.248 host 171.71.238.13 eq 10000 
access-list 110 extended permit tcp 217.17.227.200 255.255.255.248 host 171.71.238.13 eq 10000 
access-list 110 extended permit gre 217.17.227.200 255.255.255.248 host 171.71.238.13 
access-list 110 extended permit esp 193.188.125.80 255.255.255.252 host 64.102.252.253 
access-list 110 extended permit udp 193.188.125.80 255.255.255.252 host 64.102.252.253 eq isakmp 
access-list 110 extended permit udp 193.188.125.80 255.255.255.252 host 64.102.252.253 eq 10000 
access-list 110 extended permit tcp 193.188.125.80 255.255.255.252 host 64.102.252.253 eq 10000 
access-list 110 extended permit gre 193.188.125.80 255.255.255.252 host 64.102.252.253 
access-list 110 extended permit esp 217.17.227.200 255.255.255.248 host 64.102.252.253 
access-list 110 extended permit udp 217.17.227.200 255.255.255.248 host 64.102.252.253 eq isakmp 
access-list 110 extended permit udp 217.17.227.200 255.255.255.248 host 64.102.252.253 eq 10000 
access-list 110 extended permit tcp 217.17.227.200 255.255.255.248 host 64.102.252.253 eq 10000 
access-list 110 extended permit gre 217.17.227.200 255.255.255.248 host 64.102.252.253 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.136.249 
access-list 110 extended permit gre host 144.254.136.249 host 64.103.36.241 
access-list 110 extended permit esp host 83.211.160.194 host 64.103.35.189 
access-list 110 extended permit udp host 83.211.160.194 host 64.103.35.189 eq isakmp 
access-list 110 extended permit tcp any host 144.254.213.17 eq 5443 
access-list 110 extended permit esp 192.133.204.0 255.255.255.0 any 
access-list 110 extended permit esp 192.133.198.0 255.255.254.0 any 
access-list 110 extended permit udp 192.133.204.0 255.255.255.0 any eq isakmp 
access-list 110 extended permit udp 192.133.198.0 255.255.254.0 any eq isakmp 
access-list 110 extended permit tcp 10.81.52.32 255.255.255.224 host 173.37.114.100 eq ssh 
access-list 110 extended permit tcp 10.81.52.32 255.255.255.224 host 64.100.52.226 eq ssh 
access-list 110 extended permit tcp 10.81.52.32 255.255.255.224 host 144.254.73.63 eq ssh 
access-list 110 extended permit udp 10.81.52.32 255.255.255.224 host 171.71.180.209 eq snmp 
access-list 110 extended permit udp 10.81.52.32 255.255.255.224 object-group snmp_managers-global-1 eq snmp 
access-list 110 extended permit tcp 10.81.52.32 255.255.255.224 host 171.71.177.236 eq smtp 
access-list 110 extended permit tcp 10.81.52.32 255.255.255.224 host 171.71.180.209 eq ftp 
access-list 110 extended permit tcp 10.81.52.32 255.255.255.224 host 171.71.180.209 eq ftp-data 
access-list 110 extended permit udp 10.81.52.32 255.255.255.224 any eq domain 
access-list 110 extended permit tcp 10.81.52.32 255.255.255.224 host 172.18.240.121 eq ssh 
access-list 110 extended permit tcp 10.81.52.32 255.255.255.224 host 172.18.240.122 eq ssh 
access-list 110 extended permit udp object-group dmz_networks-bgl-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-bgl-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit tcp object-group dmz_networks-bgl-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit udp object-group dmz_networks-bgl-1 object-group snmp_managers-global-1 eq domain 
access-list 110 extended permit udp object-group dmz_networks-bgl-1 object-group ntp_servers-global-1 eq ntp 
access-list 110 extended permit icmp object-group dmz_networks-bgl-1 object-group cisco_internal_networks-global-1 
access-list 110 extended permit udp host 72.163.216.245 host 10.64.63.11 eq snmp 
access-list 110 extended permit udp host 72.163.216.253 host 10.64.63.11 eq snmp 
access-list 110 extended permit udp host 72.163.216.245 host 10.64.63.12 eq snmp 
access-list 110 extended permit udp host 72.163.216.253 host 10.64.63.12 eq snmp 
access-list 110 extended permit udp 10.64.63.0 255.255.255.0 host 72.163.192.55 range 2055 2065 
access-list 110 extended permit udp 10.64.63.0 255.255.255.0 host 72.163.192.56 range 2055 2065 
access-list 110 extended permit udp 10.64.63.0 255.255.255.0 host 72.163.192.57 range 2055 2065 
access-list 110 extended permit gre host 128.107.235.30 host 10.104.17.4 
access-list 110 extended permit esp host 115.248.164.65 host 10.76.160.21 
access-list 110 extended permit udp host 115.248.164.65 host 10.76.160.21 eq isakmp 
access-list 110 extended permit udp host 115.248.164.65 host 10.76.160.21 eq 4500 
access-list 110 extended permit gre host 72.163.216.168 host 10.104.145.4 
access-list 110 extended permit gre host 72.163.216.168 host 10.77.17.1 
access-list 110 extended permit gre host 72.163.216.168 host 10.78.207.145 
access-list 110 extended permit gre host 72.163.216.168 host 10.66.139.124 
access-list 110 extended permit gre host 172.17.153.20 host 10.33.226.193 
access-list 110 extended permit gre host 172.17.153.65 host 10.33.226.193 
access-list 110 extended permit esp host 72.163.216.158 host 10.78.242.253 
access-list 110 extended permit ah host 72.163.216.158 host 10.78.242.253 
access-list 110 extended permit udp host 72.163.216.158 host 10.78.242.253 eq isakmp 
access-list 110 extended permit udp 10.64.63.0 255.255.255.0 host 64.103.129.33 range 2055 2065 
access-list 110 extended permit udp 10.64.63.0 255.255.255.0 host 64.103.129.34 range 2055 2065 
access-list 110 extended permit udp 10.64.63.0 255.255.255.0 host 64.103.129.35 range 2055 2065 
access-list 110 extended permit udp any host 72.163.215.43 eq 4500 
access-list 110 extended permit udp any host 72.163.130.103 eq 4500 
access-list 110 extended permit esp host 72.163.216.158 host 10.76.47.34 
access-list 110 extended permit udp host 72.163.216.158 host 10.76.47.34 eq isakmp 
access-list 110 extended permit tcp host 64.102.242.120 host 72.163.43.46 eq https 
access-list 110 extended permit esp host 220.227.79.140 host 10.76.160.21 
access-list 110 extended permit udp host 220.227.79.140 host 10.76.160.21 eq isakmp 
access-list 110 extended permit udp host 220.227.79.140 host 10.76.160.21 eq 4500 
access-list 110 extended permit tcp host 64.103.39.179 host 10.53.192.35 eq 5222 
access-list 110 extended permit tcp host 64.103.39.179 host 10.53.192.35 eq 5269 
access-list 110 extended permit tcp host 64.103.39.179 host 10.53.192.35 eq 5061 
access-list 110 extended permit tcp host 64.103.39.180 host 10.53.192.68 eq 5443 
access-list 110 extended permit gre host 10.61.32.15 host 10.53.41.98 
access-list 110 remark *** SJC KICKSTART SERVER ***
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 171.70.177.16 eq www 
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 173.37.113.172 eq www 
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 144.254.72.87 eq www 
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 171.70.177.16 eq https 
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 173.37.113.172 eq https 
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 144.254.72.87 eq https 
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 173.37.181.23 eq www 
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 gt 1023 host 173.37.181.23 gt 1023 
access-list 110 remark *** SJC Filer with WINES build files ***
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 171.70.150.194 eq 445 
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 171.70.150.194 eq netbios-ssn 
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 171.70.144.245 eq netbios-ssn 
access-list 110 remark *** SJC Altiris Service ***
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 171.68.46.115 eq 445 
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 171.68.46.115 eq netbios-ssn 
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 171.68.46.115 eq 402 
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 171.68.46.115 eq 415 
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 171.68.46.115 eq 4300 
access-list 110 extended permit tcp 10.28.69.128 255.255.255.128 host 171.68.46.115 eq 1119 
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 171.70.168.39 eq bootps 
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 171.70.168.40 eq bootps 
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 171.70.168.159 eq bootps 
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 171.70.168.39 eq bootpc 
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 171.70.168.40 eq bootpc 
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 171.70.168.159 eq bootpc 
access-list 110 remark *** SJC DNS service ***
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 171.70.168.183 eq domain 
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 171.70.168.155 eq domain 
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 171.70.168.167 eq domain 
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 171.68.226.120 eq domain 
access-list 110 remark *** RCDN DNS service ***
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 173.37.87.157 eq domain 
access-list 110 remark *** NETBIOS Name Service to SJC WINS ***
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 171.71.196.25 eq netbios-ns 
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 171.71.196.26 eq netbios-ns 
access-list 110 remark *** SJC NTP ***
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 10.81.254.131 eq ntp 
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 10.81.254.202 eq ntp 
access-list 110 remark *** Windows Boot - TFTP to filer ***
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 host 171.70.150.194 eq tftp 
access-list 110 remark *** Linux Build Ports ***
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 gt 1023 host 171.70.150.194 gt 1023 
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 gt 1023 host 171.70.144.245 gt 1023 
access-list 110 remark *** SJC / RCDN KICKSTART SERVER ***
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 171.70.177.16 eq www 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 173.37.113.172 eq www 
access-list 110 remark *** Filer with WINES build files ***
access-list 110 remark *** SJC Altiris Service ***
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 171.68.46.115 eq 445 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 171.68.46.115 eq netbios-ssn 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 171.68.46.115 eq 402 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 171.68.46.115 eq 415 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 171.68.46.115 eq 1119 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 171.68.46.115 eq 4300 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 72.163.42.112 eq bootps 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 72.163.42.113 eq bootps 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 72.163.42.112 eq bootpc 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 72.163.42.113 eq bootpc 
access-list 110 remark *** Corporate DNS server for EMAN ***
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 173.37.87.155 eq domain 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 173.37.87.156 eq domain 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 72.163.47.13 eq domain 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 72.163.47.14 eq domain 
access-list 110 remark *** Global DNS server LD.s
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 72.163.47.11 eq domain 
access-list 110 remark *** NETBIOS Name Service to WINS ***
access-list 110 remark *** NTP ***
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 10.81.254.131 eq ntp 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 10.81.254.202 eq ntp 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 171.70.168.183 eq domain 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 171.68.226.120 eq domain 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 object-group cisco_dns-global-1 eq domain 
access-list 110 extended permit udp 173.37.148.80 255.255.255.252 host 72.163.42.112 eq bootps 
access-list 110 extended permit udp 173.37.148.80 255.255.255.252 host 72.163.42.113 eq bootps 
access-list 110 extended permit udp 173.37.148.88 255.255.255.252 host 72.163.42.112 eq bootps 
access-list 110 extended permit udp 173.37.148.88 255.255.255.252 host 72.163.42.113 eq bootps 
access-list 110 extended permit udp 173.37.148.84 255.255.255.252 host 72.163.42.112 eq bootps 
access-list 110 extended permit udp 173.37.148.84 255.255.255.252 host 72.163.42.113 eq bootps 
access-list 110 extended permit udp 173.37.148.92 255.255.255.252 host 72.163.42.112 eq bootps 
access-list 110 extended permit udp 173.37.148.92 255.255.255.252 host 72.163.42.113 eq bootps 
access-list 110 extended permit udp 173.37.148.96 255.255.255.252 host 72.163.42.112 eq bootps 
access-list 110 extended permit udp 173.37.148.96 255.255.255.252 host 72.163.42.113 eq bootps 
access-list 110 extended permit udp 173.37.148.80 255.255.255.252 host 72.163.42.112 eq bootpc 
access-list 110 extended permit udp 173.37.148.80 255.255.255.252 host 72.163.42.113 eq bootpc 
access-list 110 extended permit udp 173.37.148.88 255.255.255.252 host 72.163.42.112 eq bootpc 
access-list 110 extended permit udp 173.37.148.88 255.255.255.252 host 72.163.42.113 eq bootpc 
access-list 110 extended permit udp 173.37.148.84 255.255.255.252 host 72.163.42.112 eq bootpc 
access-list 110 extended permit udp 173.37.148.84 255.255.255.252 host 72.163.42.113 eq bootpc 
access-list 110 extended permit udp 173.37.148.92 255.255.255.252 host 72.163.42.112 eq bootpc 
access-list 110 extended permit udp 173.37.148.92 255.255.255.252 host 72.163.42.113 eq bootpc 
access-list 110 extended permit udp 173.37.148.96 255.255.255.252 host 72.163.42.112 eq bootpc 
access-list 110 extended permit udp 173.37.148.96 255.255.255.252 host 72.163.42.113 eq bootpc 
access-list 110 remark *** SJC KICKSTART SERVER ***
access-list 110 extended permit tcp 10.61.46.128 255.255.255.128 host 171.70.177.16 eq www 
access-list 110 extended permit tcp 10.61.46.128 255.255.255.128 host 173.37.113.172 eq www 
access-list 110 extended permit tcp 10.61.46.128 255.255.255.128 host 144.254.72.87 eq www 
access-list 110 extended permit tcp 10.61.46.128 255.255.255.128 host 171.70.177.16 eq https 
access-list 110 extended permit tcp 10.61.46.128 255.255.255.128 host 173.37.113.172 eq https 
access-list 110 extended permit tcp 10.61.46.128 255.255.255.128 host 144.254.72.87 eq https 
access-list 110 remark *** Filer with WINES build files ***
access-list 110 extended permit tcp 10.61.46.128 255.255.255.128 host 144.254.230.48 eq netbios-ssn 
access-list 110 extended permit tcp 10.61.46.128 255.255.255.128 host 144.254.230.48 eq 445 
access-list 110 remark *** SJC Altiris Service ***
access-list 110 extended permit tcp 10.61.46.128 255.255.255.128 host 171.68.46.115 eq 445 
access-list 110 extended permit tcp 10.61.46.128 255.255.255.128 host 171.68.46.115 eq netbios-ssn 
access-list 110 extended permit tcp 10.61.46.128 255.255.255.128 host 171.68.46.115 eq 402 
access-list 110 extended permit tcp 10.61.46.128 255.255.255.128 host 171.68.46.115 eq 415 
access-list 110 extended permit tcp 10.61.46.128 255.255.255.128 host 171.68.46.115 eq 4300 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 144.254.71.154 eq bootps 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 144.254.71.155 eq bootps 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 144.254.71.154 eq bootpc 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 144.254.71.155 eq bootpc 
access-list 110 remark *** Corporate DNS server for EMAN ***
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 144.254.71.149 eq domain 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 144.254.71.150 eq domain 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 173.38.200.92 eq domain 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 173.38.200.93 eq domain 
access-list 110 remark *** Global DNS server LD.s
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 144.254.71.184 eq domain 
access-list 110 remark *** NETBIOS Name Service to WINS ***
access-list 110 remark *** NTP ***
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 10.81.254.131 eq ntp 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 10.81.254.202 eq ntp 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 144.254.230.48 eq tftp 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 gt 1023 host 144.254.230.48 gt 1023 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 171.70.168.183 eq domain 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 171.68.226.120 eq domain 
access-list 110 remark ****** allow TCP 1119 to Altris servers *******
access-list 110 extended permit tcp 10.61.46.128 255.255.255.128 host 171.68.46.115 eq 1119 
access-list 110 extended permit udp any host 171.70.157.76 eq domain 
access-list 110 extended permit udp any host 171.68.227.88 eq domain 
access-list 110 extended permit udp any host 171.70.144.28 eq domain 
access-list 110 extended permit udp any host 64.102.4.6 eq domain 
access-list 110 extended permit udp any host 64.102.19.210 eq domain 
access-list 110 extended permit udp any host 64.102.115.13 eq domain 
access-list 110 extended permit udp any host 144.254.15.110 eq domain 
access-list 110 extended permit udp any host 64.104.206.4 eq domain 
access-list 110 extended permit udp object-group dmz_loopbacks-global-1 any eq domain 
access-list 110 extended permit udp object-group dmz_networks-global-1 any eq domain 
access-list 110 extended deny udp any any eq domain 
access-list 110 extended permit udp any any eq domain 
access-list 110 extended permit udp any object-group ntp_servers-global-1 eq ntp 
access-list 110 extended permit tcp any host 64.102.253.193 eq 10000 
access-list 110 extended permit udp host 64.104.249.228 host 64.104.193.42 eq syslog 
access-list 110 extended permit udp host 64.104.249.228 host 171.70.139.31 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-ams-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-aus-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-japan-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-isr-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-singapore-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-hk-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-rtp-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-bxb-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-rich-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-brnt-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-sjc-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-vancouver-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-rcdn9-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-alln-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-shanghai-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-aer01-1 object-group eman_syslog-global-1 eq syslog 
access-list 110 extended permit udp object-group dmz_networks-ams-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_networks-aus-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_networks-japan-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_networks-isr-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_networks-singapore-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_networks-hk-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_networks-rtp-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_networks-bxb-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_networks-rich-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_networks-brnt-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_networks-sjc-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_networks-vancouver-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_networks-rcdn9-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_networks-alln-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_networks-shanghai-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit udp object-group dmz_networks-aer01-1 object-group snmp_managers-global-1 eq snmptrap 
access-list 110 extended permit tcp object-group dmz_networks-ams-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit tcp object-group dmz_networks-aus-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit tcp object-group dmz_networks-japan-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit tcp object-group dmz_networks-isr-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit tcp object-group dmz_networks-singapore-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit tcp object-group dmz_networks-hk-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit tcp object-group dmz_networks-rtp-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit tcp object-group dmz_networks-bxb-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit tcp object-group dmz_networks-brnt-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit tcp object-group dmz_networks-rich-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit tcp object-group dmz_networks-sjc-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit tcp object-group dmz_networks-vancouver-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit tcp object-group dmz_networks-rcdn9-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit tcp object-group dmz_networks-alln-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit tcp object-group dmz_networks-aer01-1 object-group tacacs_servers-global-1 eq tacacs 
access-list 110 extended permit udp object-group dmz_networks-aer01-1 object-group tftp_servers-global-1 eq tftp 
access-list 110 extended permit tcp 192.118.76.0 255.255.255.224 host 64.102.6.243 eq tacacs 
access-list 110 extended permit tcp 192.118.76.0 255.255.255.224 host 171.70.168.246 eq tacacs 
access-list 110 extended permit tcp 192.118.76.0 255.255.255.224 host 64.104.123.228 eq tacacs 
access-list 110 extended permit tcp 192.118.76.0 255.255.255.224 host 72.163.128.156 eq tacacs 
access-list 110 extended permit tcp 192.118.76.32 255.255.255.240 host 64.102.6.243 eq tacacs 
access-list 110 extended permit tcp 192.118.76.32 255.255.255.240 host 171.70.168.246 eq tacacs 
access-list 110 extended permit tcp 192.118.76.32 255.255.255.240 host 64.104.123.228 eq tacacs 
access-list 110 extended permit tcp 192.118.76.32 255.255.255.240 host 72.163.128.156 eq tacacs 
access-list 110 extended permit tcp 192.118.76.48 255.255.255.240 host 64.102.6.243 eq tacacs 
access-list 110 extended permit tcp 192.118.76.48 255.255.255.240 host 171.70.168.246 eq tacacs 
access-list 110 extended permit tcp 192.118.76.48 255.255.255.240 host 64.104.123.228 eq tacacs 
access-list 110 extended permit tcp 192.118.76.48 255.255.255.240 host 72.163.128.156 eq tacacs 
access-list 110 extended permit tcp 192.118.76.0 255.255.255.224 host 144.254.71.234 eq tacacs 
access-list 110 extended permit tcp 192.118.76.32 255.255.255.240 host 144.254.71.234 eq tacacs 
access-list 110 extended permit tcp 192.118.76.48 255.255.255.240 host 144.254.71.234 eq tacacs 
access-list 110 extended permit udp host 64.104.127.65 host 171.70.168.154 eq tftp 
access-list 110 extended permit udp host 64.104.95.129 host 171.70.168.154 eq tftp 
access-list 110 extended permit udp 12.46.104.0 255.255.254.0 any eq domain 
access-list 110 extended permit tcp 12.46.104.0 255.255.254.0 any eq domain 
access-list 110 extended permit tcp host 72.163.0.234 any eq domain 
access-list 110 extended permit icmp host 72.163.0.234 any echo 
access-list 110 extended permit tcp host 72.163.0.242 any eq domain 
access-list 110 extended permit icmp host 72.163.0.242 any echo 
access-list 110 extended permit tcp 198.133.219.0 255.255.255.0 host 171.70.168.183 eq domain 
access-list 110 extended permit tcp 198.133.219.0 255.255.255.0 host 171.68.226.120 eq domain 
access-list 110 extended permit tcp 198.133.219.0 255.255.255.0 host 64.102.6.247 eq domain 
access-list 110 extended permit udp object-group sciatl_dmz_bcp-sciatl-1 host 64.102.14.19 eq domain 
access-list 110 extended permit tcp host 64.102.245.52 host 64.102.14.14 eq smtp 
access-list 110 extended permit tcp host 64.102.245.52 host 64.102.14.14 eq 587 
access-list 110 extended permit tcp host 128.107.242.145 host 171.68.226.120 eq domain 
access-list 110 extended permit tcp host 128.107.242.145 host 171.70.168.183 eq domain 
access-list 110 extended permit tcp host 128.107.242.145 host 64.102.6.247 eq domain 
access-list 110 extended permit icmp any object-group cisco_internal_networks-global-1 echo-reply 
access-list 110 extended permit icmp any object-group cisco_internal_networks-global-1 unreachable 
access-list 110 extended permit icmp any object-group cisco_internal_networks-global-1 time-exceeded 
access-list 110 extended permit icmp any object-group cisco_internal_networks-global-1 parameter-problem 
access-list 110 extended deny icmp any any 
access-list 110 extended permit tcp host 64.103.38.235 host 10.63.224.21 eq 9080 
access-list 110 extended permit tcp host 128.107.227.11 host 171.70.168.154 eq ssh 
access-list 110 extended permit tcp host 128.107.227.12 host 171.70.168.154 eq ssh 
access-list 110 extended permit esp host 89.218.61.6 host 64.103.35.189 
access-list 110 extended permit udp host 89.218.61.6 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 91.212.94.99 host 64.103.35.61 
access-list 110 extended permit esp host 91.212.94.99 host 64.103.35.189 
access-list 110 extended permit udp host 91.212.94.99 host 64.103.35.61 eq isakmp 
access-list 110 extended permit udp host 91.212.94.99 host 64.103.35.61 eq 4500 
access-list 110 extended permit udp host 91.212.94.99 host 64.103.35.189 eq isakmp 
access-list 110 extended permit udp host 91.212.94.99 host 64.103.35.189 eq 4500 
access-list 110 extended permit udp any host 64.104.240.22 range 5246 5247 
access-list 110 extended permit udp any host 64.104.240.23 range 5246 5247 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.86.96 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.86.97 
access-list 110 extended permit udp host 144.254.51.152 range 5246 5247 any 
access-list 110 extended permit udp host 144.254.51.153 range 5246 5247 any 
access-list 110 extended permit udp host 64.100.13.106 range 5246 5247 any 
access-list 110 extended permit udp host 64.100.13.107 range 5246 5247 any 
access-list 110 extended permit udp host 64.100.2.3 range 5246 5247 any 
access-list 110 extended permit udp host 64.100.2.8 range 5246 5247 any 
access-list 110 extended permit udp host 64.100.2.9 range 5246 5247 any 
access-list 110 extended permit udp host 64.102.255.229 range 5246 5247 any 
access-list 110 extended permit udp host 64.103.27.135 range 5246 5247 any 
access-list 110 extended permit tcp any host 171.68.46.188 eq ssh 
access-list 110 extended deny tcp host 198.137.202.18 host 144.254.73.146 eq ssh 
access-list 110 extended deny tcp host 198.137.202.18 host 171.68.46.188 eq ssh 
access-list 110 extended permit gre host 64.104.127.65 host 10.79.89.226 
access-list 110 extended permit udp 173.38.154.32 255.255.255.224 10.50.176.0 255.255.240.0 range 50000 54999 
access-list 110 extended permit udp 173.38.154.32 255.255.255.224 10.50.176.0 255.255.240.0 eq 6001 
access-list 110 extended permit tcp 173.38.154.32 255.255.255.224 10.50.176.0 255.255.240.0 eq 2776 
access-list 110 extended permit tcp 173.38.154.32 255.255.255.224 10.50.176.0 255.255.240.0 eq 2777 
access-list 110 extended permit gre host 64.104.127.65 host 10.72.33.108 
access-list 110 extended permit tcp any object-group ndcs-nw-raex-ect object-group raex-ect-services_tcp 
access-list 110 extended permit 41 host 128.107.240.254 host 171.69.7.186 
access-list 110 extended permit 41 host 128.107.240.254 host 10.60.19.126 
access-list 110 extended permit tcp any host 171.70.192.4 eq https 
access-list 110 extended permit tcp any host 171.70.192.4 eq 8000 
access-list 110 extended permit udp host 198.133.219.83 host 171.68.225.107 eq 5101 
access-list 110 extended permit tcp host 198.133.219.83 host 171.68.225.107 eq 9678 
access-list 110 extended permit tcp host 198.133.219.83 host 171.68.225.107 eq 9680 
access-list 110 extended permit udp host 198.133.219.84 host 171.68.225.107 eq 5101 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 64.104.193.36 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 64.102.19.68 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 64.102.121.150 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 64.102.121.152 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 171.70.149.213 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 171.70.149.201 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 144.254.227.116 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 144.254.227.117 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 64.104.193.4 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 64.104.193.29 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 64.102.19.44 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 64.102.19.102 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 64.102.19.36 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 144.254.227.115 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 171.71.182.167 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 64.102.21.212 eq 577 
access-list 110 extended permit tcp object-group ipass_ext_hosts-global-1 host 64.104.193.89 eq 577 
access-list 110 extended permit tcp host 12.20.30.57 any eq citrix-ica 
access-list 110 extended permit tcp host 12.20.30.58 any eq citrix-ica 
access-list 110 extended permit tcp host 12.20.30.59 any eq citrix-ica 
access-list 110 extended permit udp host 12.20.30.57 any eq 1604 
access-list 110 extended permit udp host 12.20.30.58 any eq 1604 
access-list 110 extended permit udp host 12.20.30.59 any eq 1604 
access-list 110 extended permit tcp host 128.107.236.87 host 172.16.8.41 eq 5003 
access-list 110 extended permit tcp host 128.107.236.87 host 172.16.8.41 eq 5005 
access-list 110 extended permit tcp 128.107.242.128 255.255.255.128 host 172.17.44.5 eq 7222 
access-list 110 extended permit tcp host 128.107.226.136 172.17.44.0 255.255.255.240 eq 7222 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 144.254.72.87 eq www 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 144.254.72.87 eq https 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 144.254.72.87 eq www 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 144.254.72.87 eq https 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 144.254.72.87 eq www 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 144.254.72.87 eq https 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 171.70.177.16 eq www 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 171.70.177.16 eq https 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 171.70.177.16 eq www 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 171.70.177.16 eq https 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 171.70.177.16 eq https 
access-list 110 extended permit tcp 198.133.219.0 255.255.255.0 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp 198.133.219.0 255.255.255.0 host 64.102.9.230 eq ldaps 
access-list 110 extended permit tcp 198.133.219.0 255.255.255.0 host 72.163.57.6 eq ldap 
access-list 110 extended permit tcp 198.133.219.0 255.255.255.0 host 72.163.57.6 eq ldaps 
access-list 110 extended permit tcp host 128.107.226.136 host 172.17.44.5 eq 7222 
access-list 110 extended permit tcp host 128.107.236.83 host 172.16.8.47 eq 5003 
access-list 110 extended permit tcp host 128.107.236.83 host 172.16.8.47 eq 5005 
access-list 110 extended permit tcp host 128.107.236.84 host 172.16.8.47 eq 5003 
access-list 110 extended permit tcp host 128.107.236.84 host 172.16.8.47 eq 5005 
access-list 110 extended permit tcp host 128.107.236.85 host 172.16.8.47 eq 5003 
access-list 110 extended permit tcp host 128.107.236.85 host 172.16.8.47 eq 5005 
access-list 110 extended permit tcp host 198.133.219.34 object-group internal_smtp-global-1 eq smtp 
access-list 110 extended permit tcp host 198.133.219.101 object-group internal_smtp-global-1 eq smtp 
access-list 110 extended permit tcp host 198.133.219.107 object-group internal_smtp-global-1 eq smtp 
access-list 110 extended permit tcp object-group dmz_smtp-global-1 object-group internal_smtp-global-1 eq smtp 
access-list 110 extended permit tcp object-group dmzdc_dns_svr-sjc-1 host 171.70.148.99 eq 6795 
access-list 110 extended permit tcp object-group dmzdc_dns_svr-sjc-1 host 171.70.148.99 eq 6796 
access-list 110 extended permit tcp any object-group Corp_RA_VPN_Concentrators eq 10000 
access-list 110 extended permit udp any object-group Corp_RA_VPN_Concentrators eq 443 
access-list 110 extended permit esp any object-group vpn_concentrator-sing-1 
access-list 110 extended permit udp any object-group vpn_concentrator-sing-1 eq isakmp 
access-list 110 extended permit udp any object-group vpn_concentrator-sing-1 eq 10000 
access-list 110 extended permit tcp any object-group vpn_concentrator-sing-1 eq ssh 
access-list 110 extended permit tcp any object-group vpn_concentrator-sing-1 eq https 
access-list 110 extended permit udp any object-group vpn_concentrator-sing-1 eq 4500 
access-list 110 extended permit esp any object-group vpn_concentrator-hk-1 
access-list 110 extended permit udp any object-group vpn_concentrator-hk-1 eq isakmp 
access-list 110 extended permit udp any object-group vpn_concentrator-hk-1 eq 10000 
access-list 110 extended permit tcp any object-group vpn_concentrator-hk-1 eq ssh 
access-list 110 extended permit tcp any object-group vpn_concentrator-hk-1 eq https 
access-list 110 extended permit esp any object-group vpn_concentrator-bgl-1 
access-list 110 extended permit udp any object-group vpn_concentrator-bgl-1 eq isakmp 
access-list 110 extended permit udp any object-group vpn_concentrator-bgl-1 eq 10000 
access-list 110 extended permit tcp any object-group vpn_concentrator-bgl-1 eq ssh 
access-list 110 extended permit tcp any object-group vpn_concentrator-bgl-1 eq https 
access-list 110 extended permit esp any object-group vpn_concentrator-isr-1 
access-list 110 extended permit udp any object-group vpn_concentrator-isr-1 eq isakmp 
access-list 110 extended permit udp any object-group vpn_concentrator-isr-1 eq 10000 
access-list 110 extended permit tcp any object-group vpn_concentrator-isr-1 eq ssh 
access-list 110 extended permit tcp any object-group vpn_concentrator-isr-1 eq https 
access-list 110 extended permit esp any object-group vpn_concentrator-japan-1 
access-list 110 extended permit udp any object-group vpn_concentrator-japan-1 eq isakmp 
access-list 110 extended permit udp any object-group vpn_concentrator-japan-1 eq 10000 
access-list 110 extended permit tcp any object-group vpn_concentrator-japan-1 eq ssh 
access-list 110 extended permit tcp any object-group vpn_concentrator-japan-1 eq https 
access-list 110 extended permit esp any object-group vpn_concentrator-brnt-1 
access-list 110 extended permit udp any object-group vpn_concentrator-brnt-1 eq isakmp 
access-list 110 extended permit udp any object-group vpn_concentrator-brnt-1 eq 10000 
access-list 110 extended permit tcp any object-group vpn_concentrator-brnt-1 eq ssh 
access-list 110 extended permit tcp any object-group vpn_concentrator-brnt-1 eq https 
access-list 110 extended permit esp any object-group vpn_concentrator-syd-1 
access-list 110 extended permit udp any object-group vpn_concentrator-syd-1 eq isakmp 
access-list 110 extended permit udp any object-group vpn_concentrator-syd-1 eq 10000 
access-list 110 extended permit tcp any object-group vpn_concentrator-syd-1 eq https 
access-list 110 extended permit tcp any object-group vpn_concentrator-syd-1 eq ssh 
access-list 110 extended permit esp any object-group vpn_concentrator-rtp-1 
access-list 110 extended permit udp any object-group vpn_concentrator-rtp-1 eq isakmp 
access-list 110 extended permit udp any object-group vpn_concentrator-rtp-1 eq 10000 
access-list 110 extended permit tcp any object-group vpn_concentrator-rtp-1 eq https 
access-list 110 extended permit tcp any object-group vpn_concentrator-rtp-1 eq ssh 
access-list 110 extended permit esp any object-group vpn_ggsg_concentrator-rtp-1 
access-list 110 extended permit udp any object-group vpn_ggsg_concentrator-rtp-1 eq isakmp 
access-list 110 extended permit udp any object-group vpn_ggsg_concentrator-rtp-1 eq 10000 
access-list 110 extended permit tcp any object-group vpn_ggsg_concentrator-rtp-1 eq https 
access-list 110 extended permit tcp any object-group vpn_ggsg_concentrator-rtp-1 eq ssh 
access-list 110 extended permit esp any object-group vpn_concentrator-rich-1 
access-list 110 extended permit udp any object-group vpn_concentrator-rich-1 eq isakmp 
access-list 110 extended permit udp any object-group vpn_concentrator-rich-1 eq 10000 
access-list 110 extended permit tcp any object-group vpn_concentrator-rich-1 eq https 
access-list 110 extended permit tcp any object-group vpn_concentrator-rich-1 eq ssh 
access-list 110 extended permit esp host 220.225.32.3 host 10.76.160.21 
access-list 110 extended permit udp host 220.225.32.3 host 10.76.160.21 eq isakmp 
access-list 110 extended permit udp host 220.225.32.3 host 10.76.160.21 eq 4500 
access-list 110 extended permit udp any host 64.104.14.228 eq 4500 
access-list 110 extended permit udp any host 64.104.14.229 eq 4500 
access-list 110 extended permit udp any host 64.104.14.230 eq 4500 
access-list 110 extended permit esp host 91.151.226.5 host 64.103.35.189 
access-list 110 extended permit udp host 91.151.226.5 host 64.103.35.189 eq isakmp 
access-list 110 extended permit tcp any object-group vpn_concentrator-bgl-2 eq https 
access-list 110 extended permit tcp any object-group vpn_concentrator-bgl-2 eq ssh 
access-list 110 extended permit esp any object-group vpn_concentrator-bgl-2 
access-list 110 extended permit udp any object-group vpn_concentrator-bgl-2 eq isakmp 
access-list 110 extended permit udp any object-group vpn_concentrator-bgl-2 eq 4500 
access-list 110 extended permit udp any object-group vpn_concentrator-bgl-2 eq 10000 
access-list 110 extended permit udp host 202.175.105.18 host 64.104.123.9 eq isakmp 
access-list 110 extended permit esp host 202.175.105.18 host 64.104.123.9 
access-list 110 extended permit udp host 202.175.105.18 host 64.104.123.10 eq isakmp 
access-list 110 extended permit esp host 202.175.105.18 host 64.104.123.10 
access-list 110 extended permit esp host 61.142.98.129 host 72.163.247.99 
access-list 110 extended permit udp host 61.142.98.129 host 72.163.247.99 eq isakmp 
access-list 110 extended permit esp any host 64.104.121.244 
access-list 110 extended permit esp any host 64.104.121.245 
access-list 110 extended permit esp any host 64.104.121.246 
access-list 110 extended permit udp any host 64.104.121.244 eq isakmp 
access-list 110 extended permit udp any host 64.104.121.245 eq isakmp 
access-list 110 extended permit udp any host 64.104.121.246 eq isakmp 
access-list 110 extended permit udp any host 64.104.121.244 eq 10000 
access-list 110 extended permit udp any host 64.104.121.245 eq 10000 
access-list 110 extended permit udp any host 64.104.121.246 eq 10000 
access-list 110 extended permit tcp any host 64.104.121.244 eq ssh 
access-list 110 extended permit tcp any host 64.104.121.245 eq ssh 
access-list 110 extended permit tcp any host 64.104.121.246 eq ssh 
access-list 110 extended permit tcp any host 64.104.121.244 eq https 
access-list 110 extended permit tcp any host 64.104.121.245 eq https 
access-list 110 extended permit tcp any host 64.104.121.246 eq https 
access-list 110 extended permit esp any host 64.104.192.131 
access-list 110 extended permit udp any host 64.104.192.131 eq isakmp 
access-list 110 extended permit udp any host 64.104.192.131 eq 10000 
access-list 110 extended permit tcp any host 64.104.192.131 eq ssh 
access-list 110 extended permit tcp any host 64.104.192.131 eq https 
access-list 110 extended permit esp host 202.3.193.130 host 64.104.219.21 
access-list 110 extended permit udp host 202.3.193.130 host 64.104.219.21 eq isakmp 
access-list 110 extended permit esp host 165.228.215.186 host 64.104.213.240 
access-list 110 extended permit udp host 165.228.215.186 host 64.104.213.240 eq isakmp 
access-list 110 extended permit esp host 109.73.245.21 host 144.254.146.9 
access-list 110 extended permit udp host 109.73.245.21 host 144.254.146.9 eq isakmp 
access-list 110 extended permit esp host 109.73.245.17 host 144.254.146.9 
access-list 110 extended permit udp host 109.73.245.17 host 144.254.146.9 eq isakmp 
access-list 110 extended permit udp host 109.73.245.17 host 144.254.146.9 eq 4500 
access-list 110 extended permit esp host 222.252.12.10 host 64.104.88.231 
access-list 110 extended permit udp host 222.252.12.10 host 64.104.88.231 eq isakmp 
access-list 110 extended permit udp any host 64.104.88.228 eq 4500 
access-list 110 extended permit udp any host 64.104.88.229 eq 4500 
access-list 110 extended permit udp any host 64.104.88.230 eq 4500 
access-list 110 extended permit udp any host 12.5.186.34 eq 4500 
access-list 110 extended permit udp any host 12.5.186.35 eq 4500 
access-list 110 extended permit udp any host 12.5.186.36 eq 4500 
access-list 110 extended permit udp any host 64.104.142.3 eq 4500 
access-list 110 extended permit udp any host 64.104.142.5 eq 4500 
access-list 110 extended permit udp any host 64.104.142.6 eq 4500 
access-list 110 extended permit udp any host 64.104.192.129 eq 4500 
access-list 110 extended permit udp any host 64.104.192.130 eq 4500 
access-list 110 extended permit udp any host 64.104.192.131 eq 4500 
access-list 110 extended permit gre host 128.107.81.84 any 
access-list 110 extended permit gre host 10.101.14.26 any 
access-list 110 extended permit gre host 198.135.0.108 any 
access-list 110 extended permit gre host 72.163.216.168 host 10.142.16.241 
access-list 110 extended permit gre host 72.163.216.168 host 10.105.40.161 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.225.30 
access-list 110 extended permit tcp host 64.103.27.87 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp host 64.103.27.103 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp host 64.103.27.105 host 171.71.184.6 eq ldap 
access-list 110 extended permit tcp host 64.103.27.87 host 171.71.184.6 eq ldaps 
access-list 110 extended permit tcp host 64.103.27.103 host 171.71.184.6 eq ldaps 
access-list 110 extended permit tcp host 64.103.27.105 host 171.71.184.6 eq ldaps 
access-list 110 extended permit udp any host 64.104.123.4 eq 4500 
access-list 110 extended permit udp any host 64.104.123.5 eq 4500 
access-list 110 extended permit udp any host 64.104.123.6 eq 4500 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.143.41 
access-list 110 extended permit esp host 195.222.34.182 host 64.103.35.61 
access-list 110 extended permit udp host 195.222.34.182 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp any host 64.104.88.229 
access-list 110 extended permit udp any host 64.104.88.229 eq isakmp 
access-list 110 extended permit udp any host 64.104.88.229 eq 10000 
access-list 110 extended permit tcp any host 64.104.88.229 eq ssh 
access-list 110 extended permit tcp any host 64.104.88.229 eq https 
access-list 110 extended permit esp host 124.160.35.210 host 64.104.123.9 
access-list 110 extended permit udp host 124.160.35.210 host 64.104.123.9 eq isakmp 
access-list 110 extended permit esp host 124.160.35.210 host 72.163.247.98 
access-list 110 extended permit esp host 124.160.35.210 host 72.163.247.102 
access-list 110 extended permit udp host 124.160.35.210 host 72.163.247.98 eq isakmp 
access-list 110 extended permit udp host 124.160.35.210 host 72.163.247.102 eq isakmp 
access-list 110 extended permit esp any host 72.163.248.204 
access-list 110 extended permit udp any host 72.163.248.204 eq isakmp 
access-list 110 extended permit udp any host 72.163.248.204 eq 4500 
access-list 110 extended permit esp any host 72.163.248.205 
access-list 110 extended permit udp any host 72.163.248.205 eq isakmp 
access-list 110 extended permit udp any host 72.163.248.205 eq 4500 
access-list 110 extended permit esp host 14.37.25.250 host 64.104.14.232 
access-list 110 extended permit udp host 14.37.25.250 host 64.104.14.232 eq isakmp 
access-list 110 extended permit esp host 14.37.25.250 host 64.104.14.233 
access-list 110 extended permit udp host 14.37.25.250 host 64.104.14.233 eq isakmp 
access-list 110 extended permit esp any object-group asa_vpn-sjc-1 
access-list 110 extended permit udp any object-group asa_vpn-sjc-1 eq isakmp 
access-list 110 extended permit udp any object-group asa_vpn-sjc-1 eq 4500 
access-list 110 extended permit udp any object-group asa_vpn-sjc-1 eq 10000 
access-list 110 extended permit tcp any object-group asa_vpn-sjc-1 eq https 
access-list 110 extended permit tcp any object-group asa_vpn-sjc-1 eq ssh 
access-list 110 extended permit udp any host 171.70.192.86 eq 4500 
access-list 110 extended permit udp any host 171.70.192.87 eq 4500 
access-list 110 extended permit udp any host 171.70.192.90 eq 4500 
access-list 110 extended permit udp any host 171.70.192.89 eq 4500 
access-list 110 extended permit udp any host 171.70.192.83 eq 4500 
access-list 110 extended permit udp any host 171.70.192.88 eq 4500 
access-list 110 extended permit udp any host 171.70.192.80 eq 4500 
access-list 110 extended permit udp any host 171.70.192.82 eq 4500 
access-list 110 extended permit udp any host 171.70.192.73 eq 4500 
access-list 110 extended permit udp any host 171.70.192.81 eq 4500 
access-list 110 extended permit esp any host 171.70.192.44 
access-list 110 extended permit esp any host 171.70.192.45 
access-list 110 extended permit esp any host 171.70.192.46 
access-list 110 extended permit udp any host 171.70.192.44 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.45 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.46 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.44 eq 10000 
access-list 110 extended permit udp any host 171.70.192.45 eq 10000 
access-list 110 extended permit udp any host 171.70.192.46 eq 10000 
access-list 110 extended permit tcp any host 171.70.192.44 eq ssh 
access-list 110 extended permit tcp any host 171.70.192.45 eq ssh 
access-list 110 extended permit tcp any host 171.70.192.46 eq ssh 
access-list 110 extended permit tcp any host 171.70.192.44 eq https 
access-list 110 extended permit tcp any host 171.70.192.45 eq https 
access-list 110 extended permit tcp any host 171.70.192.46 eq https 
access-list 110 extended permit udp any host 171.70.192.44 eq 4500 
access-list 110 extended permit udp any host 171.70.192.45 eq 4500 
access-list 110 extended permit udp any host 171.70.192.46 eq 4500 
access-list 110 extended permit tcp host 128.107.235.198 host 10.35.169.45 eq 5003 
access-list 110 extended permit udp object-group sj_alpha_vcse object-group sj_alpha_vcs_control eq 6001 
access-list 110 extended permit esp any host 171.69.237.146 
access-list 110 extended permit udp any host 171.69.237.146 eq isakmp 
access-list 110 extended permit udp any host 171.69.237.146 eq 4500 
access-list 110 extended permit udp any object-group sjc_vpn_40-sjc-1 eq 4500 
access-list 110 extended permit udp any host 171.70.192.71 eq 4500 
access-list 110 extended permit udp any host 171.70.192.71 eq isakmp 
access-list 110 extended permit esp any host 171.70.192.71 
access-list 110 extended permit udp any host 171.70.192.71 eq 10000 
access-list 110 extended permit tcp any host 171.70.192.71 eq https 
access-list 110 extended permit tcp any host 171.70.192.71 eq ssh 
access-list 110 extended permit udp any host 171.70.192.71 eq 443 
access-list 110 extended permit udp any host 171.70.192.72 eq 4500 
access-list 110 extended permit udp any host 171.70.192.72 eq isakmp 
access-list 110 extended permit esp any host 171.70.192.72 
access-list 110 extended permit udp any host 171.70.192.72 eq 10000 
access-list 110 extended permit tcp any host 171.70.192.72 eq https 
access-list 110 extended permit tcp any host 171.70.192.72 eq ssh 
access-list 110 extended permit udp any host 171.70.192.72 eq 443 
access-list 110 extended permit udp any object-group vpn_concentrator-sjc-1 eq 10000 
access-list 110 extended permit udp any object-group vpn_concentrator-sjc-1 eq isakmp 
access-list 110 extended permit esp any object-group vpn_concentrator-sjc-1 
access-list 110 extended permit tcp any object-group vpn_concentrator-sjc-1 eq https 
access-list 110 extended permit tcp any object-group vpn_concentrator-sjc-1 eq ssh 
access-list 110 extended permit udp any object-group vpn_concentrator-sjc-1 eq 443 
access-list 110 extended permit esp any object-group vpn_concentrator_asa-bxb-1 
access-list 110 extended permit udp any object-group vpn_concentrator_asa-bxb-1 eq isakmp 
access-list 110 extended permit udp any object-group vpn_concentrator_asa-bxb-1 eq 4500 
access-list 110 extended permit udp any object-group vpn_concentrator_asa-bxb-1 eq 10000 
access-list 110 extended permit tcp any object-group vpn_concentrator_asa-bxb-1 eq https 
access-list 110 extended permit tcp any object-group vpn_concentrator_asa-bxb-1 eq ssh 
access-list 110 extended permit esp any host 198.135.0.177 
access-list 110 extended permit udp any host 198.135.0.177 eq isakmp 
access-list 110 extended permit udp any host 198.135.0.177 eq 4500 
access-list 110 extended permit tcp any host 198.135.0.178 eq https 
access-list 110 extended permit tcp any host 198.135.0.178 eq 8000 
access-list 110 extended permit tcp any host 198.135.0.179 eq https 
access-list 110 extended permit tcp any host 198.135.0.179 eq 8000 
access-list 110 extended permit esp any host 198.135.0.180 
access-list 110 extended permit udp any host 198.135.0.180 eq isakmp 
access-list 110 extended permit udp any host 198.135.0.180 eq 4500 
access-list 110 extended permit esp any host 198.135.0.181 
access-list 110 extended permit udp any host 198.135.0.181 eq isakmp 
access-list 110 extended permit udp any host 198.135.0.181 eq 4500 
access-list 110 extended permit esp any object-group vpn_concentrator-shn-1 
access-list 110 extended permit udp any object-group vpn_concentrator-shn-1 eq isakmp 
access-list 110 extended permit udp any object-group vpn_concentrator-shn-1 eq 4500 
access-list 110 extended permit udp any object-group vpn_concentrator-shn-1 eq 10000 
access-list 110 extended permit tcp any object-group vpn_concentrator-shn-1 eq https 
access-list 110 extended permit tcp any object-group vpn_concentrator-shn-1 eq ssh 
access-list 110 extended permit esp any object-group vpn_concentrator_crdc-shn-1 
access-list 110 extended permit udp any object-group vpn_concentrator_crdc-shn-1 eq isakmp 
access-list 110 extended permit udp any object-group vpn_concentrator_crdc-shn-1 eq 4500 
access-list 110 extended permit udp any object-group vpn_concentrator_crdc-shn-1 eq 10000 
access-list 110 extended permit tcp any object-group vpn_concentrator_crdc-shn-1 eq https 
access-list 110 extended permit tcp any object-group vpn_concentrator_crdc-shn-1 eq ssh 
access-list 110 extended permit esp any object-group vpn_concentrator_ect-shn-1 
access-list 110 extended permit udp any object-group vpn_concentrator_ect-shn-1 eq isakmp 
access-list 110 extended permit udp any object-group vpn_concentrator_ect-shn-1 eq 4500 
access-list 110 extended permit esp any host 171.70.192.89 
access-list 110 extended permit udp any host 171.70.192.89 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.89 eq 10000 
access-list 110 extended permit tcp any host 171.70.192.89 eq https 
access-list 110 extended permit tcp any host 171.70.192.89 eq ssh 
access-list 110 extended permit esp any host 171.70.192.81 
access-list 110 extended permit udp any host 171.70.192.81 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.81 eq 10000 
access-list 110 extended permit tcp any host 171.70.192.81 eq https 
access-list 110 extended permit tcp any host 171.70.192.81 eq ssh 
access-list 110 extended permit esp any host 171.70.192.90 
access-list 110 extended permit udp any host 171.70.192.90 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.90 eq 10000 
access-list 110 extended permit tcp any host 171.70.192.90 eq https 
access-list 110 extended permit tcp any host 171.70.192.90 eq ssh 
access-list 110 extended permit esp any host 171.70.192.85 
access-list 110 extended permit udp any host 171.70.192.85 eq 4500 
access-list 110 extended permit udp any host 171.70.192.85 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.85 eq 10000 
access-list 110 extended permit tcp any host 171.70.192.85 eq https 
access-list 110 extended permit tcp any host 171.70.192.85 eq ssh 
access-list 110 extended permit udp any host 171.70.192.80 eq isakmp 
access-list 110 extended permit esp any host 171.70.192.80 
access-list 110 extended permit udp any host 171.70.192.80 eq 10000 
access-list 110 extended permit tcp any host 171.70.192.80 eq https 
access-list 110 extended permit tcp any host 171.70.192.80 eq ssh 
access-list 110 extended permit tcp any host 171.70.192.86 eq https 
access-list 110 extended permit tcp any host 171.70.192.86 eq ssh 
access-list 110 extended permit tcp any host 171.70.192.87 eq https 
access-list 110 extended permit tcp any host 171.70.192.87 eq ssh 
access-list 110 extended permit tcp any host 171.70.192.88 eq https 
access-list 110 extended permit tcp any host 171.70.192.88 eq ssh 
access-list 110 extended permit esp any host 171.70.192.83 
access-list 110 extended permit udp any host 171.70.192.83 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.83 eq 10000 
access-list 110 extended permit esp any host 171.70.192.84 
access-list 110 extended permit udp any host 171.70.192.84 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.84 eq 10000 
access-list 110 extended permit udp any host 171.70.192.84 eq 4500 
access-list 110 extended permit tcp any host 171.70.192.84 eq https 
access-list 110 extended permit tcp any host 171.70.192.84 eq ssh 
access-list 110 extended permit esp any host 171.70.192.91 
access-list 110 extended permit udp any host 171.70.192.91 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.91 eq 10000 
access-list 110 extended permit udp any host 171.70.192.91 eq 4500 
access-list 110 extended permit tcp any host 171.70.192.91 eq https 
access-list 110 extended permit tcp any host 171.70.192.91 eq ssh 
access-list 110 extended permit esp any host 171.70.192.86 
access-list 110 extended permit udp any host 171.70.192.86 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.86 eq 10000 
access-list 110 extended permit esp any host 171.70.192.87 
access-list 110 extended permit udp any host 171.70.192.87 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.87 eq 10000 
access-list 110 extended permit esp any host 171.70.192.88 
access-list 110 extended permit udp any host 171.70.192.88 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.88 eq 10000 
access-list 110 extended permit tcp any object-group sjc_vpn_41-sjc-1 eq ssh 
access-list 110 extended permit udp any object-group sjc_vpn_41-sjc-1 eq isakmp 
access-list 110 extended permit esp any object-group sjc_vpn_41-sjc-1 
access-list 110 extended permit udp any object-group sjc_vpn_41-sjc-1 eq 4500 
access-list 110 extended permit udp any object-group sjc_vpn_41-sjc-1 eq 10000 
access-list 110 extended permit tcp any object-group sjc_vpn_41-sjc-1 eq https 
access-list 110 extended permit esp any host 171.70.35.81 
access-list 110 extended permit udp any host 171.70.35.81 eq isakmp 
access-list 110 extended permit udp any host 171.70.35.81 eq 4500 
access-list 110 extended permit udp any host 64.102.252.2 eq 4500 
access-list 110 extended permit udp any host 64.102.252.3 eq 4500 
access-list 110 extended permit udp any host 64.102.252.4 eq 4500 
access-list 110 extended permit udp any host 64.102.252.5 eq 4500 
access-list 110 extended permit udp any host 64.102.252.6 eq 4500 
access-list 110 extended permit udp any host 64.102.252.7 eq 4500 
access-list 110 extended permit udp any host 64.102.252.11 eq 4500 
access-list 110 extended permit udp any host 12.159.148.18 eq 4500 
access-list 110 extended permit udp any host 12.159.148.19 eq 4500 
access-list 110 extended permit udp any host 12.159.148.20 eq 4500 
access-list 110 extended permit udp any host 12.159.148.21 eq 4500 
access-list 110 extended permit esp any host 171.69.237.147 
access-list 110 extended permit tcp any host 171.70.192.73 eq https 
access-list 110 extended permit tcp any host 171.70.192.73 eq ssh 
access-list 110 extended permit esp any host 171.70.192.73 
access-list 110 extended permit udp any host 171.70.192.73 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.73 eq 10000 
access-list 110 extended permit esp host 205.128.1.35 host 64.102.57.50 
access-list 110 extended permit esp host 4.36.129.34 host 64.102.57.50 
access-list 110 extended permit udp host 205.128.1.35 host 64.102.57.50 eq isakmp 
access-list 110 extended permit udp host 4.36.129.34 host 64.102.57.50 eq isakmp 
access-list 110 extended permit esp host 163.251.239.60 host 64.102.57.56 
access-list 110 extended permit esp host 163.251.208.35 host 64.102.57.56 
access-list 110 extended permit udp host 163.251.239.60 host 64.102.57.56 eq 4500 
access-list 110 extended permit udp host 163.251.208.35 host 64.102.57.56 eq 4500 
access-list 110 extended permit esp any 64.103.12.128 255.255.255.240 
access-list 110 extended permit esp any host 128.107.200.82 
access-list 110 extended permit udp any host 128.107.200.82 eq 4500 
access-list 110 extended permit udp any host 128.107.200.82 eq isakmp 
access-list 110 extended permit tcp any host 64.102.252.53 eq https 
access-list 110 extended permit udp any host 64.102.252.53 eq 443 
access-list 110 extended permit tcp any host 64.102.252.53 eq 8000 
access-list 110 extended permit tcp any host 64.102.223.161 eq www 
access-list 110 extended permit tcp any host 64.102.223.161 eq https 
access-list 110 extended permit esp any host 128.107.200.81 
access-list 110 extended permit udp any host 128.107.200.81 eq 4500 
access-list 110 extended permit udp any host 128.107.200.81 eq isakmp 
access-list 110 extended permit esp any host 128.107.200.83 
access-list 110 extended permit udp any host 128.107.200.83 eq isakmp 
access-list 110 extended permit udp any host 128.107.200.83 eq 4500 
access-list 110 extended permit esp any host 128.107.200.84 
access-list 110 extended permit udp any host 128.107.200.84 eq isakmp 
access-list 110 extended permit udp any host 128.107.200.84 eq 4500 
access-list 110 extended permit esp any host 128.107.200.85 
access-list 110 extended permit udp any host 128.107.200.85 eq isakmp 
access-list 110 extended permit udp any host 128.107.200.85 eq 4500 
access-list 110 extended permit esp any host 64.102.223.161 
access-list 110 extended permit udp any host 64.102.223.161 eq 4500 
access-list 110 extended permit udp any host 64.102.223.161 eq isakmp 
access-list 110 extended permit tcp host 64.102.244.98 host 172.18.106.67 eq www 
access-list 110 extended permit tcp host 64.102.244.98 host 172.18.106.67 eq https 
access-list 110 extended permit tcp host 64.102.244.98 host 172.18.106.67 eq 1627 
access-list 110 extended permit tcp host 64.102.244.98 host 172.18.106.67 eq 5003 
access-list 110 extended permit tcp host 64.102.244.98 host 172.18.106.67 eq 61004 
access-list 110 extended permit tcp host 64.102.244.98 host 172.18.106.67 eq 1433 
access-list 110 extended permit udp host 64.102.244.98 host 172.18.106.67 eq ntp 
access-list 110 extended permit tcp host 64.102.244.98 host 172.18.106.68 eq www 
access-list 110 extended permit tcp host 64.102.244.98 host 172.18.106.68 eq https 
access-list 110 extended permit tcp host 64.102.244.98 host 172.18.106.68 eq 1627 
access-list 110 extended permit tcp host 64.102.244.98 host 172.18.106.68 eq 5003 
access-list 110 extended permit tcp host 64.102.244.98 host 172.18.106.68 eq 61004 
access-list 110 extended permit tcp host 64.102.244.98 host 172.18.106.68 eq 1433 
access-list 110 extended permit udp host 64.102.244.98 host 172.18.106.68 eq ntp 
access-list 110 extended permit tcp host 64.102.244.99 host 172.18.106.67 eq www 
access-list 110 extended permit tcp host 64.102.244.99 host 172.18.106.67 eq https 
access-list 110 extended permit tcp host 64.102.244.99 host 172.18.106.67 eq 1627 
access-list 110 extended permit tcp host 64.102.244.99 host 172.18.106.67 eq 5003 
access-list 110 extended permit tcp host 64.102.244.99 host 172.18.106.67 eq 61004 
access-list 110 extended permit tcp host 64.102.244.99 host 172.18.106.67 eq 1433 
access-list 110 extended permit udp host 64.102.244.99 host 172.18.106.67 eq ntp 
access-list 110 extended permit tcp host 64.102.244.99 host 172.18.106.68 eq www 
access-list 110 extended permit tcp host 64.102.244.99 host 172.18.106.68 eq https 
access-list 110 extended permit tcp host 64.102.244.99 host 172.18.106.68 eq 1627 
access-list 110 extended permit tcp host 64.102.244.99 host 172.18.106.68 eq 5003 
access-list 110 extended permit tcp host 64.102.244.99 host 172.18.106.68 eq 61004 
access-list 110 extended permit tcp host 64.102.244.99 host 172.18.106.68 eq 1433 
access-list 110 extended permit udp host 64.102.244.99 host 172.18.106.68 eq ntp 
access-list 110 extended permit esp any object-group ect-global-1 
access-list 110 extended permit udp any object-group ect-global-1 eq isakmp 
access-list 110 extended permit udp any object-group ect-global-1 eq 4500 
access-list 110 extended permit esp any host 171.68.223.5 
access-list 110 extended permit udp any host 171.68.223.5 eq isakmp 
access-list 110 extended permit udp any host 171.68.223.5 eq 4500 
access-list 110 extended permit tcp any host 128.107.200.76 eq https 
access-list 110 extended permit tcp any host 128.107.200.76 eq 8000 
access-list 110 extended permit esp any host 128.107.200.68 
access-list 110 extended permit udp any host 128.107.200.68 eq isakmp 
access-list 110 extended permit udp any host 128.107.200.68 eq 4500 
access-list 110 extended permit esp any host 128.107.200.70 
access-list 110 extended permit udp any host 128.107.200.70 eq isakmp 
access-list 110 extended permit udp any host 128.107.200.70 eq 4500 
access-list 110 extended permit tcp any host 128.107.200.70 eq https 
access-list 110 extended permit esp any host 128.107.200.97 
access-list 110 extended permit udp any host 128.107.200.97 eq isakmp 
access-list 110 extended permit udp any host 128.107.200.97 eq 4500 
access-list 110 extended permit udp any host 128.107.200.97 eq 848 
access-list 110 extended permit esp any host 128.107.200.98 
access-list 110 extended permit udp any host 128.107.200.98 eq isakmp 
access-list 110 extended permit udp any host 128.107.200.98 eq 4500 
access-list 110 extended permit udp any host 128.107.200.98 eq 848 
access-list 110 extended permit esp any host 128.107.200.100 
access-list 110 extended permit udp any host 128.107.200.100 eq isakmp 
access-list 110 extended permit udp any host 128.107.200.100 eq 4500 
access-list 110 extended permit udp any host 128.107.200.100 eq 848 
access-list 110 extended permit esp any host 128.107.200.65 
access-list 110 extended permit udp any host 128.107.200.65 eq isakmp 
access-list 110 extended permit udp any host 128.107.200.65 eq 4500 
access-list 110 extended permit esp any host 128.107.200.66 
access-list 110 extended permit udp any host 128.107.200.66 eq isakmp 
access-list 110 extended permit udp any host 128.107.200.66 eq 4500 
access-list 110 extended permit esp any host 128.107.200.67 
access-list 110 extended permit udp any host 128.107.200.67 eq isakmp 
access-list 110 extended permit udp any host 128.107.200.67 eq 4500 
access-list 110 extended permit tcp any host 128.107.200.67 eq https 
access-list 110 extended permit esp any host 128.107.200.69 
access-list 110 extended permit udp any host 128.107.200.69 eq isakmp 
access-list 110 extended permit udp any host 128.107.200.69 eq 4500 
access-list 110 extended permit esp any host 128.107.200.101 
access-list 110 extended permit udp any host 128.107.200.101 eq 4500 
access-list 110 extended permit udp any host 128.107.200.101 eq isakmp 
access-list 110 extended permit udp any host 72.163.198.202 range 5246 5247 
access-list 110 extended permit gre host 199.249.234.77 host 171.71.120.50 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.14 
access-list 110 extended permit gre host 64.103.36.241 host 10.62.58.177 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.138.97 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.142.105 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.97.250 
access-list 110 extended permit gre host 64.104.252.65 host 10.67.38.129 
access-list 110 extended permit gre host 10.66.129.144 host 172.17.153.20 
access-list 110 extended permit gre host 10.66.129.144 host 128.107.240.170 
access-list 110 extended permit tcp object-group auth_src-sjc-1 object-group auth_dest-sjc-1 eq https 
access-list 110 extended permit tcp host 64.104.94.66 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.104.94.67 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.104.94.68 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.104.94.66 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.104.94.67 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.104.94.68 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.104.94.66 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 64.104.94.67 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 64.104.94.68 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 64.104.249.138 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.104.249.139 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.104.249.140 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.104.249.138 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.104.249.139 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.104.249.140 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.104.249.138 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 64.104.249.139 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 64.104.249.140 host 171.70.144.143 eq https 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.5.225 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.6.225 
access-list 110 extended permit gre host 64.104.252.65 host 10.66.216.64 
access-list 110 extended permit gre any 64.103.12.128 255.255.255.240 
access-list 110 extended permit tcp any 64.103.12.128 255.255.255.240 eq pptp 
access-list 110 extended permit esp host 69.223.230.140 host 64.102.253.90 
access-list 110 extended permit udp host 69.223.230.140 host 64.102.253.90 eq isakmp 
access-list 110 extended permit esp host 69.223.230.140 host 64.102.253.94 
access-list 110 extended permit udp host 69.223.230.140 host 64.102.253.94 eq isakmp 
access-list 110 extended permit tcp any host 64.102.252.53 eq www 
access-list 110 extended permit tcp host 129.41.16.74 host 171.71.180.45 eq 8002 
access-list 110 extended permit esp any host 64.101.31.10 
access-list 110 extended permit udp any host 64.101.31.10 eq isakmp 
access-list 110 extended permit esp any host 64.101.31.6 
access-list 110 extended permit udp any host 64.101.31.6 eq isakmp 
access-list 110 extended permit esp host 69.178.6.1 host 64.101.31.6 
access-list 110 extended permit esp host 69.178.6.1 host 64.101.31.10 
access-list 110 extended permit udp host 69.178.6.1 host 64.101.31.6 eq isakmp 
access-list 110 extended permit udp host 69.178.6.1 host 64.101.31.10 eq isakmp 
access-list 110 extended permit esp host 67.105.95.188 host 64.101.31.6 
access-list 110 extended permit esp host 67.105.95.188 host 64.101.31.10 
access-list 110 extended permit udp host 67.105.95.188 host 64.101.31.6 eq isakmp 
access-list 110 extended permit udp host 67.105.95.188 host 64.101.31.10 eq isakmp 
access-list 110 extended permit esp host 216.239.45.18 host 171.71.177.220 
access-list 110 extended permit udp host 216.239.45.18 host 171.71.177.220 eq isakmp 
access-list 110 extended permit esp host 64.103.36.18 host 10.58.46.50 
access-list 110 extended permit udp host 64.103.36.18 host 10.58.46.50 eq isakmp 
access-list 110 extended permit esp any host 171.70.192.25 
access-list 110 extended permit udp any host 171.70.192.25 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.25 eq 10000 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 173.38.200.71 eq bootps 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 173.38.200.71 eq bootpc 
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 object-group kicker-global-1 eq tftp 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 object-group kicker-global-1 eq tftp 
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 object-group kicker-global-1 eq tftp 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 object-group kicker-global-1 eq tftp 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 object-group kicker-global-1 eq tftp 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 object-group kicker-global-1 eq tftp 
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 object-group kicker-global-1 eq 4011 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 object-group kicker-global-1 eq 4011 
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 object-group kicker-global-1 eq 4011 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 object-group kicker-global-1 eq 4011 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 object-group kicker-global-1 eq 4011 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 object-group kicker-global-1 eq 4011 
access-list 110 extended permit udp 10.28.65.128 255.255.255.128 gt 1023 object-group kicker-global-1 gt 1023 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 gt 1023 object-group kicker-global-1 gt 1023 
access-list 110 extended permit udp 10.28.69.128 255.255.255.128 gt 1023 object-group kicker-global-1 gt 1023 
access-list 110 extended permit udp 10.101.15.192 255.255.255.224 gt 1023 object-group kicker-global-1 gt 1023 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 gt 1023 object-group kicker-global-1 gt 1023 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 gt 1023 object-group kicker-global-1 gt 1023 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 171.68.46.115 eq 1119 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 173.37.113.172 eq www 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 64.100.35.35 eq www 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 144.254.226.58 eq www 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 173.37.113.172 eq https 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 64.100.35.35 eq https 
access-list 110 extended permit tcp 10.101.15.192 255.255.255.224 host 144.254.226.58 eq https 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 171.71.182.156 eq www 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 171.71.182.156 eq https 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 72.163.46.57 eq www 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 64.101.140.97 eq netbios-ssn 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 64.101.140.97 eq 445 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 171.68.46.115 eq 445 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 171.68.46.115 eq netbios-ssn 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 171.68.46.115 eq 402 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 171.68.46.115 eq 415 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 171.68.46.115 eq 4300 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 72.163.42.112 eq bootps 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 72.163.42.113 eq bootps 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 72.163.42.112 eq bootpc 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 72.163.42.113 eq bootpc 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 64.101.128.22 eq domain 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 64.101.128.23 eq domain 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 72.163.47.13 eq domain 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 72.163.47.14 eq domain 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 72.163.47.11 eq domain 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 64.101.140.238 eq netbios-ns 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 10.81.254.131 eq ntp 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 10.81.254.202 eq ntp 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 171.68.10.150 eq ntp 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 171.68.10.80 eq ntp 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 64.101.140.97 eq tftp 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 gt 1023 host 64.101.140.97 gt 1023 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 171.70.168.183 eq domain 
access-list 110 extended permit udp 10.101.167.0 255.255.255.128 host 171.68.226.120 eq domain 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 171.68.46.115 eq 1119 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 173.37.113.172 eq www 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 64.100.35.35 eq www 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 144.254.226.58 eq www 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 173.37.113.172 eq https 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 64.100.35.35 eq https 
access-list 110 extended permit tcp 10.101.167.0 255.255.255.128 host 144.254.226.58 eq https 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 171.71.182.156 eq www 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 72.163.46.57 eq www 
access-list 110 remark : 17July2010 | dunoland | INC000012716336 | cax01-dcz01n-build-vla86
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 173.37.113.172 eq https 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 171.71.182.156 eq https 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 64.100.35.35 eq www 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 64.100.35.35 eq https 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 144.254.226.58 eq www 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 144.254.226.58 eq https 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 64.101.140.97 eq netbios-ssn 
access-list 110 extended permit tcp 10.101.206.128 255.255.255.224 host 64.101.140.97 eq 445 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 64.101.140.238 eq netbios-ns 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 64.101.140.97 eq tftp 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 64.101.128.22 eq domain 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 64.101.128.23 eq domain 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 171.68.10.150 eq ntp 
access-list 110 extended permit udp 10.101.206.128 255.255.255.224 host 171.68.10.80 eq ntp 
access-list 110 extended permit tcp host 128.107.233.108 host 10.81.233.166 eq 1610 
access-list 110 extended permit tcp host 128.107.233.108 host 10.81.233.166 eq 1620 
access-list 110 extended permit esp any object-group ect-hk-1 
access-list 110 extended permit udp any object-group ect-hk-1 eq isakmp 
access-list 110 extended permit udp any object-group ect-hk-1 eq 4500 
access-list 110 extended permit tcp any host 64.104.123.22 eq www 
access-list 110 extended permit tcp any host 64.104.123.22 eq https 
access-list 110 extended permit tcp any host 64.104.123.21 eq 8000 
access-list 110 extended permit tcp any host 64.104.123.21 eq https 
access-list 110 extended permit esp any object-group ect-tokyo-1 
access-list 110 extended permit udp any object-group ect-tokyo-1 eq isakmp 
access-list 110 extended permit udp any object-group ect-tokyo-1 eq 4500 
access-list 110 extended permit tcp any host 64.104.15.227 eq 8000 
access-list 110 extended permit tcp any host 64.104.15.227 eq https 
access-list 110 extended permit esp any host 64.104.208.64 
access-list 110 extended permit esp any host 64.104.208.65 
access-list 110 extended permit esp any host 72.163.247.99 
access-list 110 extended permit udp any host 72.163.247.99 eq isakmp 
access-list 110 extended permit udp host 15.224.9.9 host 171.71.3.18 eq isakmp 
access-list 110 extended permit esp host 15.224.9.9 host 171.71.3.18 
access-list 110 extended permit udp host 15.224.9.9 host 171.71.3.18 eq 10000 
access-list 110 extended permit udp host 198.217.224.209 host 171.71.3.34 eq isakmp 
access-list 110 extended permit esp host 198.217.224.209 host 171.71.3.34 
access-list 110 extended permit udp host 198.217.224.209 host 171.71.3.34 eq 10000 
access-list 110 extended permit gre host 198.217.224.209 host 171.71.3.34 
access-list 110 extended permit udp host 198.217.224.217 host 171.71.3.34 eq isakmp 
access-list 110 extended permit esp host 198.217.224.217 host 171.71.3.34 
access-list 110 extended permit udp host 198.217.224.217 host 171.71.3.34 eq 10000 
access-list 110 extended permit gre host 198.217.224.217 host 171.71.3.34 
access-list 110 extended permit ah host 198.217.224.209 host 171.71.3.34 
access-list 110 extended permit ah host 198.217.224.217 host 171.71.3.34 
access-list 110 extended permit tcp any host 171.71.3.4 eq ssh 
access-list 110 extended permit tcp any host 171.71.3.4 eq https 
access-list 110 extended permit tcp any host 171.71.3.6 eq ssh 
access-list 110 extended permit tcp any host 171.71.3.6 eq https 
access-list 110 extended permit esp any object-group xnet_vpn_concentrators-sjc-1 
access-list 110 extended permit udp any object-group xnet_vpn_concentrators-sjc-1 eq isakmp 
access-list 110 extended permit udp any object-group xnet_vpn_concentrators-sjc-1 eq 10000 
access-list 110 extended permit tcp any object-group xnet_vpn_concentrators-sjc-1 eq 10000 
access-list 110 extended permit udp any object-group xnet_vpn_concentrators-sjc-1 eq 4500 
access-list 110 extended permit esp host 192.133.193.90 host 64.102.253.94 
access-list 110 extended permit esp host 192.133.193.90 host 64.102.253.90 
access-list 110 extended permit gre object-group microsoft_vpn_support-sjc-2 host 171.69.100.127 
access-list 110 extended permit esp host 192.67.48.74 host 171.69.100.127 
access-list 110 extended permit esp host 192.67.48.75 host 171.69.100.127 
access-list 110 extended permit gre object-group microsoft_vpn_support-sjc-2 host 171.69.100.47 
access-list 110 extended permit gre host 64.103.36.241 object-group outbound_vpn-global-1 
access-list 110 extended permit esp 128.107.245.0 255.255.255.224 object-group cisco_internal_networks-global-1 
access-list 110 extended permit esp host 203.210.208.227 host 64.104.88.231 
access-list 110 extended permit udp host 203.210.208.227 host 64.104.88.231 eq isakmp 
access-list 110 extended permit gre any 171.68.245.64 255.255.255.192 
access-list 110 extended permit esp any 171.68.245.64 255.255.255.192 
access-list 110 extended permit tcp host 64.103.39.100 host 144.254.208.80 range 5443 5445 
access-list 110 extended permit tcp host 64.103.38.235 host 10.63.224.21 eq 5443 
access-list 110 extended permit esp 128.107.250.160 255.255.255.224 any 
access-list 110 extended permit gre 128.107.250.160 255.255.255.224 any 
access-list 110 extended permit udp 128.107.250.160 255.255.255.224 any eq isakmp 
access-list 110 extended permit esp host 64.102.254.10 any 
access-list 110 extended permit udp host 64.102.254.10 any eq isakmp 
access-list 110 extended permit esp host 64.102.254.10 host 10.83.117.66 
access-list 110 extended permit udp host 64.102.254.10 host 10.83.117.66 eq isakmp 
access-list 110 extended permit esp host 80.163.119.234 host 64.103.35.189 
access-list 110 extended permit udp host 80.163.119.234 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 80.88.249.24 host 216.128.60.189 
access-list 110 extended permit udp host 80.88.249.24 host 216.128.60.189 eq isakmp 
access-list 110 extended permit esp host 64.103.36.18 host 10.52.147.122 
access-list 110 extended permit udp host 64.103.36.18 host 10.52.147.122 eq isakmp 
access-list 110 extended permit esp host 64.103.36.18 host 10.60.4.118 
access-list 110 extended permit udp host 64.103.36.18 host 10.60.4.118 eq isakmp 
access-list 110 extended permit esp host 72.163.216.158 host 10.104.194.6 
access-list 110 extended permit udp host 72.163.216.158 host 10.104.194.6 eq isakmp 
access-list 110 extended permit esp host 72.163.216.158 host 10.104.59.59 
access-list 110 extended permit udp host 72.163.216.158 host 10.104.59.59 eq isakmp 
access-list 110 extended permit esp host 72.163.216.158 host 10.76.11.253 
access-list 110 extended permit udp host 72.163.216.158 host 10.76.11.253 eq isakmp 
access-list 110 extended permit esp host 64.103.36.18 host 10.52.147.66 
access-list 110 extended permit udp host 64.103.36.18 host 10.52.147.66 eq isakmp 
access-list 110 extended permit icmp 64.103.38.192 255.255.255.224 any 
access-list 110 extended permit esp 64.103.38.192 255.255.255.224 any 
access-list 110 extended permit udp 64.103.38.192 255.255.255.224 any eq isakmp 
access-list 110 extended permit udp 64.103.38.192 255.255.255.224 any eq 4500 
access-list 110 extended permit esp host 64.103.36.18 any 
access-list 110 extended permit udp host 64.103.36.18 any eq isakmp 
access-list 110 extended permit esp any host 171.70.192.14 
access-list 110 extended permit udp any host 171.70.192.14 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.14 eq 4500 
access-list 110 extended permit esp any host 171.70.192.11 
access-list 110 extended permit udp any host 171.70.192.11 eq isakmp 
access-list 110 extended permit udp any host 171.70.192.11 eq 4500 
access-list 110 extended permit esp object-group outbound_vpn-sjc-1 host 64.101.65.47 
access-list 110 extended permit esp object-group agilent_vpn_ext-sjc-1 object-group agilent_vpn_int-sjc-1 
access-list 110 extended permit esp host 167.206.7.6 host 64.102.148.21 
access-list 110 extended permit esp host 74.128.1.100 host 64.102.148.21 
access-list 110 extended permit esp host 203.127.177.12 host 64.103.176.18 
access-list 110 extended permit tcp host 203.127.177.12 host 64.103.176.18 eq 10000 
access-list 110 extended permit esp host 128.107.81.84 host 10.92.240.158 
access-list 110 extended permit udp host 128.107.81.84 host 10.92.240.158 eq isakmp 
access-list 110 extended permit tcp any 128.107.235.48 255.255.255.240 eq 42027 
access-list 110 extended permit tcp any 128.107.235.48 255.255.255.240 eq 12028 
access-list 110 extended permit tcp any 128.107.235.48 255.255.255.240 eq ssh 
access-list 110 extended permit tcp any 128.107.235.48 255.255.255.240 eq 8443 
access-list 110 extended permit esp host 128.107.81.84 host 10.92.77.158 
access-list 110 extended permit udp host 128.107.81.84 host 10.92.77.158 eq isakmp 
access-list 110 extended permit esp any 64.101.164.128 255.255.255.192 
access-list 110 extended permit udp any host 64.104.192.165 eq isakmp 
access-list 110 extended permit esp any host 64.104.192.165 
access-list 110 extended permit udp any host 64.104.192.165 eq 10000 
access-list 110 extended permit udp any host 64.104.192.166 eq isakmp 
access-list 110 extended permit esp any host 64.104.192.166 
access-list 110 extended permit udp any host 64.104.192.166 eq 10000 
access-list 110 extended permit tcp any host 64.104.192.165 eq https 
access-list 110 extended permit tcp any host 64.104.192.165 eq ssh 
access-list 110 extended permit tcp any host 64.104.192.166 eq https 
access-list 110 extended permit tcp any host 64.104.192.166 eq ssh 
access-list 110 extended permit esp host 202.12.242.87 host 64.104.226.20 
access-list 110 extended permit esp host 202.12.239.87 host 64.104.226.20 
access-list 110 extended permit ah host 202.12.242.87 host 64.104.226.20 
access-list 110 extended permit ah host 202.12.239.87 host 64.104.226.20 
access-list 110 extended permit esp host 81.211.97.178 host 64.103.35.189 
access-list 110 extended permit udp host 81.211.97.178 host 64.103.35.189 eq isakmp 
access-list 110 extended permit udp any host 144.254.146.18 eq isakmp 
access-list 110 extended permit esp any host 144.254.146.18 
access-list 110 extended permit udp any host 144.254.146.22 eq isakmp 
access-list 110 extended permit esp any host 144.254.146.22 
access-list 110 extended permit udp any host 144.254.146.4 eq isakmp 
access-list 110 extended permit udp any host 144.254.146.4 eq 10000 
access-list 110 extended permit esp any host 144.254.146.4 
access-list 110 extended permit udp any host 144.254.146.9 eq isakmp 
access-list 110 extended permit esp any host 144.254.146.9 
access-list 110 extended permit udp host 217.41.21.46 host 144.254.146.18 eq isakmp 
access-list 110 extended permit udp any host 144.254.146.9 eq 4500 
access-list 110 extended permit gre host 64.103.36.241 object-group hotspot_bbsm-ams-1 
access-list 110 extended permit udp host 64.103.39.1 host 172.19.61.51 eq 2055 
access-list 110 extended permit udp host 64.103.39.3 host 172.19.61.51 eq 2055 
access-list 110 extended permit tcp host 128.107.233.36 host 10.34.130.10 eq 2000 
access-list 110 extended permit udp host 128.107.233.36 host 10.34.130.10 eq tftp 
access-list 110 extended permit udp host 128.107.233.36 host 10.34.130.10 range 20480 32767 
access-list 110 extended permit esp host 128.107.81.84 host 10.95.26.78 
access-list 110 extended permit udp host 128.107.81.84 host 10.95.26.78 eq isakmp 
access-list 110 extended permit esp host 63.67.145.5 host 171.71.10.125 
access-list 110 extended permit udp host 63.67.145.5 host 171.71.10.125 eq isakmp 
access-list 110 extended permit esp host 65.74.0.192 host 64.101.31.6 
access-list 110 extended permit esp host 65.74.0.192 host 64.101.31.10 
access-list 110 extended permit udp host 65.74.0.192 host 64.101.31.6 eq isakmp 
access-list 110 extended permit udp host 65.74.0.192 host 64.101.31.10 eq isakmp 
access-list 110 extended permit udp host 171.71.148.74 host 16.212.56.1 eq isakmp 
access-list 110 extended permit esp host 171.71.148.74 host 16.212.56.1 
access-list 110 extended permit esp host 170.248.184.135 host 64.101.65.49 
access-list 110 extended permit esp host 170.248.184.136 host 64.101.65.49 
access-list 110 extended permit esp host 170.252.11.250 host 64.101.65.49 
access-list 110 extended permit ah host 170.248.184.135 host 64.101.65.49 
access-list 110 extended permit ah host 170.248.184.136 host 64.101.65.49 
access-list 110 extended permit ah host 170.252.11.250 host 64.101.65.49 
access-list 110 extended permit udp host 170.248.184.135 host 64.101.65.49 eq isakmp 
access-list 110 extended permit udp host 170.248.184.136 host 64.101.65.49 eq isakmp 
access-list 110 extended permit udp host 170.252.11.250 host 64.101.65.49 eq isakmp 
access-list 110 extended permit esp object-group hp_vendor_vpn-global-1 64.102.35.0 255.255.255.128 
access-list 110 extended permit ah object-group hp_vendor_vpn-global-1 64.102.35.0 255.255.255.128 
access-list 110 extended permit gre object-group hp_vendor_vpn-global-1 64.102.35.0 255.255.255.128 
access-list 110 extended permit udp object-group hp_vendor_vpn-global-1 64.102.35.0 255.255.255.128 eq isakmp 
access-list 110 extended permit udp object-group hp_vendor_vpn-global-1 64.102.35.0 255.255.255.128 eq 4500 
access-list 110 extended permit udp object-group hp_vendor_vpn-global-1 64.102.35.0 255.255.255.128 eq 1701 
access-list 110 extended permit tcp host 131.107.0.144 host 171.69.100.127 eq pptp 
access-list 110 extended permit tcp host 131.107.0.144 host 171.69.100.47 eq pptp 
access-list 110 extended permit tcp host 205.248.102.75 host 171.69.100.127 eq pptp 
access-list 110 extended permit tcp host 205.248.102.75 host 171.69.100.47 eq pptp 
access-list 110 extended permit gre host 131.107.0.144 host 171.69.100.127 
access-list 110 extended permit gre host 131.107.0.144 host 171.69.100.47 
access-list 110 extended permit gre host 205.248.102.75 host 171.69.100.127 
access-list 110 extended permit gre host 205.248.102.75 host 171.69.100.47 
access-list 110 extended permit tcp object-group microsoft_vpn_support-sjc-1 host 171.69.101.210 eq pptp 
access-list 110 extended permit gre object-group microsoft_vpn_support-sjc-1 host 171.69.101.210 
access-list 110 extended permit tcp object-group microsoft_vpn_support-sjc-1 host 171.69.100.47 eq pptp 
access-list 110 extended permit gre object-group microsoft_vpn_support-sjc-1 host 171.69.100.47 
access-list 110 extended permit tcp object-group microsoft_vpn_support-sjc-1 host 171.69.100.127 eq pptp 
access-list 110 extended permit gre object-group microsoft_vpn_support-sjc-1 host 171.69.100.127 
access-list 110 extended permit tcp object-group cco_dr_hosts-rtp-1 object-group cco_dr_smx-rtp-1 range 44441 44443 
access-list 110 extended permit tcp host 64.102.255.109 host 171.68.226.150 eq 7222 
access-list 110 extended permit tcp host 64.102.255.110 host 171.68.226.150 eq 7222 
access-list 110 extended permit tcp host 128.107.80.66 object-group orative_int_auth-sjc-1 eq 5443 
access-list 110 extended permit tcp host 128.107.80.66 object-group orative_int_auth-sjc-1 eq 6532 
access-list 110 extended permit tcp host 128.107.80.66 object-group orative_int_auth-sjc-1 eq 7080 
access-list 110 extended permit tcp host 128.107.80.66 object-group orative_int_auth-sjc-1 eq 15443 
access-list 110 extended permit tcp host 128.107.80.66 object-group orative_int_auth-sjc-1 eq 16532 
access-list 110 extended permit tcp host 128.107.80.66 object-group orative_int_auth-sjc-1 eq 17080 
access-list 110 extended permit tcp host 128.107.80.67 object-group orative_int_auth-sjc-1 eq 5443 
access-list 110 extended permit tcp host 128.107.80.67 object-group orative_int_auth-sjc-1 eq 6532 
access-list 110 extended permit tcp host 128.107.80.67 object-group orative_int_auth-sjc-1 eq 7080 
access-list 110 extended permit tcp host 128.107.80.67 object-group orative_int_auth-sjc-1 eq 8443 
access-list 110 extended permit tcp host 128.107.80.67 object-group orative_int_auth-sjc-1 eq 15443 
access-list 110 extended permit tcp host 128.107.80.67 object-group orative_int_auth-sjc-1 eq 16532 
access-list 110 extended permit tcp host 128.107.80.67 object-group orative_int_auth-sjc-1 eq 17080 
access-list 110 extended permit tcp host 128.107.80.68 object-group orative_int_auth-sjc-1 eq 5443 
access-list 110 extended permit tcp host 128.107.80.68 object-group orative_int_auth-sjc-1 eq 6532 
access-list 110 extended permit tcp host 128.107.80.68 object-group orative_int_auth-sjc-1 eq 7080 
access-list 110 extended permit tcp host 128.107.80.68 object-group orative_int_auth-sjc-1 eq 15443 
access-list 110 extended permit tcp host 128.107.80.68 object-group orative_int_auth-sjc-1 eq 16532 
access-list 110 extended permit tcp host 128.107.80.68 object-group orative_int_auth-sjc-1 eq 17080 
access-list 110 extended permit tcp host 128.107.80.72 object-group orative_int_auth-sjc-1 eq 5443 
access-list 110 extended permit tcp host 128.107.80.72 object-group orative_int_auth-sjc-1 eq 6532 
access-list 110 extended permit tcp host 128.107.80.72 object-group orative_int_auth-sjc-1 eq 7080 
access-list 110 extended permit tcp host 128.107.80.72 object-group orative_int_auth-sjc-1 eq 8443 
access-list 110 extended permit tcp host 128.107.80.72 object-group orative_int_auth-sjc-1 eq 15443 
access-list 110 extended permit tcp host 128.107.80.72 object-group orative_int_auth-sjc-1 eq 16532 
access-list 110 extended permit tcp host 128.107.80.72 object-group orative_int_auth-sjc-1 eq 17080 
access-list 110 extended permit tcp host 128.107.72.15 host 171.68.10.148 eq 44441 
access-list 110 extended permit tcp host 128.107.72.16 host 171.68.10.148 eq 44441 
access-list 110 extended permit tcp host 128.107.72.15 host 171.68.10.148 eq 44442 
access-list 110 extended permit tcp host 128.107.72.16 host 171.68.10.148 eq 44442 
access-list 110 extended permit tcp host 128.107.72.15 host 171.68.10.148 eq 44443 
access-list 110 extended permit tcp host 128.107.72.16 host 171.68.10.148 eq 44443 
access-list 110 extended permit tcp host 204.69.199.43 host 171.68.10.148 eq 44441 
access-list 110 extended permit tcp host 204.69.199.44 host 171.68.10.148 eq 44441 
access-list 110 extended permit tcp host 204.69.199.43 host 171.68.10.148 eq 44442 
access-list 110 extended permit tcp host 204.69.199.44 host 171.68.10.148 eq 44442 
access-list 110 extended permit tcp host 204.69.199.43 host 171.68.10.148 eq 44443 
access-list 110 extended permit tcp host 204.69.199.44 host 171.68.10.148 eq 44443 
access-list 110 extended permit tcp host 64.102.246.167 host 171.70.144.82 range 44441 44443 
access-list 110 extended permit tcp host 64.102.246.167 host 171.70.144.83 range 44441 44443 
access-list 110 extended permit tcp host 64.102.246.168 host 171.70.144.82 range 44441 44443 
access-list 110 extended permit tcp host 64.102.246.168 host 171.70.144.83 range 44441 44443 
access-list 110 extended permit tcp host 64.102.246.169 host 171.70.144.82 range 44441 44443 
access-list 110 extended permit tcp host 64.102.246.169 host 171.70.144.83 range 44441 44443 
access-list 110 extended permit tcp object-group ace_dmz_test_env-sjc-1 host 172.17.46.17 eq https 
access-list 110 extended permit tcp object-group ace_dmz_test_env-sjc-1 host 172.17.56.13 eq 589 
access-list 110 extended permit tcp object-group ace_dmz_test_env-sjc-1 host 172.17.48.132 range 44441 44443 
access-list 110 extended permit tcp object-group ace_dmz_test_env-sjc-1 host 172.17.48.133 range 44441 44443 
access-list 110 extended permit udp 128.107.234.160 255.255.255.224 any eq 3389 
access-list 110 extended permit udp 128.107.235.160 255.255.255.224 any eq 3389 
access-list 110 extended permit udp 64.102.240.160 255.255.255.224 any eq 3389 
access-list 110 extended permit udp 172.17.213.16 255.255.255.248 host 172.18.185.68 range 2055 2065 
access-list 110 extended permit udp 10.81.255.0 255.255.255.224 host 172.18.185.68 range 2055 2065 
access-list 110 extended permit udp object-group dmz_loopbacks-bxb-1 host 172.18.185.68 range 2055 2065 
access-list 110 extended permit udp host 10.86.234.5 host 64.102.12.51 range 2055 2065 
access-list 110 extended permit udp 172.17.213.16 255.255.255.248 host 64.102.12.51 range 2055 2065 
access-list 110 extended permit udp 10.81.255.0 255.255.255.224 host 64.102.12.51 range 2055 2065 
access-list 110 extended permit udp host 10.89.255.200 host 172.18.185.68 range 2055 2065 
access-list 110 extended permit udp host 10.70.225.98 host 64.104.193.90 range 2055 2065 
access-list 110 extended permit udp host 10.75.225.195 host 72.163.192.57 range 2055 2065 
access-list 110 extended permit udp host 10.75.225.196 host 72.163.192.57 range 2055 2065 
access-list 110 extended permit udp host 10.68.1.6 host 64.104.193.90 range 2055 2065 
access-list 110 extended permit udp host 10.56.72.35 host 10.61.2.140 range 2055 2065 
access-list 110 extended permit udp host 10.59.15.227 host 10.61.2.140 range 2055 2065 
access-list 110 extended permit udp host 10.70.225.115 host 64.104.193.90 range 2055 2065 
access-list 110 extended permit udp host 10.70.225.116 host 64.104.193.90 range 2055 2065 
access-list 110 extended permit udp 172.17.153.0 255.255.255.0 172.19.61.0 255.255.255.128 eq snmptrap 
access-list 110 extended permit tcp 172.17.153.0 255.255.255.0 172.19.61.0 255.255.255.128 eq bgp 
access-list 110 extended permit udp 10.81.255.0 255.255.255.0 172.19.61.0 255.255.255.128 range 2055 2065 
access-list 110 extended permit udp 10.81.255.0 255.255.255.0 172.19.61.0 255.255.255.128 eq snmptrap 
access-list 110 extended permit tcp 10.81.255.0 255.255.255.0 172.19.61.0 255.255.255.128 eq bgp 
access-list 110 extended permit gre host 64.104.127.65 object-group hotspot_bbsm-hk-1 
access-list 110 extended permit gre host 64.104.95.129 object-group hotspot_bbsm-sing-1 
access-list 110 extended permit gre host 64.104.252.65 10.66.0.0 255.254.0.0 
access-list 110 extended permit esp host 64.103.36.18 host 64.103.102.23 
access-list 110 extended permit udp host 64.103.36.18 host 64.103.102.23 eq isakmp 
access-list 110 extended permit udp any host 64.102.223.132 eq 443 
access-list 110 extended permit udp any host 64.102.223.134 eq 443 
access-list 110 extended permit esp host 61.5.145.186 host 64.103.35.189 
access-list 110 extended permit udp host 61.5.145.186 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 41.220.72.58 host 64.103.35.189 
access-list 110 extended permit udp host 41.220.72.58 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp any host 144.254.221.45 
access-list 110 extended permit udp any host 144.254.221.45 eq isakmp 
access-list 110 extended permit udp any host 144.254.221.45 eq 4500 
access-list 110 extended permit udp any host 144.254.221.45 eq 10000 
access-list 110 extended permit esp any host 144.254.221.46 
access-list 110 extended permit udp any host 144.254.221.46 eq isakmp 
access-list 110 extended permit udp any host 144.254.221.46 eq 4500 
access-list 110 extended permit udp any host 144.254.221.46 eq 10000 
access-list 110 extended permit esp any host 144.254.221.44 
access-list 110 extended permit udp any host 144.254.221.44 eq isakmp 
access-list 110 extended permit udp any host 144.254.221.44 eq 10000 
access-list 110 extended permit esp any host 192.118.79.8 
access-list 110 extended permit udp any host 192.118.79.8 eq isakmp 
access-list 110 extended permit udp any host 192.118.79.8 eq 10000 
access-list 110 extended permit tcp any host 192.118.79.8 eq ssh 
access-list 110 extended permit tcp any host 192.118.79.8 eq https 
access-list 110 extended permit esp any host 192.118.79.6 
access-list 110 extended permit udp any host 192.118.79.6 eq isakmp 
access-list 110 extended permit udp any host 192.118.79.6 eq 10000 
access-list 110 extended permit tcp any host 192.118.79.6 eq ssh 
access-list 110 extended permit tcp any host 192.118.79.6 eq https 
access-list 110 extended permit esp any host 192.118.79.7 
access-list 110 extended permit udp any host 192.118.79.7 eq isakmp 
access-list 110 extended permit udp any host 192.118.79.7 eq 10000 
access-list 110 extended permit tcp any host 192.118.79.7 eq ssh 
access-list 110 extended permit tcp any host 192.118.79.7 eq https 
access-list 110 extended permit udp any host 144.254.221.37 eq isakmp 
access-list 110 extended permit esp any host 144.254.221.37 
access-list 110 extended permit udp any host 144.254.221.37 eq 10000 
access-list 110 extended permit tcp any host 144.254.221.37 eq ssh 
access-list 110 extended permit tcp any host 144.254.221.37 eq https 
access-list 110 extended permit udp any host 144.254.221.38 eq isakmp 
access-list 110 extended permit esp any host 144.254.221.38 
access-list 110 extended permit udp any host 144.254.221.38 eq 10000 
access-list 110 extended permit tcp any host 144.254.221.38 eq ssh 
access-list 110 extended permit tcp any host 144.254.221.38 eq https 
access-list 110 extended permit udp any host 144.254.221.39 eq isakmp 
access-list 110 extended permit esp any host 144.254.221.39 
access-list 110 extended permit udp any host 144.254.221.39 eq 10000 
access-list 110 extended permit tcp any host 144.254.221.39 eq ssh 
access-list 110 extended permit tcp any host 144.254.221.39 eq https 
access-list 110 extended permit esp host 212.82.216.58 host 64.103.35.189 
access-list 110 extended permit udp host 212.82.216.58 host 64.103.35.189 eq isakmp 
access-list 110 extended permit udp host 212.82.216.58 host 64.103.35.189 eq 4500 
access-list 110 extended permit esp host 203.174.180.250 host 64.104.213.241 
access-list 110 extended permit udp host 203.174.180.250 host 64.104.213.241 eq isakmp 
access-list 110 extended permit udp host 203.174.180.250 host 64.104.213.241 eq 4500 
access-list 110 extended permit esp host 203.174.181.154 host 64.104.213.241 
access-list 110 extended permit udp host 203.174.181.154 host 64.104.213.241 eq isakmp 
access-list 110 extended permit udp host 203.174.181.154 host 64.104.213.241 eq 4500 
access-list 110 extended permit esp host 61.47.80.142 host 64.104.83.33 
access-list 110 extended permit udp host 61.47.80.142 host 64.104.83.33 eq isakmp 
access-list 110 extended permit gre host 64.104.95.129 host 10.68.192.3 
access-list 110 extended permit gre host 10.64.63.16 host 10.78.10.67 
access-list 110 extended permit esp host 122.52.239.153 host 64.104.77.181 
access-list 110 extended permit udp host 122.52.239.153 host 64.104.77.181 eq isakmp 
access-list 110 extended permit udp host 122.52.239.153 host 64.104.77.181 eq 4500 
access-list 110 extended permit esp host 122.56.107.13 host 64.104.213.241 
access-list 110 extended permit udp host 122.56.107.13 host 64.104.213.241 eq isakmp 
access-list 110 extended permit udp host 122.56.107.13 host 64.104.213.241 eq 4500 
access-list 110 extended permit esp host 203.174.180.249 host 64.104.213.241 
access-list 110 extended permit udp host 203.174.180.249 host 64.104.213.241 eq isakmp 
access-list 110 extended permit udp host 203.174.180.249 host 64.104.213.241 eq 4500 
access-list 110 extended permit esp host 196.192.9.243 host 64.103.35.61 
access-list 110 extended permit udp host 196.192.9.243 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 180.43.108.113 host 64.104.14.232 
access-list 110 extended permit esp host 180.43.108.113 host 64.104.14.233 
access-list 110 extended permit udp host 180.43.108.113 host 64.104.14.232 eq isakmp 
access-list 110 extended permit udp host 180.43.108.113 host 64.104.14.233 eq isakmp 
access-list 110 extended permit esp host 121.15.168.73 host 72.163.247.99 
access-list 110 extended permit udp host 121.15.168.73 host 72.163.247.99 eq isakmp 
access-list 110 extended permit esp any object-group ect-ntn-1 
access-list 110 extended permit udp any object-group ect-ntn-1 eq isakmp 
access-list 110 extended permit udp any object-group ect-ntn-1 eq 4500 
access-list 110 extended permit tcp any host 192.118.79.35 eq https 
access-list 110 extended permit tcp any host 192.118.79.35 eq 8000 
access-list 110 extended permit udp host 194.247.220.5 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 194.247.220.5 host 64.103.35.189 
access-list 110 extended permit udp 212.39.82.232 255.255.255.248 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp 212.39.82.232 255.255.255.248 host 64.103.35.189 
access-list 110 extended permit esp any object-group ect-ams-1 
access-list 110 extended permit udp any object-group ect-ams-1 eq isakmp 
access-list 110 extended permit udp any object-group ect-ams-1 eq 4500 
access-list 110 extended permit tcp any host 144.254.220.142 eq https 
access-list 110 extended permit tcp any host 144.254.220.142 eq 8000 
access-list 110 extended permit tcp host 128.107.234.70 host 171.70.144.74 eq 15000 
access-list 110 extended permit tcp host 128.107.227.212 host 171.70.156.58 eq 1556 
access-list 110 extended permit tcp host 128.107.241.75 host 171.70.156.58 eq 1556 
access-list 110 extended permit tcp host 198.133.219.171 host 64.102.7.21 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.172 host 64.102.7.21 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.173 host 64.102.7.21 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.175 host 64.102.7.21 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.176 host 64.102.7.21 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.177 host 64.102.7.21 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.179 host 64.102.7.21 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.180 host 64.102.7.21 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.181 host 64.102.7.21 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.187 host 64.102.7.21 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.188 host 64.102.7.21 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.189 host 64.102.7.21 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.187 host 64.102.7.22 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.188 host 64.102.7.22 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.189 host 64.102.7.22 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.171 host 64.102.7.22 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.172 host 64.102.7.22 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.173 host 64.102.7.22 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.175 host 64.102.7.22 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.176 host 64.102.7.22 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.177 host 64.102.7.22 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.179 host 64.102.7.22 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.180 host 64.102.7.22 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.181 host 64.102.7.22 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.233 host 171.68.10.148 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.234 host 171.68.10.148 range 44441 44443 
access-list 110 extended permit tcp host 128.107.74.36 host 171.68.10.148 range 44441 44443 
access-list 110 extended permit tcp host 128.107.74.37 host 171.68.10.148 range 44441 44443 
access-list 110 extended permit tcp object-group mp_dmz_ext-sjc-1 object-group mp_dmz_int-sjc-1 eq 4443 
access-list 110 extended permit tcp object-group cco_download_svr-rtp-1 object-group cco_download_svr_auth-rtp-1 range 44441 44443 
access-list 110 extended permit tcp object-group dmz_siteminder-sjc-1 host 171.68.10.148 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.171 host 171.68.10.149 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.172 host 171.68.10.149 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.173 host 171.68.10.149 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.175 host 171.68.10.149 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.176 host 171.68.10.149 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.179 host 171.68.10.149 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.180 host 171.68.10.149 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.181 host 171.68.10.149 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.187 host 171.68.10.149 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.188 host 171.68.10.149 range 44441 44443 
access-list 110 extended permit tcp host 198.133.219.189 host 171.68.10.149 range 44441 44443 
access-list 110 extended permit esp any host 64.102.253.66 
access-list 110 extended permit udp any host 64.102.253.66 eq isakmp 
access-list 110 extended permit udp any host 64.102.253.66 eq 4500 
access-list 110 extended permit esp any host 64.102.253.67 
access-list 110 extended permit udp any host 64.102.253.67 eq isakmp 
access-list 110 extended permit udp any host 64.102.253.67 eq 4500 
access-list 110 extended permit esp any host 64.102.253.73 
access-list 110 extended permit udp any host 64.102.253.73 eq isakmp 
access-list 110 extended permit udp any host 64.102.253.73 eq 4500 
access-list 110 extended permit tcp object-group hotspot_pilot-rtp-1 object-group hotspot_pilot-sjc-1 eq 8996 
access-list 110 extended permit tcp object-group hotspot_pilot-rtp-1 object-group hotspot_pilot-sjc-1 eq 8995 
access-list 110 extended permit tcp object-group hotspot_pilot-rtp-1 object-group hotspot_pilot-sjc-1 eq 1099 
access-list 110 extended permit tcp object-group hotspot_pilot-rtp-1 object-group hotspot_pilot-sjc-1 eq ssh 
access-list 110 extended permit tcp object-group hotspot_pilot-rtp-1 object-group hotspot_pilot-sjc-1 eq https 
access-list 110 extended permit gre host 64.102.240.233 10.80.0.0 255.240.0.0 
access-list 110 extended permit gre host 64.102.240.233 10.96.0.0 255.255.0.0 
access-list 110 extended permit gre host 64.104.47.236 10.70.0.0 255.254.0.0 
access-list 110 extended permit gre host 64.104.44.97 10.70.0.0 255.254.0.0 
access-list 110 extended permit esp host 123.220.247.193 host 64.104.14.248 
access-list 110 extended permit udp host 123.220.247.193 host 64.104.14.248 eq isakmp 
access-list 110 extended permit esp host 61.112.161.131 host 64.104.14.248 
access-list 110 extended permit udp host 61.112.161.131 host 64.104.14.248 eq isakmp 
access-list 110 extended permit esp host 211.129.153.46 host 64.104.8.21 
access-list 110 extended permit udp host 211.129.153.46 host 64.104.8.21 eq isakmp 
access-list 110 extended permit udp host 161.225.129.30 host 64.101.65.46 eq isakmp 
access-list 110 extended permit esp host 161.225.129.30 host 64.101.65.46 
access-list 110 extended permit esp host 61.126.132.31 host 64.104.14.248 
access-list 110 extended permit udp host 61.126.132.31 host 64.104.14.248 eq isakmp 
access-list 110 extended permit tcp host 64.104.44.2 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.104.44.2 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.104.44.2 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 64.104.44.3 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.104.44.3 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.104.44.3 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 64.104.44.4 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.104.44.4 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.104.44.4 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 64.104.127.114 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.104.127.114 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.104.127.114 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 64.104.127.115 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.104.127.115 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.104.127.115 host 171.70.144.143 eq https 
access-list 110 extended permit tcp host 64.104.127.116 host 171.70.144.141 eq https 
access-list 110 extended permit tcp host 64.104.127.116 host 171.70.144.142 eq https 
access-list 110 extended permit tcp host 64.104.127.116 host 171.70.144.143 eq https 
access-list 110 extended permit gre host 64.104.127.65 host 10.74.237.33 
access-list 110 extended permit esp any object-group vpn_tac_support-global-1 
access-list 110 extended permit esp any host 64.102.253.90 
access-list 110 extended permit udp any host 64.102.253.90 eq isakmp 
access-list 110 extended permit esp any host 64.102.253.94 
access-list 110 extended permit udp any host 64.102.253.94 eq isakmp 
access-list 110 extended permit udp host 128.107.241.124 128.107.96.0 255.255.224.0 eq mobile-ip 
access-list 110 extended permit udp host 128.107.241.124 171.70.230.0 255.255.254.0 eq mobile-ip 
access-list 110 extended permit udp host 128.107.241.124 171.70.236.0 255.255.252.0 eq mobile-ip 
access-list 110 extended permit esp any host 128.107.200.75 
access-list 110 extended permit udp any host 128.107.200.75 eq isakmp 
access-list 110 extended permit udp any host 128.107.200.75 eq 4500 
access-list 110 extended permit tcp any host 128.107.200.75 eq https 
access-list 110 extended permit tcp any host 128.107.200.75 eq 8000 
access-list 110 extended permit esp any host 128.107.200.99 
access-list 110 extended permit udp any host 128.107.200.99 eq isakmp 
access-list 110 extended permit udp any host 128.107.200.99 eq 4500 
access-list 110 extended permit esp any object-group esenoc_vpn-rtp-1 
access-list 110 extended permit tcp any object-group esenoc_vpn-rtp-1 eq ssh 
access-list 110 extended permit tcp any object-group esenoc_vpn-rtp-1 eq https 
access-list 110 extended permit udp any object-group esenoc_vpn-rtp-1 eq isakmp 
access-list 110 extended permit udp any object-group esenoc_vpn-rtp-1 eq 4500 
access-list 110 extended permit udp any object-group esenoc_vpn-rtp-1 eq 10000 
access-list 110 extended permit esp any object-group ese_vpn-rtp-1 
access-list 110 extended permit udp any object-group ese_vpn-rtp-1 eq isakmp 
access-list 110 extended permit esp any object-group ect-rtp-1 
access-list 110 extended permit udp any object-group ect-rtp-1 eq isakmp 
access-list 110 extended permit udp any object-group ect-rtp-1 eq 4500 
access-list 110 extended permit tcp any host 64.102.252.34 eq ssh 
access-list 110 extended permit tcp any host 64.102.252.34 eq https 
access-list 110 extended permit tcp any host 64.102.252.35 eq ssh 
access-list 110 extended permit tcp any host 64.102.252.35 eq https 
access-list 110 extended permit tcp any host 64.102.252.36 eq ssh 
access-list 110 extended permit tcp any host 64.102.252.36 eq https 
access-list 110 extended permit esp any host 64.102.252.10 
access-list 110 extended permit udp any host 64.102.252.10 eq isakmp 
access-list 110 extended permit udp any host 64.102.252.10 eq 10000 
access-list 110 extended permit esp any host 64.102.252.12 
access-list 110 extended permit udp any host 64.102.252.12 eq isakmp 
access-list 110 extended permit udp any host 64.102.252.12 eq 10000 
access-list 110 extended permit esp any host 64.102.252.34 
access-list 110 extended permit udp any host 64.102.252.34 eq isakmp 
access-list 110 extended permit udp any host 64.102.252.34 eq 4500 
access-list 110 extended permit udp any host 64.102.252.34 eq 10000 
access-list 110 extended permit esp any host 64.102.252.35 
access-list 110 extended permit udp any host 64.102.252.35 eq isakmp 
access-list 110 extended permit udp any host 64.102.252.35 eq 4500 
access-list 110 extended permit udp any host 64.102.252.35 eq 10000 
access-list 110 extended permit esp any host 64.102.252.36 
access-list 110 extended permit udp any host 64.102.252.36 eq isakmp 
access-list 110 extended permit udp any host 64.102.252.36 eq 4500 
access-list 110 extended permit udp any host 64.102.252.36 eq 10000 
access-list 110 extended permit tcp host 64.102.254.149 host 172.18.134.49 eq 6665 
access-list 110 extended permit tcp host 64.102.254.149 host 172.18.134.49 eq 6666 
access-list 110 extended permit tcp host 64.102.254.149 host 172.18.134.49 eq 6667 
access-list 110 extended permit tcp any host 64.104.94.55 eq 5443 
access-list 110 extended permit tcp any host 64.104.94.55 eq 9080 
access-list 110 extended permit tcp any host 64.104.94.165 eq ssh 
access-list 110 extended permit tcp host 64.104.94.165 host 10.68.3.80 eq 5443 
access-list 110 extended permit tcp host 64.104.94.165 host 10.68.3.80 eq 9080 
access-list 110 extended permit tcp any host 64.103.26.165 eq ssh 
access-list 110 extended permit tcp host 64.103.26.59 134.24.132.0 255.255.255.0 eq www 
access-list 110 extended permit tcp host 64.103.26.59 134.24.132.0 255.255.255.0 eq https 
access-list 110 extended permit tcp host 64.103.26.59 134.24.132.0 255.255.255.0 eq 7000 
access-list 110 extended permit udp host 144.254.51.152 any range 5246 5247 
access-list 110 extended permit udp host 144.254.51.153 any range 5246 5247 
access-list 110 extended permit udp host 64.100.13.106 any range 5246 5247 
access-list 110 extended permit udp host 64.100.13.107 any range 5246 5247 
access-list 110 extended permit udp host 64.100.2.3 any range 5246 5247 
access-list 110 extended permit udp host 64.100.2.8 any range 5246 5247 
access-list 110 extended permit udp host 64.100.2.9 any range 5246 5247 
access-list 110 extended permit tcp host 64.103.26.115 host 10.53.40.7 eq 5222 
access-list 110 extended permit tcp host 64.103.26.115 host 10.53.40.7 eq 5269 
access-list 110 extended permit udp host 145.248.195.33 host 144.254.146.9 eq isakmp 
access-list 110 extended permit esp host 82.213.56.18 host 144.254.146.9 
access-list 110 extended permit udp host 82.213.56.18 host 144.254.146.9 eq isakmp 
access-list 110 extended permit udp host 67.148.157.189 any eq isakmp 
access-list 110 extended permit esp host 67.148.157.189 any 
access-list 110 extended permit udp host 67.148.157.189 any eq 4500 
access-list 110 extended permit udp host 67.148.157.190 any eq isakmp 
access-list 110 extended permit esp host 67.148.157.190 any 
access-list 110 extended permit udp host 67.148.157.190 any eq 4500 
access-list 110 extended permit esp host 193.253.216.11 host 64.103.35.61 
access-list 110 extended permit udp host 193.253.216.11 host 64.103.35.61 eq isakmp 
access-list 110 extended permit udp host 193.253.216.11 host 64.103.35.61 eq 4500 
access-list 110 extended permit tcp host 64.103.26.78 host 10.63.224.21 eq 5443 
access-list 110 extended permit tcp host 64.103.26.78 host 10.63.224.21 eq 9080 
access-list 110 extended permit udp host 144.254.146.9 host 196.219.220.161 eq isakmp 
access-list 110 extended permit udp any host 144.254.221.41 eq isakmp 
access-list 110 extended permit esp any host 144.254.221.41 
access-list 110 extended permit tcp any host 144.254.221.41 eq ssh 
access-list 110 extended permit tcp any host 144.254.221.41 eq https 
access-list 110 extended permit udp any host 144.254.221.41 eq 10000 
access-list 110 extended permit udp any host 144.254.221.41 eq 4500 
access-list 110 extended permit udp any host 144.254.221.42 eq isakmp 
access-list 110 extended permit esp any host 144.254.221.42 
access-list 110 extended permit tcp any host 144.254.221.42 eq ssh 
access-list 110 extended permit tcp any host 144.254.221.42 eq https 
access-list 110 extended permit udp any host 144.254.221.42 eq 10000 
access-list 110 extended permit udp any host 144.254.221.42 eq 4500 
access-list 110 extended permit tcp host 64.103.26.115 host 10.53.40.21 eq 5222 
access-list 110 extended permit tcp host 64.103.26.115 host 10.53.40.21 eq 5269 
access-list 110 extended permit tcp any host 64.103.39.100 eq 5443 
access-list 110 extended permit tcp any host 64.103.39.100 eq 9080 
access-list 110 extended permit tcp host 64.103.26.165 host 144.254.208.80 eq 5443 
access-list 110 extended permit tcp host 64.103.26.165 host 144.254.208.80 eq 9080 
access-list 110 extended permit tcp host 64.102.254.149 host 172.18.134.49 eq 5443 
access-list 110 extended permit tcp host 64.102.254.149 host 172.18.134.49 eq 9080 
access-list 110 extended permit tcp host 64.102.254.149 host 172.18.133.49 eq 5444 
access-list 110 extended permit tcp host 64.102.254.149 host 172.18.133.49 eq 9081 
access-list 110 extended permit tcp host 64.102.242.120 host 72.163.56.102 eq ldaps 
access-list 110 extended permit tcp host 64.102.242.121 host 72.163.56.102 eq ldaps 
access-list 110 extended permit tcp host 64.102.242.120 host 171.68.38.106 eq ldaps 
access-list 110 extended permit tcp host 64.102.242.121 host 171.68.38.106 eq ldaps 
access-list 110 extended permit tcp host 64.102.242.120 host 171.68.224.6 eq ldaps 
access-list 110 extended permit tcp host 64.102.242.121 host 171.68.224.6 eq ldaps 
access-list 110 extended permit tcp host 64.100.8.212 host 172.18.133.235 eq bgp 
access-list 110 extended permit tcp any host 72.163.6.10 eq https 
access-list 110 extended permit tcp any object-group anyconnect_xmm_rcd-rcdn-1 eq https 
access-list 110 extended permit tcp object-group anyconnect_xmm_rcd-rcdn-1 object-group anyconnect_int_ds_hosts-rcdn-1 eq ldaps 
access-list 110 extended permit tcp object-group anyconnect_xmm_rcd-rcdn-1 object-group anyconnect_exchange_hosts-rcdn-1 eq https 
access-list 110 extended permit tcp host 64.102.242.120 host 72.163.62.158 eq https 
access-list 110 extended permit tcp host 64.102.242.121 host 72.163.62.158 eq https 
access-list 110 extended permit tcp host 64.102.242.120 host 72.163.129.198 eq https 
access-list 110 extended permit tcp host 64.102.242.121 host 72.163.129.198 eq https 
access-list 110 extended permit tcp host 64.102.242.120 host 64.104.123.83 eq https 
access-list 110 extended permit tcp host 64.102.242.121 host 64.104.123.83 eq https 
access-list 110 extended permit tcp host 64.102.242.120 host 144.254.231.90 eq https 
access-list 110 extended permit tcp host 64.102.242.121 host 144.254.231.90 eq https 
access-list 110 extended permit tcp host 64.102.242.120 host 171.70.151.132 eq https 
access-list 110 extended permit tcp host 64.102.242.121 host 171.70.151.132 eq https 
access-list 110 extended permit tcp host 64.102.242.120 host 128.107.191.10 eq https 
access-list 110 extended permit tcp host 64.102.242.121 host 128.107.191.10 eq https 
access-list 110 extended permit tcp host 64.103.27.100 host 10.75.228.55 eq ldap 
access-list 110 extended permit tcp host 64.100.13.188 host 10.75.228.55 eq ldap 
access-list 110 extended permit tcp host 64.100.13.196 host 10.75.228.55 eq ldap 
access-list 110 extended permit udp host 64.103.27.100 host 10.75.228.55 eq 389 
access-list 110 extended permit udp host 64.100.13.188 host 10.75.228.55 eq 389 
access-list 110 extended permit udp host 64.100.13.196 host 10.75.228.55 eq 389 
access-list 110 extended permit tcp host 64.103.27.100 host 10.75.228.55 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.188 host 10.75.228.55 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.196 host 10.75.228.55 eq ldaps 
access-list 110 extended permit udp host 64.103.27.100 host 10.75.228.55 eq 636 
access-list 110 extended permit udp host 64.100.13.188 host 10.75.228.55 eq 636 
access-list 110 extended permit udp host 64.100.13.196 host 10.75.228.55 eq 636 
access-list 110 extended permit tcp host 64.103.27.100 host 72.163.57.76 eq ldap 
access-list 110 extended permit tcp host 64.100.13.188 host 72.163.57.76 eq ldap 
access-list 110 extended permit tcp host 64.100.13.196 host 72.163.57.76 eq ldap 
access-list 110 extended permit udp host 64.103.27.100 host 72.163.57.76 eq 389 
access-list 110 extended permit udp host 64.100.13.188 host 72.163.57.76 eq 389 
access-list 110 extended permit udp host 64.100.13.196 host 72.163.57.76 eq 389 
access-list 110 extended permit tcp host 64.103.27.100 host 72.163.57.76 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.188 host 72.163.57.76 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.196 host 72.163.57.76 eq ldaps 
access-list 110 extended permit udp host 64.103.27.100 host 72.163.57.76 eq 636 
access-list 110 extended permit udp host 64.100.13.188 host 72.163.57.76 eq 636 
access-list 110 extended permit udp host 64.100.13.196 host 72.163.57.76 eq 636 
access-list 110 extended permit tcp host 64.103.27.100 host 64.102.115.13 eq ldap 
access-list 110 extended permit tcp host 64.100.13.188 host 64.102.115.13 eq ldap 
access-list 110 extended permit tcp host 64.100.13.196 host 64.102.115.13 eq ldap 
access-list 110 extended permit udp host 64.103.27.100 host 64.102.115.13 eq 389 
access-list 110 extended permit udp host 64.100.13.188 host 64.102.115.13 eq 389 
access-list 110 extended permit udp host 64.100.13.196 host 64.102.115.13 eq 389 
access-list 110 extended permit tcp host 64.103.27.100 host 64.102.115.13 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.188 host 64.102.115.13 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.196 host 64.102.115.13 eq ldaps 
access-list 110 extended permit udp host 64.103.27.100 host 64.102.115.13 eq 636 
access-list 110 extended permit udp host 64.100.13.188 host 64.102.115.13 eq 636 
access-list 110 extended permit udp host 64.100.13.196 host 64.102.115.13 eq 636 
access-list 110 extended permit tcp host 64.103.27.100 host 171.70.144.28 eq ldap 
access-list 110 extended permit tcp host 64.100.13.188 host 171.70.144.28 eq ldap 
access-list 110 extended permit tcp host 64.100.13.196 host 171.70.144.28 eq ldap 
access-list 110 extended permit udp host 64.103.27.100 host 171.70.144.28 eq 389 
access-list 110 extended permit udp host 64.100.13.188 host 171.70.144.28 eq 389 
access-list 110 extended permit udp host 64.100.13.196 host 171.70.144.28 eq 389 
access-list 110 extended permit tcp host 64.103.27.100 host 171.70.144.28 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.188 host 171.70.144.28 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.196 host 171.70.144.28 eq ldaps 
access-list 110 extended permit udp host 64.103.27.100 host 171.70.144.28 eq 636 
access-list 110 extended permit udp host 64.100.13.188 host 171.70.144.28 eq 636 
access-list 110 extended permit udp host 64.100.13.196 host 171.70.144.28 eq 636 
access-list 110 extended permit tcp host 64.103.27.100 host 144.254.231.218 eq ldap 
access-list 110 extended permit tcp host 64.100.13.188 host 144.254.231.218 eq ldap 
access-list 110 extended permit tcp host 64.100.13.196 host 144.254.231.218 eq ldap 
access-list 110 extended permit udp host 64.103.27.100 host 144.254.231.218 eq 389 
access-list 110 extended permit udp host 64.100.13.188 host 144.254.231.218 eq 389 
access-list 110 extended permit udp host 64.100.13.196 host 144.254.231.218 eq 389 
access-list 110 extended permit tcp host 64.103.27.100 host 144.254.231.218 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.188 host 144.254.231.218 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.196 host 144.254.231.218 eq ldaps 
access-list 110 extended permit udp host 64.103.27.100 host 144.254.231.218 eq 636 
access-list 110 extended permit udp host 64.100.13.188 host 144.254.231.218 eq 636 
access-list 110 extended permit udp host 64.100.13.196 host 144.254.231.218 eq 636 
access-list 110 extended permit tcp host 64.103.27.100 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp host 64.100.13.188 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp host 64.100.13.196 host 64.102.9.230 eq ldap 
access-list 110 extended permit udp host 64.103.27.100 host 64.102.9.230 eq 389 
access-list 110 extended permit udp host 64.100.13.188 host 64.102.9.230 eq 389 
access-list 110 extended permit udp host 64.100.13.196 host 64.102.9.230 eq 389 
access-list 110 extended permit tcp host 64.103.27.100 host 64.102.9.230 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.188 host 64.102.9.230 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.196 host 64.102.9.230 eq ldaps 
access-list 110 extended permit udp host 64.103.27.100 host 64.102.9.230 eq 636 
access-list 110 extended permit udp host 64.100.13.188 host 64.102.9.230 eq 636 
access-list 110 extended permit udp host 64.100.13.196 host 64.102.9.230 eq 636 
access-list 110 extended permit tcp host 64.103.27.100 host 171.68.224.207 eq ldap 
access-list 110 extended permit tcp host 64.100.13.188 host 171.68.224.207 eq ldap 
access-list 110 extended permit tcp host 64.100.13.196 host 171.68.224.207 eq ldap 
access-list 110 extended permit udp host 64.103.27.100 host 171.68.224.207 eq 389 
access-list 110 extended permit udp host 64.100.13.188 host 171.68.224.207 eq 389 
access-list 110 extended permit udp host 64.100.13.196 host 171.68.224.207 eq 389 
access-list 110 extended permit tcp host 64.103.27.100 host 171.68.224.207 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.188 host 171.68.224.207 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.196 host 171.68.224.207 eq ldaps 
access-list 110 extended permit udp host 64.103.27.100 host 171.68.224.207 eq 636 
access-list 110 extended permit udp host 64.100.13.188 host 171.68.224.207 eq 636 
access-list 110 extended permit udp host 64.100.13.196 host 171.68.224.207 eq 636 
access-list 110 extended permit tcp host 64.103.27.100 host 72.163.57.6 eq ldap 
access-list 110 extended permit tcp host 64.100.13.188 host 72.163.57.6 eq ldap 
access-list 110 extended permit tcp host 64.100.13.196 host 72.163.57.6 eq ldap 
access-list 110 extended permit udp host 64.103.27.100 host 72.163.57.6 eq 389 
access-list 110 extended permit udp host 64.100.13.188 host 72.163.57.6 eq 389 
access-list 110 extended permit udp host 64.100.13.196 host 72.163.57.6 eq 389 
access-list 110 extended permit tcp host 64.103.27.100 host 72.163.57.6 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.188 host 72.163.57.6 eq ldaps 
access-list 110 extended permit tcp host 64.100.13.196 host 72.163.57.6 eq ldaps 
access-list 110 extended permit udp host 64.103.27.100 host 72.163.57.6 eq 636 
access-list 110 extended permit udp host 64.100.13.188 host 72.163.57.6 eq 636 
access-list 110 extended permit udp host 64.100.13.196 host 72.163.57.6 eq 636 
access-list 110 extended permit tcp host 64.102.242.120 host 72.163.62.222 eq https 
access-list 110 extended permit tcp host 64.102.242.121 host 72.163.62.222 eq https 
access-list 110 extended permit tcp host 64.102.242.120 host 72.163.63.30 eq https 
access-list 110 extended permit tcp host 64.102.242.121 host 72.163.63.30 eq https 
access-list 110 extended permit tcp any host 64.102.253.68 eq https 
access-list 110 extended permit tcp any host 64.102.253.68 eq 8000 
access-list 110 extended permit tcp any host 64.102.253.68 eq 10000 
access-list 110 extended permit esp any host 171.70.35.68 
access-list 110 extended permit udp any host 171.70.35.68 eq isakmp 
access-list 110 extended permit esp any host 64.100.223.254 
access-list 110 extended permit udp any host 64.100.223.254 eq isakmp 
access-list 110 extended permit esp object-group hp_vendor_vpn_ext-rtp-1 object-group hp_vendor_vpn_int-rtp-1 
access-list 110 extended permit esp object-group hp_vendor_vpn_ext-rtp-1 object-group hp_vendor_vpn_int-sjc-1 
access-list 110 extended permit esp host 210.138.173.89 host 64.104.14.247 
access-list 110 extended permit udp host 210.138.173.89 host 64.104.14.247 eq isakmp 
access-list 110 extended permit esp host 210.138.173.89 host 64.104.14.248 
access-list 110 extended permit udp host 210.138.173.89 host 64.104.14.248 eq isakmp 
access-list 110 extended permit gre any 64.104.15.198 255.255.255.254 
access-list 110 extended deny gre any 64.104.15.192 255.255.255.240 
access-list 110 extended deny gre any host 64.104.15.223 
access-list 110 extended permit gre any 64.104.15.192 255.255.255.224 
access-list 110 extended permit esp any 64.104.15.198 255.255.255.254 
access-list 110 extended deny esp any 64.104.15.192 255.255.255.240 
access-list 110 extended deny esp any host 64.104.15.223 
access-list 110 extended permit esp any 64.104.15.192 255.255.255.224 
access-list 110 extended permit gre any 64.104.200.96 255.255.255.224 
access-list 110 extended permit esp any 64.104.200.96 255.255.255.224 
access-list 110 extended permit esp host 220.98.4.248 host 64.104.14.247 
access-list 110 extended permit udp host 220.98.4.248 host 64.104.14.247 eq isakmp 
access-list 110 extended permit esp host 220.98.4.248 host 64.104.14.248 
access-list 110 extended permit udp host 220.98.4.248 host 64.104.14.248 eq isakmp 
access-list 110 extended permit esp host 220.110.12.250 host 64.104.14.247 
access-list 110 extended permit udp host 220.110.12.250 host 64.104.14.247 eq isakmp 
access-list 110 extended permit esp host 220.110.12.250 host 64.104.14.248 
access-list 110 extended permit udp host 220.110.12.250 host 64.104.14.248 eq isakmp 
access-list 110 extended permit esp host 221.245.226.74 host 64.104.14.232 
access-list 110 extended permit esp host 221.245.226.74 host 64.104.14.233 
access-list 110 extended permit udp host 221.245.226.74 host 64.104.14.232 eq isakmp 
access-list 110 extended permit udp host 221.245.226.74 host 64.104.14.233 eq isakmp 
access-list 110 extended permit esp host 61.118.247.199 host 64.104.14.232 
access-list 110 extended permit esp host 61.118.247.199 host 64.104.14.233 
access-list 110 extended permit udp host 61.118.247.199 host 64.104.14.232 eq isakmp 
access-list 110 extended permit udp host 61.118.247.199 host 64.104.14.233 eq isakmp 
access-list 110 extended permit esp host 222.158.224.241 host 64.104.14.247 
access-list 110 extended permit udp host 222.158.224.241 host 64.104.14.247 eq isakmp 
access-list 110 extended permit esp host 222.158.224.241 host 64.104.14.248 
access-list 110 extended permit udp host 222.158.224.241 host 64.104.14.248 eq isakmp 
access-list 110 extended permit esp host 122.1.1.19 host 64.104.14.247 
access-list 110 extended permit esp host 122.1.1.19 host 64.104.14.248 
access-list 110 extended permit udp host 122.1.1.19 host 64.104.14.247 eq isakmp 
access-list 110 extended permit udp host 122.1.1.19 host 64.104.14.248 eq isakmp 
access-list 110 extended permit esp any host 64.104.82.1 
access-list 110 extended permit esp any host 64.104.82.2 
access-list 110 extended permit udp any host 64.104.82.1 eq isakmp 
access-list 110 extended permit udp any host 64.104.82.2 eq isakmp 
access-list 110 extended permit udp any host 64.104.82.1 eq 4500 
access-list 110 extended permit udp any host 64.104.82.2 eq 4500 
access-list 110 extended permit gre host 64.104.95.129 host 10.68.160.65 
access-list 110 extended permit esp host 222.127.10.155 host 64.104.77.181 
access-list 110 extended permit udp host 222.127.10.155 host 64.104.77.181 eq isakmp 
access-list 110 extended permit udp host 222.127.10.155 host 64.104.77.181 eq 4500 
access-list 110 extended permit esp any host 64.103.209.131 
access-list 110 extended permit esp any host 64.103.209.132 
access-list 110 extended permit udp any host 64.103.209.131 eq 4500 
access-list 110 extended permit udp any host 64.103.209.132 eq 4500 
access-list 110 extended permit esp host 180.43.28.206 host 64.104.14.247 
access-list 110 extended permit udp host 180.43.28.206 host 64.104.14.247 eq isakmp 
access-list 110 extended permit esp host 180.43.28.206 host 64.104.14.248 
access-list 110 extended permit udp host 180.43.28.206 host 64.104.14.248 eq isakmp 
access-list 110 extended permit udp host 217.66.233.130 host 144.254.146.9 eq isakmp 
access-list 110 extended permit esp host 217.91.36.251 host 64.103.35.189 
access-list 110 extended permit udp host 217.91.36.251 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 212.185.189.202 host 64.103.35.189 
access-list 110 extended permit udp host 212.185.189.202 host 64.103.35.189 eq isakmp 
access-list 110 extended permit udp host 64.103.35.61 host 82.135.246.248 eq isakmp 
access-list 110 extended permit esp object-group japan_site2site_vpn_backup-tokyo-1 host 64.104.14.232 
access-list 110 extended permit udp object-group japan_site2site_vpn_backup-tokyo-1 host 64.104.14.232 eq isakmp 
access-list 110 extended permit esp object-group japan_site2site_vpn_backup-tokyo-1 host 64.104.14.233 
access-list 110 extended permit udp object-group japan_site2site_vpn_backup-tokyo-1 host 64.104.14.233 eq isakmp 
access-list 110 extended permit esp host 196.203.143.26 host 64.103.35.189 
access-list 110 extended permit udp host 196.203.143.26 host 64.103.35.189 eq isakmp 
access-list 110 extended permit udp host 193.95.99.218 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 211.122.197.174 host 64.104.14.248 
access-list 110 extended permit udp host 211.122.197.174 host 64.104.14.248 eq isakmp 
access-list 110 extended permit esp host 165.228.215.186 host 64.104.213.242 
access-list 110 extended permit udp host 165.228.215.186 host 64.104.213.242 eq isakmp 
access-list 110 extended permit esp host 219.143.103.141 host 72.163.247.99 
access-list 110 extended permit udp host 219.143.103.141 host 72.163.247.99 eq isakmp 
access-list 110 extended permit esp host 219.143.103.142 host 72.163.247.99 
access-list 110 extended permit udp host 219.143.103.142 host 72.163.247.99 eq isakmp 
access-list 110 extended permit tcp any host 64.104.82.5 eq https 
access-list 110 extended permit tcp any host 64.104.82.5 eq 8000 
access-list 110 extended permit esp host 202.140.146.49 64.103.182.192 255.255.255.224 
access-list 110 extended permit udp host 202.140.146.49 64.103.182.192 255.255.255.224 eq isakmp 
access-list 110 extended permit tcp host 202.140.146.49 64.103.182.192 255.255.255.224 eq 18207 
access-list 110 extended permit tcp host 202.140.146.49 64.103.182.192 255.255.255.224 eq 18231 
access-list 110 extended permit esp host 192.8.194.7 64.103.182.192 255.255.255.224 
access-list 110 extended permit ah host 192.8.194.7 64.103.182.192 255.255.255.224 
access-list 110 extended permit udp host 192.8.194.7 64.103.182.192 255.255.255.224 eq isakmp 
access-list 110 extended permit esp any host 72.163.171.2 
access-list 110 extended permit esp any host 72.163.171.4 
access-list 110 extended permit udp any host 72.163.171.2 eq 10000 
access-list 110 extended permit udp any host 72.163.171.4 eq 10000 
access-list 110 extended permit udp any host 72.163.171.2 eq isakmp 
access-list 110 extended permit udp any host 72.163.171.4 eq isakmp 
access-list 110 extended permit tcp any host 72.163.171.2 eq ssh 
access-list 110 extended permit tcp any host 72.163.171.4 eq ssh 
access-list 110 extended permit tcp any host 72.163.171.2 eq https 
access-list 110 extended permit tcp any host 72.163.171.4 eq https 
access-list 110 extended permit esp any host 72.163.130.103 
access-list 110 extended permit esp any host 72.163.215.43 
access-list 110 extended permit udp any host 72.163.130.103 eq 10000 
access-list 110 extended permit udp any host 72.163.215.43 eq 10000 
access-list 110 extended permit udp any host 72.163.130.103 eq isakmp 
access-list 110 extended permit udp any host 72.163.215.43 eq isakmp 
access-list 110 extended permit tcp any host 72.163.130.103 eq ssh 
access-list 110 extended permit tcp any host 72.163.215.43 eq ssh 
access-list 110 extended permit tcp any host 72.163.130.103 eq https 
access-list 110 extended permit tcp any host 72.163.215.43 eq https 
access-list 110 extended permit tcp any host 72.163.215.44 eq https 
access-list 110 extended permit tcp any host 72.163.215.44 eq 8000 
access-list 110 extended permit tcp any host 72.163.248.231 eq www 
access-list 110 extended permit tcp any host 72.163.248.231 eq https 
access-list 110 extended permit udp any host 72.163.248.231 eq 443 
access-list 110 extended permit tcp any host 72.163.248.232 eq www 
access-list 110 extended permit tcp any host 72.163.248.232 eq https 
access-list 110 extended permit udp any host 72.163.248.232 eq 443 
access-list 110 extended permit esp any host 64.104.123.12 
access-list 110 extended permit udp any host 64.104.123.12 eq isakmp 
access-list 110 extended permit tcp host 144.230.95.78 host 64.103.146.65 eq 500 
access-list 110 extended permit udp host 144.230.95.78 host 64.103.146.65 eq isakmp 
access-list 110 extended permit udp host 144.230.95.78 host 64.103.146.65 eq 10001 
access-list 110 extended permit esp host 211.141.83.92 host 64.104.172.43 
access-list 110 extended permit udp host 211.141.83.92 host 64.104.172.43 eq isakmp 
access-list 110 extended permit udp host 211.141.83.92 host 64.104.172.43 eq 50 
access-list 110 extended permit udp host 211.141.83.92 host 64.104.172.43 eq 10000 
access-list 110 extended permit esp host 173.36.116.10 host 66.187.209.105 
access-list 110 extended permit udp host 173.36.116.10 host 66.187.209.105 eq isakmp 
access-list 110 extended permit udp host 173.36.116.10 host 66.187.209.105 eq 4500 
access-list 110 extended permit esp any host 209.82.96.210 
access-list 110 extended permit udp any host 209.82.96.210 eq isakmp 
access-list 110 extended permit udp any host 209.82.96.210 eq 10000 
access-list 110 extended permit tcp any host 12.159.148.22 eq www 
access-list 110 extended permit esp any host 12.159.148.18 
access-list 110 extended permit udp any host 12.159.148.18 eq isakmp 
access-list 110 extended permit udp any host 12.159.148.18 eq 10000 
access-list 110 extended permit tcp any host 12.159.148.18 eq ssh 
access-list 110 extended permit tcp any host 12.159.148.18 eq https 
access-list 110 extended permit esp any host 12.159.148.19 
access-list 110 extended permit udp any host 12.159.148.19 eq isakmp 
access-list 110 extended permit udp any host 12.159.148.19 eq 10000 
access-list 110 extended permit tcp any host 12.159.148.19 eq ssh 
access-list 110 extended permit tcp any host 12.159.148.19 eq https 
access-list 110 extended permit esp any host 12.159.148.20 
access-list 110 extended permit udp any host 12.159.148.20 eq isakmp 
access-list 110 extended permit udp any host 12.159.148.20 eq 10000 
access-list 110 extended permit tcp any host 12.159.148.20 eq ssh 
access-list 110 extended permit tcp any host 12.159.148.20 eq https 
access-list 110 extended permit esp any host 12.159.148.21 
access-list 110 extended permit udp any host 12.159.148.21 eq isakmp 
access-list 110 extended permit udp any host 12.159.148.21 eq 10000 
access-list 110 extended permit tcp any host 12.159.148.21 eq ssh 
access-list 110 extended permit tcp any host 12.159.148.21 eq https 
access-list 110 extended permit esp any host 12.159.148.22 
access-list 110 extended permit udp any host 12.159.148.22 eq isakmp 
access-list 110 extended permit esp any host 12.159.148.23 
access-list 110 extended permit udp any host 12.159.148.23 eq isakmp 
access-list 110 extended permit udp any host 12.159.148.23 eq 4500 
access-list 110 extended permit esp any host 12.159.148.24 
access-list 110 extended permit udp any host 12.159.148.24 eq isakmp 
access-list 110 extended permit udp any host 12.159.148.24 eq 4500 
access-list 110 extended permit tcp any host 12.159.148.25 eq 8000 
access-list 110 extended permit tcp any host 12.159.148.25 eq https 
access-list 110 extended permit esp host 198.135.0.108 any 
access-list 110 extended permit udp host 198.135.0.108 any eq isakmp 
access-list 110 extended permit tcp any host 64.101.105.3 eq https 
access-list 110 extended permit udp any object-group alpha_lwapp-sjc-1 eq 12223 
access-list 110 extended permit udp any host 171.70.35.131 eq 12222 
access-list 110 extended permit udp any host 171.70.35.133 eq 12222 
access-list 110 extended permit udp any host 171.70.35.135 eq 12222 
access-list 110 extended permit udp any host 171.70.35.137 eq 12222 
access-list 110 extended permit udp any object-group alpha_lwapp-sjc-1 eq 5247 
access-list 110 extended permit udp any host 171.70.35.131 eq 5246 
access-list 110 extended permit udp any host 171.70.35.133 eq 5246 
access-list 110 extended permit udp any host 171.70.35.135 eq 5246 
access-list 110 extended permit udp any host 171.70.35.137 eq 5246 
access-list 110 extended permit udp any host 64.102.223.98 eq 12223 
access-list 110 extended permit udp any host 64.102.223.99 eq 12223 
access-list 110 extended permit udp any host 64.102.223.99 eq 12222 
access-list 110 extended permit udp any host 72.163.198.194 eq 12223 
access-list 110 extended permit udp any host 72.163.198.195 eq 12223 
access-list 110 extended permit udp any host 72.163.198.195 eq 12222 
access-list 110 extended permit esp host 212.123.18.140 host 64.103.35.61 
access-list 110 extended permit esp host 213.206.37.58 host 64.103.35.61 
access-list 110 extended permit udp host 212.123.18.140 host 64.103.35.61 eq isakmp 
access-list 110 extended permit udp host 213.206.37.58 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 216.81.81.71 host 64.102.57.50 
access-list 110 extended permit udp host 216.81.81.71 host 64.102.57.50 eq isakmp 
access-list 110 extended permit udp host 216.81.81.71 host 64.102.57.50 eq 4500 
access-list 110 extended permit gre host 64.104.127.65 host 10.75.32.3 
access-list 110 extended permit gre host 64.104.252.65 host 10.66.226.193 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.141.217 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.131.105 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.140.217 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.130.217 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.143.17 
access-list 110 extended permit esp host 194.0.215.146 host 64.103.35.61 
access-list 110 extended permit esp host 194.0.215.146 host 64.103.35.189 
access-list 110 extended permit udp host 194.0.215.146 host 64.103.35.61 eq isakmp 
access-list 110 extended permit udp host 194.0.215.146 host 64.103.35.189 eq isakmp 
access-list 110 extended permit udp any host 144.254.221.36 eq 443 
access-list 110 extended permit udp any host 144.254.221.43 eq 443 
access-list 110 extended permit udp any host 144.254.221.44 eq 443 
access-list 110 extended permit udp any host 171.70.192.182 eq 5246 
access-list 110 extended permit udp any host 171.70.192.182 eq 5247 
access-list 110 extended permit udp any host 171.70.192.183 eq 5246 
access-list 110 extended permit udp any host 171.70.192.183 eq 5247 
access-list 110 extended permit udp any host 171.70.192.184 eq 5246 
access-list 110 extended permit udp any host 171.70.192.184 eq 5247 
access-list 110 extended permit udp any host 171.70.192.185 eq 5246 
access-list 110 extended permit udp any host 171.70.192.185 eq 5247 
access-list 110 extended permit udp any host 171.70.192.186 eq 5246 
access-list 110 extended permit udp any host 171.70.192.186 eq 5247 
access-list 110 extended permit gre host 10.115.8.79 any 
access-list 110 extended permit gre host 10.115.8.80 any 
access-list 110 extended permit gre host 10.81.225.208 any 
access-list 110 extended permit gre host 10.81.225.209 any 
access-list 110 extended permit tcp host 64.103.26.141 host 144.254.208.111 range sip 5061 
access-list 110 extended permit tcp host 64.103.26.141 host 144.254.208.112 range sip 5061 
access-list 110 extended permit tcp host 64.103.26.141 host 144.254.208.113 range sip 5061 
access-list 110 extended permit tcp host 64.103.26.141 host 144.254.208.114 range sip 5061 
access-list 110 extended permit esp host 89.121.2.198 host 64.103.35.189 
access-list 110 extended permit udp host 89.121.2.198 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 196.213.110.234 host 64.103.35.61 
access-list 110 extended permit udp host 196.213.110.234 host 64.103.35.61 eq isakmp 
access-list 110 extended permit tcp host 72.163.8.10 host 173.37.178.201 eq https 
access-list 110 extended permit tcp host 72.163.8.11 host 173.37.178.201 eq https 
access-list 110 extended permit tcp host 72.163.8.10 host 173.37.178.202 eq https 
access-list 110 extended permit tcp host 72.163.8.11 host 173.37.178.202 eq https 
access-list 110 extended permit tcp host 72.163.8.10 host 173.37.178.203 eq https 
access-list 110 extended permit tcp host 72.163.8.11 host 173.37.178.203 eq https 
access-list 110 extended permit tcp host 72.163.8.10 host 72.163.56.102 eq ldaps 
access-list 110 extended permit tcp host 72.163.8.11 host 72.163.56.102 eq ldaps 
access-list 110 extended permit tcp host 72.163.8.10 host 171.68.38.106 eq ldaps 
access-list 110 extended permit tcp host 72.163.8.11 host 171.68.38.106 eq ldaps 
access-list 110 extended permit tcp host 72.163.8.10 host 171.68.224.6 eq ldaps 
access-list 110 extended permit tcp host 72.163.8.11 host 171.68.224.6 eq ldaps 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.132.249 
access-list 110 extended permit tcp host 128.107.81.132 host 171.70.121.28 eq 5443 
access-list 110 extended permit tcp host 128.107.81.132 host 171.70.121.28 eq 9080 
access-list 110 extended permit tcp host 128.107.85.165 host 171.70.121.28 eq 5443 
access-list 110 extended permit tcp host 128.107.85.165 host 171.70.121.28 eq 9080 
access-list 110 extended permit tcp host 128.107.83.10 host 10.34.30.35 range sip 5061 
access-list 110 extended permit tcp object-group sjc_wgsx-sjc-1 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp object-group sjc_wgsx-sjc-1 host 72.163.57.6 eq ldap 
access-list 110 extended permit tcp object-group sjc_wgsx-sjc-1 host 64.102.9.230 eq ldaps 
access-list 110 extended permit tcp object-group sjc_wgsx-sjc-1 host 72.163.57.6 eq ldaps 
access-list 110 extended permit tcp 128.107.227.224 255.255.255.240 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp 128.107.227.224 255.255.255.240 host 72.163.57.6 eq ldap 
access-list 110 extended permit tcp 128.107.242.0 255.255.255.128 host 64.102.9.230 eq ldap 
access-list 110 extended permit tcp 128.107.242.0 255.255.255.128 host 72.163.57.6 eq ldap 
access-list 110 extended permit tcp 128.107.227.224 255.255.255.240 host 64.102.9.230 eq ldaps 
access-list 110 extended permit tcp 128.107.227.224 255.255.255.240 host 72.163.57.6 eq ldaps 
access-list 110 extended permit tcp 128.107.242.0 255.255.255.128 host 64.102.9.230 eq ldaps 
access-list 110 extended permit tcp 128.107.242.0 255.255.255.128 host 72.163.57.6 eq ldaps 
access-list 110 extended permit esp host 41.250.250.139 host 64.103.35.189 
access-list 110 extended permit gre host 41.250.250.139 host 64.103.35.189 
access-list 110 extended permit tcp object-group rtp_wgsx-rtp-1 object-group ldap_dsx_servers-global-1 eq ldap 
access-list 110 extended permit tcp object-group rtp_wgsx-rtp-1 object-group ldap_dsx_servers-global-1 eq ldaps 
access-list 110 extended permit tcp host 128.107.233.108 host 171.68.224.207 eq ldap 
access-list 110 extended permit tcp host 128.107.233.108 host 171.68.224.207 eq ldaps 
access-list 110 extended permit esp host 58.210.240.126 host 72.163.247.99 
access-list 110 extended permit udp host 58.210.240.126 host 72.163.247.99 eq isakmp 
access-list 110 extended permit tcp host 64.102.240.9 host 172.26.172.170 eq 5443 
access-list 110 extended permit tcp host 64.102.240.9 host 172.26.172.170 eq 9080 
access-list 110 extended permit gre host 64.103.36.241 host 216.128.58.217 
access-list 110 extended permit gre host 64.103.36.241 host 216.128.59.57 
access-list 110 extended permit gre host 64.103.36.241 host 10.53.41.2 
access-list 110 extended permit gre host 64.104.252.65 host 10.67.45.129 
access-list 110 extended permit udp host 72.163.251.208 any eq sip 
access-list 110 extended permit udp host 72.163.251.209 any eq sip 
access-list 110 extended permit udp host 72.163.251.210 any eq sip 
access-list 110 extended permit udp host 72.163.251.208 any eq 5070 
access-list 110 extended permit udp host 72.163.251.209 any eq 5070 
access-list 110 extended permit udp host 72.163.251.210 any eq 5070 
access-list 110 extended permit udp host 72.163.251.208 any range 50000 52900 
access-list 110 extended permit udp host 72.163.251.209 any range 50000 52900 
access-list 110 extended permit udp host 72.163.251.210 any range 50000 52900 
access-list 110 extended permit udp host 72.163.251.208 any 
access-list 110 extended permit udp host 72.163.251.209 any 
access-list 110 extended permit udp host 72.163.251.210 any 
access-list 110 extended deny ip object-group cisco_internal_networks-global-1 any 
access-list 110 extended permit udp 144.254.51.64 255.255.255.240 any range 4000 65000 
access-list 110 extended permit tcp host 128.107.243.30 host 173.37.181.22 eq www 
access-list 110 extended permit tcp host 128.107.243.30 host 173.37.181.22 eq https 
access-list 110 extended permit tcp host 128.107.243.30 host 173.37.181.22 range 50120 50121 
access-list 110 extended permit tcp host 128.107.243.30 host 173.37.181.23 eq www 
access-list 110 extended permit tcp host 128.107.243.30 host 173.37.181.23 eq https 
access-list 110 extended permit udp 128.107.87.0 255.255.255.0 10.35.204.0 255.255.255.0 eq sip 
access-list 110 extended permit udp 128.107.87.0 255.255.255.0 10.35.204.0 255.255.255.0 range 4000 65000 
access-list 110 extended permit udp 128.107.231.0 255.255.255.0 10.35.204.0 255.255.255.0 eq sip 
access-list 110 extended permit udp 128.107.231.0 255.255.255.0 10.35.204.0 255.255.255.0 range 4000 65000 
access-list 110 extended permit tcp 128.107.87.0 255.255.255.0 10.35.204.0 255.255.255.0 eq sip 
access-list 110 extended permit tcp 128.107.231.0 255.255.255.0 10.35.204.0 255.255.255.0 eq sip 
access-list 110 extended permit icmp 128.107.87.0 255.255.255.0 10.35.204.0 255.255.255.0 
access-list 110 extended permit icmp 128.107.231.0 255.255.255.0 10.35.204.0 255.255.255.0 
access-list 110 extended permit tcp host 128.107.82.106 host 128.107.201.136 eq 2776 
access-list 110 extended permit tcp host 128.107.82.106 host 128.107.201.136 eq 7006 
access-list 110 extended permit udp host 128.107.82.106 host 128.107.201.136 eq 2776 
access-list 110 extended permit udp host 128.107.82.106 host 128.107.201.136 eq 2777 
access-list 110 extended permit udp host 128.107.82.106 host 128.107.201.136 eq 6006 
access-list 110 extended permit tcp host 128.107.82.106 host 10.35.202.2 eq 2776 
access-list 110 extended permit tcp host 128.107.82.106 host 10.35.202.2 eq 7006 
access-list 110 extended permit udp host 128.107.82.106 host 10.35.202.2 eq 2776 
access-list 110 extended permit udp host 128.107.82.106 host 10.35.202.2 eq 2777 
access-list 110 extended permit udp host 128.107.82.106 host 10.35.202.2 eq 6006 
access-list 110 extended permit udp 59.151.13.0 255.255.255.0 any eq 9000 
access-list 110 extended permit udp 59.151.14.0 255.255.255.0 any eq 9000 
access-list 110 extended permit udp 59.151.107.0 255.255.255.0 any eq 9000 
access-list 110 extended permit tcp host 128.107.85.182 object-group webex_as_lab_onetouch_src_ports host 10.35.126.29 object-group webex_as_lab_onetouch_destination_ports 
access-list 110 extended permit udp host 128.107.85.182 object-group webex_as_lab_onetouch_src_ports host 10.35.126.29 object-group webex_as_lab_onetouch_destination_ports 
access-list 110 extended permit tcp host 128.107.85.182 range 40000 49999 host 10.35.126.29 eq ldaps 
access-list 110 extended permit udp object-group sj_alpha_vcs_express eq 902 object-group sj_alpha_vcs_control 
access-list 110 extended permit tcp host 128.107.85.181 eq 4443 host 10.35.63.127 
access-list 110 extended permit tcp host 128.107.85.181 eq 5061 host 10.35.63.127 
access-list 110 extended permit tcp host 128.107.85.181 eq 4443 host 10.35.63.66 
access-list 110 extended permit tcp host 128.107.85.181 eq 5061 host 10.35.63.66 
access-list 110 extended permit tcp host 128.107.85.181 eq domain host 10.35.63.66 
access-list 110 extended permit udp host 128.107.85.181 eq domain host 10.35.63.66 
access-list 110 extended permit tcp host 128.107.85.188 eq domain host 10.35.63.66 
access-list 110 extended permit udp host 128.107.85.188 eq domain host 10.35.63.66 
access-list 110 extended permit tcp host 128.107.85.188 eq www host 10.35.63.66 
access-list 110 extended permit tcp host 128.107.85.188 eq https host 10.35.63.66 
access-list 110 extended permit tcp host 128.107.85.181 host 10.35.63.66 eq www 
access-list 110 extended permit tcp host 128.107.85.181 host 10.35.63.66 eq https 
access-list 110 extended permit tcp host 128.107.85.188 host 10.35.63.66 eq www 
access-list 110 extended permit tcp host 128.107.85.188 host 10.35.63.66 eq https 
access-list 110 extended permit gre host 72.163.216.168 host 10.105.77.33 
access-list 110 extended permit gre host 64.104.127.65 host 10.79.90.160 
access-list 110 extended permit gre host 64.104.127.65 host 10.225.51.65 
access-list 110 extended permit gre host 64.104.127.65 host 10.225.35.65 
access-list 110 extended permit gre host 64.104.44.97 host 10.70.218.225 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.16 
access-list 110 extended permit gre host 72.163.216.168 host 10.105.159.1 
access-list 110 extended permit gre host 64.104.95.129 host 10.68.137.1 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.28 
access-list 110 extended permit esp host 61.47.104.214 host 64.104.77.181 
access-list 110 extended permit udp host 61.47.104.214 host 64.104.77.181 eq isakmp 
access-list 110 extended permit gre host 72.163.216.168 host 10.143.14.160 
access-list 110 extended permit gre host 72.163.216.168 host 10.64.47.164 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.4 
access-list 110 extended permit esp host 121.171.235.34 host 64.104.123.9 
access-list 110 extended permit udp host 121.171.235.34 host 64.104.123.9 eq isakmp 
access-list 110 extended permit udp host 121.171.235.34 host 64.104.123.9 eq 4500 
access-list 110 extended permit esp host 41.206.22.34 host 64.103.35.61 
access-list 110 extended permit udp host 41.206.22.34 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 89.216.55.50 host 64.103.35.189 
access-list 110 extended permit udp host 89.216.55.50 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 213.33.232.86 host 64.103.35.189 
access-list 110 extended permit udp host 213.33.232.86 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 195.146.148.2 host 64.103.35.61 
access-list 110 extended permit udp host 195.146.148.2 host 64.103.35.61 eq isakmp 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.23 
access-list 110 extended permit udp host 173.38.154.55 any range 4000 65000 
access-list 110 extended permit esp host 178.188.118.54 host 64.103.35.189 
access-list 110 extended permit udp host 178.188.118.54 host 64.103.35.189 eq isakmp 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.25 
access-list 110 extended permit gre host 10.49.68.21 host 64.103.36.241 
access-list 110 extended permit tcp 10.61.46.128 255.255.255.128 host 144.254.230.49 eq 445 
access-list 110 extended permit udp 10.61.46.128 255.255.255.128 host 144.254.230.49 eq tftp 
access-list 110 extended permit esp host 120.28.34.166 host 64.104.88.231 
access-list 110 extended permit udp host 120.28.34.166 host 64.104.88.231 eq isakmp 
access-list 110 extended permit esp host 213.160.19.202 host 64.103.35.61 
access-list 110 extended permit udp host 213.160.19.202 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 178.124.194.78 host 64.103.35.189 
access-list 110 extended permit udp host 178.124.194.78 host 64.103.35.189 eq isakmp 
access-list 110 extended permit tcp host 128.107.85.189 object-group webex_as_lab_onetouch_src_ports host 10.35.126.29 object-group webex_as_lab_onetouch_destination_ports 
access-list 110 extended permit udp host 128.107.85.189 object-group webex_as_lab_onetouch_src_ports host 10.35.126.29 object-group webex_as_lab_onetouch_destination_ports 
access-list 110 extended permit esp host 175.139.202.54 host 64.104.77.181 
access-list 110 extended permit udp host 175.139.202.54 host 64.104.77.181 eq isakmp 
access-list 110 extended permit udp host 175.139.202.54 host 64.104.77.181 eq 4500 
access-list 110 extended permit tcp any host 209.82.96.210 eq https 
access-list 110 extended permit udp any host 209.82.96.210 eq 443 
access-list 110 extended permit tcp host 208.90.56.0 host 64.102.12.58 eq https 
access-list 110 extended permit tcp host 208.90.56.1 host 64.102.12.58 eq https 
access-list 110 extended permit tcp host 208.90.56.2 host 64.102.12.58 eq https 
access-list 110 extended permit tcp host 208.90.56.0 host 64.102.12.60 eq https 
access-list 110 extended permit tcp host 208.90.56.1 host 64.102.12.60 eq https 
access-list 110 extended permit tcp host 208.90.56.2 host 64.102.12.60 eq https 
access-list 110 extended permit tcp host 208.90.56.0 host 173.36.128.10 eq https 
access-list 110 extended permit tcp host 208.90.56.1 host 173.36.128.10 eq https 
access-list 110 extended permit tcp host 208.90.56.2 host 173.36.128.10 eq https 
access-list 110 extended permit tcp host 208.90.56.0 host 173.36.128.13 eq https 
access-list 110 extended permit tcp host 208.90.56.1 host 173.36.128.13 eq https 
access-list 110 extended permit tcp host 208.90.56.2 host 173.36.128.13 eq https 
access-list 110 extended permit tcp any object-group V4-ETE-ORION-SERVERS eq https 
access-list 110 extended permit tcp any host 171.68.106.20 eq 2000 
access-list 110 extended permit tcp any host 171.68.106.20 eq 2443 
access-list 110 extended permit tcp any host 171.68.106.20 eq sip 
access-list 110 extended permit tcp any host 171.68.106.20 eq 5061 
access-list 110 extended permit tcp any host 171.68.106.20 eq 3804 
access-list 110 extended permit udp any host 171.68.106.20 eq tftp 
access-list 110 extended permit tcp any host 171.68.106.21 eq 2000 
access-list 110 extended permit tcp any host 171.68.106.21 eq 2443 
access-list 110 extended permit tcp any host 171.68.106.21 eq sip 
access-list 110 extended permit tcp any host 171.68.106.21 eq 5061 
access-list 110 extended permit tcp any host 171.68.106.21 eq 3804 
access-list 110 extended permit udp any host 171.68.106.21 eq tftp 
access-list 110 extended permit udp any host 171.68.106.22 range 16384 32767 
access-list 110 extended permit esp host 50.20.130.93 host 171.69.7.185 
access-list 110 extended permit udp host 50.20.130.93 host 171.69.7.185 eq isakmp 
access-list 110 extended permit udp host 50.20.130.93 host 171.69.7.185 eq 4500 
access-list 110 extended permit esp host 64.127.109.94 host 171.71.238.29 
access-list 110 extended permit udp host 64.127.109.94 host 171.71.238.29 eq isakmp 
access-list 110 extended permit udp host 64.127.109.94 host 171.71.238.29 eq 4500 
access-list 110 extended permit esp host 64.127.109.94 host 171.69.7.185 
access-list 110 extended permit udp host 64.127.109.94 host 171.69.7.185 eq isakmp 
access-list 110 extended permit udp host 64.127.109.94 host 171.69.7.185 eq 4500 
access-list 110 extended permit esp host 112.95.169.62 host 72.163.247.98 
access-list 110 extended permit udp host 112.95.169.62 host 72.163.247.98 eq isakmp 
access-list 110 extended permit tcp host 128.107.246.212 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.212 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.213 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.213 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.214 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.214 host 171.68.155.30 eq https 
access-list 110 extended permit esp host 212.77.218.226 host 64.103.35.189 
access-list 110 extended permit udp host 212.77.218.226 host 64.103.35.189 eq isakmp 
access-list 110 extended permit udp host 119.151.96.2 host 64.104.155.210 eq isakmp 
access-list 110 extended permit gre host 119.151.96.2 host 64.104.155.210 
access-list 110 extended permit esp host 119.151.96.2 host 64.104.155.210 
access-list 110 extended permit esp host 198.32.107.15 host 64.102.252.253 
access-list 110 extended permit udp host 198.32.107.15 host 64.102.252.253 eq isakmp 
access-list 110 extended permit esp host 198.32.107.15 host 171.71.238.13 
access-list 110 extended permit udp host 198.32.107.15 host 171.71.238.13 eq isakmp 
access-list 110 extended permit esp host 222.62.77.124 host 72.163.247.99 
access-list 110 extended permit udp host 222.62.77.124 host 72.163.247.99 eq isakmp 
access-list 110 extended permit esp host 61.91.245.114 host 64.104.83.33 
access-list 110 extended permit udp host 61.91.245.114 host 64.104.83.33 eq isakmp 
access-list 110 extended permit esp host 115.236.30.155 host 72.163.247.98 
access-list 110 extended permit udp host 115.236.30.155 host 72.163.247.98 eq isakmp 
access-list 110 extended permit esp host 124.155.203.226 host 64.104.77.181 
access-list 110 extended permit udp host 124.155.203.226 host 64.104.77.181 eq isakmp 
access-list 110 extended permit esp host 120.28.34.166 host 64.104.83.33 
access-list 110 extended permit udp host 120.28.34.166 host 64.104.83.33 eq isakmp 
access-list 110 extended permit udp any host 72.163.19.132 eq 443 
access-list 110 extended permit udp any host 72.163.19.133 eq 443 
access-list 110 extended permit udp any host 72.163.19.134 eq 443 
access-list 110 extended permit udp any host 72.163.19.135 eq 443 
access-list 110 extended permit udp any host 72.163.19.136 eq 443 
access-list 110 extended permit ip host 67.202.204.185 host 64.101.102.5 
access-list 110 extended permit ip host 67.202.204.185 host 64.101.102.6 
access-list 110 extended permit ip host 208.185.216.6 host 64.101.102.5 
access-list 110 extended permit ip host 208.185.216.6 host 64.101.102.6 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.27 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.26 
access-list 110 extended permit gre host 64.104.127.65 host 10.74.249.65 
access-list 110 extended permit tcp host 128.107.246.215 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.215 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.216 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.216 host 171.68.155.30 eq https 
access-list 110 extended permit tcp host 128.107.246.217 host 171.68.155.30 eq www 
access-list 110 extended permit tcp host 128.107.246.217 host 171.68.155.30 eq https 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.22 
access-list 110 extended permit esp host 110.170.20.162 host 64.104.77.181 
access-list 110 extended permit udp host 110.170.20.162 host 64.104.77.181 eq isakmp 
access-list 110 extended permit esp host 213.168.31.106 host 64.103.35.189 
access-list 110 extended permit udp host 213.168.31.106 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 195.200.190.106 host 64.103.35.189 
access-list 110 extended permit udp host 195.200.190.106 host 64.103.35.189 eq isakmp 
access-list 110 extended permit gre host 64.103.36.241 host 10.49.68.24 
access-list 110 extended permit esp host 221.120.194.254 host 64.103.35.189 
access-list 110 extended permit udp host 221.120.194.254 host 64.103.35.189 eq isakmp 
access-list 110 extended permit esp host 221.120.194.254 host 64.103.35.61 
access-list 110 extended permit udp host 221.120.194.254 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 84.205.102.23 host 64.103.35.61 
access-list 110 extended permit udp host 84.205.102.23 host 64.103.35.61 eq isakmp 
access-list 110 extended permit udp host 84.205.102.23 host 64.103.35.61 eq 4500 
access-list 110 extended permit udp host 119.151.96.2 host 64.104.155.146 eq isakmp 
access-list 110 extended permit gre host 119.151.96.2 host 64.104.155.146 
access-list 110 extended permit esp host 119.151.96.2 host 64.104.155.146 
access-list 110 extended permit gre host 65.88.237.59 host 64.100.45.169 
access-list 110 extended permit udp host 65.88.237.59 host 64.100.45.169 eq isakmp 
access-list 110 extended permit esp host 65.88.237.59 host 64.100.45.169 
access-list 110 extended permit tcp any host 144.254.221.45 eq https 
access-list 110 extended permit tcp any host 144.254.221.46 eq https 
access-list 110 remark permit from GES remote site to NG HUBS (DMVPN)
access-list 110 extended permit udp object-group GES_GLOBAL_NG_REMOTE_RLANVPN_DMVPN object-group GES_GLOBAL_NG_HUBS_DMVPN eq isakmp 
access-list 110 extended permit esp object-group GES_GLOBAL_NG_REMOTE_RLANVPN_DMVPN object-group GES_GLOBAL_NG_HUBS_DMVPN 
access-list 110 extended permit icmp object-group GES_GLOBAL_NG_REMOTE_RLANVPN_DMVPN object-group GES_GLOBAL_NG_HUBS_DMVPN echo 
access-list 110 extended permit esp host 80.188.11.74 host 64.103.35.61 
access-list 110 extended permit udp host 80.188.11.74 host 64.103.35.61 eq isakmp 
access-list 110 extended permit esp host 184.94.240.210 host 171.70.203.162 
access-list 110 extended permit esp host 184.94.240.211 host 171.70.203.162 
access-list 110 extended permit udp host 184.94.240.210 host 171.70.203.162 eq isakmp 
access-list 110 extended permit udp host 184.94.240.211 host 171.70.203.162 eq isakmp 
access-list 110 extended permit esp host 68.166.109.210 host 64.102.252.253 
access-list 110 extended permit udp host 68.166.109.210 host 64.102.252.253 eq isakmp 
access-list 110 extended permit esp host 68.166.109.210 host 171.71.238.13 
access-list 110 extended permit udp host 68.166.109.210 host 171.71.238.13 eq isakmp 
access-list 110 extended permit esp host 74.217.3.61 host 64.100.45.169 
access-list 110 extended permit udp host 74.217.3.61 host 64.100.45.169 eq isakmp 
access-list 110 extended permit gre host 64.103.36.241 host 144.254.141.25 
access-list 110 extended permit esp host 58.240.229.98 host 72.163.247.98 
access-list 110 extended permit udp host 58.240.229.98 host 72.163.247.98 eq isakmp 
access-list 110 extended permit udp 144.254.51.80 255.255.255.240 10.50.179.0 255.255.255.0 eq 6001 
access-list 110 extended permit udp 144.254.51.80 255.255.255.240 10.50.179.0 255.255.255.0 eq 1719 
access-list 110 extended permit udp 144.254.51.80 255.255.255.240 10.50.179.0 255.255.255.0 eq 5050 
access-list 110 extended permit udp 144.254.51.80 255.255.255.240 10.50.179.0 255.255.255.0 eq 2776 
access-list 110 extended permit udp 144.254.51.80 255.255.255.240 10.50.179.0 255.255.255.0 eq 2777 
access-list 110 extended permit tcp 144.254.51.80 255.255.255.240 10.50.179.0 255.255.255.0 eq 2776 
access-list 110 extended permit tcp 144.254.51.80 255.255.255.240 10.50.179.0 255.255.255.0 eq 2777 
access-list 110 extended permit udp 144.254.51.80 255.255.255.240 10.50.179.0 255.255.255.0 range 50000 54999 
access-list 110 extended permit tcp host 128.107.82.105 host 10.35.150.26 eq 2776 
access-list 110 extended permit tcp host 128.107.82.105 host 10.35.150.26 eq 7006 
access-list 110 extended permit udp host 128.107.82.105 host 10.35.150.26 eq 2776 
access-list 110 extended permit udp host 128.107.82.105 host 10.35.150.26 eq 2777 
access-list 110 extended permit udp host 128.107.82.105 host 10.35.150.26 eq 6006 
access-list 110 extended permit tcp host 128.107.82.106 host 10.35.150.26 eq 2776 
access-list 110 extended permit tcp host 128.107.82.106 host 10.35.150.26 eq 7006 
access-list 110 extended permit udp host 128.107.82.106 host 10.35.150.26 eq 2776 
access-list 110 extended permit udp host 128.107.82.106 host 10.35.150.26 eq 2777 
access-list 110 extended permit udp host 128.107.82.106 host 10.35.150.26 eq 6006 
access-list 110 extended permit udp host 173.36.192.20 host 10.35.48.55 eq 902 
access-list 110 extended permit udp host 173.36.192.29 host 10.35.48.55 eq 902 
access-list 110 extended permit udp host 173.36.192.20 host 10.35.48.75 eq snmptrap 
access-list 110 extended permit udp host 173.36.192.29 host 10.35.48.75 eq snmptrap 
access-list 110 extended permit udp host 173.36.192.20 host 10.35.48.76 eq snmptrap 
access-list 110 extended permit udp host 173.36.192.29 host 10.35.48.76 eq snmptrap 
access-list 110 extended permit udp host 173.36.192.20 host 10.35.48.77 eq snmptrap 
access-list 110 extended permit udp host 173.36.192.29 host 10.35.48.77 eq snmptrap 
access-list 110 extended permit udp host 173.36.192.20 host 10.35.48.78 eq snmptrap 
access-list 110 extended permit udp host 173.36.192.29 host 10.35.48.78 eq snmptrap 
access-list 110 extended permit udp host 173.36.192.20 host 10.42.4.76 eq snmptrap 
access-list 110 extended permit udp host 173.36.192.29 host 10.42.4.76 eq snmptrap 
access-list 110 extended permit udp host 173.36.192.20 host 10.35.48.75 eq syslog 
access-list 110 extended permit udp host 173.36.192.20 host 10.35.48.76 eq syslog 
access-list 110 extended permit udp host 173.36.192.20 host 10.35.48.77 eq syslog 
access-list 110 extended permit udp host 173.36.192.20 host 10.35.48.78 eq syslog 
access-list 110 extended permit udp host 173.36.192.20 host 10.42.4.76 eq syslog 
access-list 110 extended permit tcp host 173.36.192.20 host 10.35.48.55 eq 7651 
access-list 110 extended permit tcp host 173.36.192.20 host 10.35.48.55 eq 7652 
access-list 110 extended permit tcp host 173.36.192.20 host 10.35.48.55 eq 7653 
access-list 110 extended permit tcp host 64.100.8.211 host 172.18.136.210 range 25000 25999 
access-list 110 extended permit udp host 64.100.8.211 host 172.18.136.210 range 50000 52399 
access-list 110 extended permit tcp host 80.195.68.81 host 192.133.190.241 eq www 
access-list 110 extended permit tcp host 80.195.68.81 host 192.133.190.194 eq www 
access-list 110 extended permit tcp host 80.195.68.81 host 192.133.190.241 eq https 
access-list 110 extended permit tcp host 80.195.68.81 host 192.133.190.194 eq https 
access-list 110 extended permit esp host 196.192.9.242 host 64.103.35.61 
access-list 110 extended permit udp host 196.192.9.242 host 64.103.35.61 eq isakmp 
access-list 110 extended permit gre host 64.102.242.226 any 
access-list 110 extended permit esp host 64.102.242.226 any 
access-list 110 extended permit udp host 64.102.242.226 any eq isakmp 
access-list 110 extended deny ip any any

access-list 102 remark MANAGED BY FIREDRILL - last revision details - joephili - rev(1.531) - Sun May 19 21_29_37 2013
access-list 102 remark last n2i details - joephili - Sun May 19 21_40_43 2013
access-list 102 extended deny udp any any eq 1434 
access-list 102 extended permit udp host 64.104.213.240 host 203.174.191.122 eq isakmp 
access-list 102 extended permit udp host 172.17.153.17 host 128.107.225.22 eq 2055 
access-list 102 extended permit udp host 172.17.153.18 host 128.107.225.22 eq 2055 
access-list 102 extended permit udp host 10.54.76.72 host 144.254.51.2 
access-list 102 extended permit udp host 10.54.76.72 host 144.254.51.3 
access-list 102 extended permit udp host 10.54.76.10 host 144.254.51.2 
access-list 102 extended permit udp host 10.54.76.10 host 144.254.51.3 
access-list 102 extended permit udp host 10.68.12.11 host 64.104.94.84 eq 2055 
access-list 102 extended permit udp host 10.68.12.12 host 64.104.94.84 eq 2055 
access-list 102 extended permit udp host 64.101.40.134 any object-group xboxlive_services_udp 
access-list 102 extended permit esp host 72.163.247.98 host 101.95.24.18 
access-list 102 extended permit udp host 72.163.247.98 host 101.95.24.18 eq isakmp 
access-list 102 extended permit esp host 171.70.203.161 host 184.94.240.210 
access-list 102 extended permit esp host 171.70.203.161 host 184.94.240.211 
access-list 102 extended permit udp host 171.70.203.161 host 184.94.240.210 eq isakmp 
access-list 102 extended permit udp host 171.70.203.161 host 184.94.240.211 eq isakmp 
access-list 102 extended permit gre host 64.104.155.211 host 119.151.96.2 
access-list 102 extended permit esp host 64.104.155.211 host 119.151.96.2 
access-list 102 extended permit udp host 64.104.155.211 host 119.151.96.2 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 213.33.209.102 
access-list 102 extended permit udp host 64.103.35.189 host 213.33.209.102 eq isakmp 
access-list 102 extended permit udp host 10.35.146.18 any object-group xboxlive_services_udp 
access-list 102 extended permit gre host 64.104.155.147 host 119.151.96.2 
access-list 102 extended permit esp host 64.104.155.147 host 119.151.96.2 
access-list 102 extended permit udp host 64.104.155.147 host 119.151.96.2 eq isakmp 
access-list 102 extended permit udp any 64.100.10.0 255.255.255.0 range 5246 5247 
access-list 102 extended permit udp any 173.39.116.0 255.255.255.0 range 5246 5247 
access-list 102 extended permit udp any host 64.100.13.100 range 5246 5247 
access-list 102 extended permit udp any host 64.100.13.102 range 5246 5247 
access-list 102 extended permit udp any host 128.107.85.187 eq 6006 
access-list 102 extended permit udp any host 128.107.85.187 eq 1719 
access-list 102 extended permit udp any host 128.107.85.187 eq 2776 
access-list 102 extended permit udp any host 128.107.85.187 eq 2777 
access-list 102 extended permit udp any host 128.107.85.187 range 50000 52399 
access-list 102 extended permit gre host 10.49.68.22 host 64.103.36.241 
access-list 102 extended permit udp object-group uc_cucm_subscribers-sjc-1 object-group uc_verizon_sip_trunk-sjc-1 eq sip 
access-list 102 extended permit gre host 144.254.133.81 host 64.103.36.241 
access-list 102 extended permit gre host 10.79.89.227 host 64.104.127.65 
access-list 102 extended permit gre host 64.100.45.169 host 65.88.237.59 
access-list 102 extended permit udp host 64.100.45.169 host 65.88.237.59 eq isakmp 
access-list 102 extended permit esp host 64.100.45.169 host 65.88.237.59 
access-list 102 extended permit udp host 171.71.3.147 host 128.242.110.162 eq isakmp 
access-list 102 extended permit esp host 171.71.3.147 host 128.242.110.162 
access-list 102 extended permit udp host 171.71.3.148 host 128.242.110.162 eq isakmp 
access-list 102 extended permit esp host 171.71.3.148 host 128.242.110.162 
access-list 102 remark permit from NG HUBS to GES remote site (DMVPN)
access-list 102 extended permit udp object-group GES_GLOBAL_NG_HUBS_DMVPN object-group GES_GLOBAL_NG_REMOTE_RLANVPN_DMVPN eq isakmp 
access-list 102 extended permit esp object-group GES_GLOBAL_NG_HUBS_DMVPN object-group GES_GLOBAL_NG_REMOTE_RLANVPN_DMVPN 
access-list 102 extended permit icmp object-group GES_GLOBAL_NG_HUBS_DMVPN object-group GES_GLOBAL_NG_REMOTE_RLANVPN_DMVPN echo-reply 
access-list 102 extended permit esp host 72.163.247.98 host 58.248.15.173 
access-list 102 extended permit udp host 72.163.247.98 host 58.248.15.173 eq isakmp 
access-list 102 extended permit esp host 72.163.247.98 host 118.122.89.227 
access-list 102 extended permit udp host 72.163.247.98 host 118.122.89.227 eq isakmp 
access-list 102 extended permit udp host 72.163.248.182 eq 5246 any 
access-list 102 extended permit udp host 72.163.248.182 eq 5247 any 
access-list 102 extended permit udp host 72.163.248.183 eq 5246 any 
access-list 102 extended permit udp host 72.163.248.183 eq 5247 any 
access-list 102 extended permit udp host 171.71.3.14 host 68.115.237.40 eq isakmp 
access-list 102 extended permit udp host 171.71.3.14 host 68.115.237.40 eq 4500 
access-list 102 extended permit udp host 171.71.3.26 host 68.115.237.41 eq isakmp 
access-list 102 extended permit udp host 171.71.3.26 host 68.115.237.41 eq 4500 
access-list 102 extended permit tcp any host 72.163.1.151 eq https 
access-list 102 extended permit tcp any host 72.163.1.152 eq https 
access-list 102 extended permit tcp any host 72.163.1.153 eq https 
access-list 102 extended permit tcp any host 72.163.1.154 eq https 
access-list 102 extended permit tcp any host 72.163.1.155 eq https 
access-list 102 extended permit udp any host 128.107.83.83 range 16384 32767 
access-list 102 extended permit udp any host 128.107.83.102 range 16384 32767 
access-list 102 extended permit gre host 10.115.8.67 host 172.17.153.20 
access-list 102 extended permit gre host 10.115.8.68 host 128.107.240.170 
access-list 102 extended permit gre host 172.17.153.20 host 10.115.8.67 
access-list 102 extended permit gre host 128.107.240.170 host 10.115.8.68 
access-list 102 extended permit gre host 128.107.240.24 host 10.68.12.143 
access-list 102 extended permit gre host 128.107.240.170 host 10.68.12.146 
access-list 102 extended permit gre host 10.68.12.143 host 128.107.240.24 
access-list 102 extended permit gre host 10.68.12.146 host 128.107.240.170 
access-list 102 extended permit udp host 10.68.12.139 host 64.104.94.84 eq 2055 
access-list 102 extended permit udp host 10.68.12.140 host 64.104.94.84 eq 2055 
access-list 102 extended permit gre any host 173.39.120.61 
access-list 102 extended permit gre any host 173.39.120.60 
access-list 102 extended permit udp host 64.103.35.189 host 89.216.55.50 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 178.188.118.54 eq isakmp 
access-list 102 extended permit gre host 64.103.36.241 host 10.49.68.21 
access-list 102 extended permit udp host 144.254.146.9 host 145.221.52.14 eq isakmp 
access-list 102 extended permit udp host 10.68.12.135 host 171.71.180.202 range 2055 2065 
access-list 102 extended permit udp host 10.68.12.136 host 171.71.180.202 range 2055 2065 
access-list 102 extended permit esp host 10.224.223.2 host 72.163.249.17 
access-list 102 extended permit udp host 10.224.223.2 host 72.163.249.17 eq isakmp 
access-list 102 extended permit esp host 10.224.97.198 host 72.163.249.17 
access-list 102 extended permit udp host 10.224.97.198 host 72.163.249.17 eq isakmp 
access-list 102 extended permit esp host 10.224.32.54 host 72.163.249.17 
access-list 102 extended permit udp host 10.224.32.54 host 72.163.249.17 eq isakmp 
access-list 102 extended permit udp host 173.37.184.121 any eq isakmp 
access-list 102 extended permit udp host 173.37.184.121 any eq 4500 
access-list 102 extended permit udp host 10.122.102.232 host 64.102.250.49 eq 2776 
access-list 102 extended permit udp host 10.122.102.232 host 64.102.250.49 eq 2777 
access-list 102 extended permit udp host 10.122.102.232 host 64.102.250.50 eq 2776 
access-list 102 extended permit udp host 10.122.102.232 host 64.102.250.50 eq 2777 
access-list 102 extended permit udp host 10.122.102.136 host 64.102.250.49 eq 2776 
access-list 102 extended permit udp host 10.122.102.136 host 64.102.250.49 eq 2777 
access-list 102 extended permit udp host 10.122.102.136 host 64.102.250.50 eq 2776 
access-list 102 extended permit udp host 10.122.102.136 host 64.102.250.50 eq 2777 
access-list 102 extended permit udp host 10.122.102.232 host 64.102.250.49 range 6000 6020 
access-list 102 extended permit udp host 10.122.102.232 host 64.102.250.49 range 50000 54999 
access-list 102 extended permit udp host 10.122.102.232 host 64.102.250.50 range 6000 6020 
access-list 102 extended permit udp host 10.122.102.232 host 64.102.250.50 range 50000 54999 
access-list 102 extended permit udp host 10.122.102.136 host 64.102.250.49 range 6000 6020 
access-list 102 extended permit udp host 10.122.102.136 host 64.102.250.49 range 50000 54999 
access-list 102 extended permit udp host 10.122.102.136 host 64.102.250.50 range 6000 6020 
access-list 102 extended permit udp host 10.122.102.136 host 64.102.250.50 range 50000 54999 
access-list 102 extended permit udp host 10.35.120.50 host 128.107.81.25 eq 902 
access-list 102 extended permit gre host 10.49.68.5 host 64.103.36.241 
access-list 102 extended permit gre any host 10.68.12.18 
access-list 102 extended permit gre any host 10.68.12.19 
access-list 102 extended permit udp object-group raex_oeap-global-1 eq 5246 any 
access-list 102 extended permit udp object-group raex_oeap-global-1 eq 5247 any 
access-list 102 extended permit udp object-group kumo_product_labs-1 object-group amazon_ec2_emea-1 range 6644 6646 
access-list 102 extended permit udp object-group kumo_product_labs-1 object-group amazon_ec2_south_america-1 range 6644 6646 
access-list 102 extended permit udp 10.50.176.0 255.255.240.0 173.38.154.32 255.255.255.224 range 50000 54999 
access-list 102 extended permit udp 10.50.176.0 255.255.240.0 173.38.154.32 255.255.255.224 eq 6001 
access-list 102 extended permit tcp 10.50.176.0 255.255.240.0 173.38.154.32 255.255.255.224 eq 2776 
access-list 102 extended permit tcp 10.50.176.0 255.255.240.0 173.38.154.32 255.255.255.224 eq 2777 
access-list 102 extended permit udp host 10.122.102.121 host 64.102.250.49 eq 2776 
access-list 102 extended permit udp host 10.122.102.121 host 64.102.250.49 eq 2777 
access-list 102 extended permit udp host 10.122.102.121 host 64.102.250.50 eq 2776 
access-list 102 extended permit udp host 10.122.102.121 host 64.102.250.50 eq 2777 
access-list 102 extended permit udp host 10.122.102.121 host 64.102.250.49 range 6000 6020 
access-list 102 extended permit udp host 10.122.102.121 host 64.102.250.49 range 50000 54999 
access-list 102 extended permit udp host 10.122.102.121 host 64.102.250.50 range 6000 6020 
access-list 102 extended permit udp host 10.122.102.121 host 64.102.250.50 range 50000 54999 
access-list 102 extended permit udp host 64.103.35.189 host 178.135.51.58 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 178.135.51.58 eq 4500 
access-list 102 extended permit udp host 64.104.32.84 any eq isakmp 
access-list 102 extended permit esp host 64.104.32.84 any 
access-list 102 extended permit udp host 64.104.32.84 any eq 4500 
access-list 102 extended permit udp host 64.104.32.84 any eq 10000 
access-list 102 extended permit tcp host 64.104.32.84 any eq 10000 
access-list 102 extended permit udp host 64.104.32.84 any eq 443 
access-list 102 extended permit tcp host 64.104.32.84 any eq https 
access-list 102 extended permit udp host 64.104.20.28 host 122.28.177.182 eq isakmp 
access-list 102 extended permit udp host 64.104.20.28 host 122.28.177.182 eq 4500 
access-list 102 extended permit esp host 64.104.20.28 host 122.28.177.182 
access-list 102 extended permit udp host 144.254.146.9 host 188.225.178.102 eq 4500 
access-list 102 extended permit udp host 144.254.146.9 host 217.21.8.90 eq 4500 
access-list 102 extended permit udp host 144.254.146.9 host 82.213.56.18 eq 4500 
access-list 102 extended permit udp host 144.254.146.9 host 196.8.87.17 eq isakmp 
access-list 102 extended permit gre 171.68.144.8 255.255.255.248 host 128.107.235.30 
access-list 102 extended permit udp any host 72.163.250.114 eq 443 
access-list 102 extended permit udp any host 72.163.250.242 eq 443 
access-list 102 extended permit udp any host 72.163.251.114 eq 443 
access-list 102 extended permit udp host 64.103.35.189 host 80.88.240.250 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 178.124.194.78 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 213.160.19.202 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 125.209.121.42 eq isakmp 
access-list 102 extended permit gre host 10.49.68.28 host 64.103.36.241 
access-list 102 extended permit udp any host 144.254.51.160 eq 443 
access-list 102 extended permit udp any host 144.254.51.161 eq 443 
access-list 102 extended permit udp any host 144.254.51.162 eq 443 
access-list 102 extended permit udp any host 144.254.51.163 eq 443 
access-list 102 extended permit udp any host 144.254.51.164 eq 443 
access-list 102 extended permit udp any host 144.254.51.165 eq 443 
access-list 102 extended permit udp any host 144.254.51.166 eq 443 
access-list 102 extended permit udp any host 144.254.51.167 eq 443 
access-list 102 extended permit udp any host 144.254.51.168 eq 443 
access-list 102 extended permit udp any host 144.254.51.169 eq 443 
access-list 102 extended permit gre host 144.254.143.73 host 64.103.36.241 
access-list 102 extended permit ip host 64.101.102.5 host 67.202.204.185 
access-list 102 extended permit ip host 64.101.102.6 host 67.202.204.185 
access-list 102 extended permit ip host 64.101.102.5 host 208.185.216.6 
access-list 102 extended permit ip host 64.101.102.6 host 208.185.216.6 
access-list 102 extended permit udp host 64.103.35.189 host 195.29.137.234 eq isakmp 
access-list 102 extended permit udp any 64.100.9.152 255.255.255.248 range 50000 54999 
access-list 102 extended permit udp any 64.100.9.152 255.255.255.248 range 16384 32766 
access-list 102 extended permit udp any 64.100.9.152 255.255.255.248 eq sip 
access-list 102 extended permit udp any 64.100.9.152 255.255.255.248 eq 2776 
access-list 102 extended permit udp any 64.100.9.152 255.255.255.248 eq 2777 
access-list 102 extended permit udp any 64.100.9.152 255.255.255.248 range 60000 61399 
access-list 102 extended permit udp any 64.100.9.152 255.255.255.248 eq 3478 
access-list 102 extended permit udp any 64.100.9.152 255.255.255.248 eq 443 
access-list 102 extended permit udp any host 64.152.208.63 eq 33001 
access-list 102 extended permit gre host 10.52.123.25 host 64.103.36.18 
access-list 102 extended permit udp host 144.254.146.9 host 193.227.215.161 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 89.107.179.21 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 212.77.218.226 
access-list 102 extended permit udp host 64.103.35.189 host 212.77.218.226 eq isakmp 
access-list 102 extended permit udp host 64.104.155.210 host 119.151.96.2 eq isakmp 
access-list 102 extended permit gre host 64.104.155.210 host 119.151.96.2 
access-list 102 extended permit esp host 64.104.155.210 host 119.151.96.2 
access-list 102 extended permit gre host 10.49.68.25 host 64.103.36.241 
access-list 102 extended permit udp host 216.128.60.197 host 82.178.19.74 eq isakmp 
access-list 102 extended permit gre host 10.72.32.65 host 64.104.127.65 
access-list 102 extended permit udp host 64.103.35.189 host 213.33.232.86 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 195.146.148.2 eq isakmp 
access-list 102 extended permit gre host 10.49.68.23 host 64.103.36.241 
access-list 102 extended permit gre host 10.49.68.17 host 64.103.36.241 
access-list 102 extended permit gre host 10.49.68.19 host 64.103.36.241 
access-list 102 extended permit gre host 10.49.68.20 host 64.103.36.241 
access-list 102 extended permit gre host 10.49.68.1 host 64.103.36.241 
access-list 102 extended permit gre host 10.143.8.65 host 72.163.216.168 
access-list 102 extended permit gre host 10.49.68.8 host 64.103.36.241 
access-list 102 extended permit gre host 10.61.2.122 host 64.103.36.18 
access-list 102 extended permit udp 10.54.64.0 255.255.224.0 host 144.254.51.2 eq 6001 
access-list 102 extended permit udp host 10.194.98.137 host 173.36.203.197 range 2776 2777 
access-list 102 extended permit tcp host 10.194.98.137 host 173.36.203.197 range 7001 7999 
access-list 102 extended permit udp any object-group sj_alpha_vcse eq 6001 
access-list 102 extended permit udp host 10.35.22.18 host 64.103.39.1 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.31 host 64.103.39.1 range snmp snmptrap 
access-list 102 extended permit udp host 171.70.93.61 host 64.103.39.1 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.76 host 64.103.39.1 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.77 host 64.103.39.1 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.78 host 64.103.39.1 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.18 host 72.163.218.194 eq snmp 
access-list 102 extended permit udp host 10.35.22.31 host 72.163.218.194 eq snmp 
access-list 102 extended permit udp host 171.70.93.61 host 72.163.218.194 eq snmp 
access-list 102 extended permit udp host 10.35.48.76 host 72.163.218.194 eq snmp 
access-list 102 extended permit udp host 10.35.48.77 host 72.163.218.194 eq snmp 
access-list 102 extended permit udp host 10.35.48.78 host 72.163.218.194 eq snmp 
access-list 102 extended permit udp host 10.104.80.12 host 72.163.218.194 eq snmp 
access-list 102 extended permit tcp any host 72.163.218.194 eq www 
access-list 102 extended permit tcp any host 72.163.218.194 eq https 
access-list 102 extended permit tcp any host 72.163.218.194 eq ssh 
access-list 102 extended permit tcp any host 72.163.218.194 eq telnet 
access-list 102 extended permit udp any host 72.163.218.194 eq snmp 
access-list 102 extended permit tcp host 10.76.101.203 host 72.163.218.194 eq 7001 
access-list 102 extended permit udp host 10.76.101.203 host 72.163.218.194 eq 2776 
access-list 102 extended permit udp host 10.76.101.203 host 72.163.218.194 eq 2777 
access-list 102 extended permit tcp host 128.107.83.52 host 171.70.168.246 eq tacacs 
access-list 102 extended permit tcp host 128.107.83.52 host 64.102.6.243 eq tacacs 
access-list 102 extended permit tcp host 128.107.83.52 host 64.104.123.228 eq tacacs 
access-list 102 extended permit tcp host 128.107.83.52 host 144.254.71.234 eq tacacs 
access-list 102 extended permit udp host 10.35.22.18 host 128.107.83.0 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.18 host 128.107.83.5 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.18 host 128.107.83.94 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.18 host 128.107.83.52 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.31 host 128.107.83.0 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.31 host 128.107.83.5 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.31 host 128.107.83.94 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.31 host 128.107.83.52 range snmp snmptrap 
access-list 102 extended permit udp host 171.70.93.61 host 128.107.83.0 range snmp snmptrap 
access-list 102 extended permit udp host 171.70.93.61 host 128.107.83.5 range snmp snmptrap 
access-list 102 extended permit udp host 171.70.93.61 host 128.107.83.94 range snmp snmptrap 
access-list 102 extended permit udp host 171.70.93.61 host 128.107.83.52 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.76 host 128.107.83.0 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.76 host 128.107.83.5 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.76 host 128.107.83.94 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.76 host 128.107.83.52 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.77 host 128.107.83.0 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.77 host 128.107.83.5 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.77 host 128.107.83.94 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.77 host 128.107.83.52 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.78 host 128.107.83.0 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.78 host 128.107.83.5 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.78 host 128.107.83.94 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.78 host 128.107.83.52 range snmp snmptrap 
access-list 102 extended permit udp host 144.254.217.132 eq 5246 any 
access-list 102 extended permit udp host 144.254.217.132 eq 5247 any 
access-list 102 extended permit udp host 144.254.217.133 eq 5246 any 
access-list 102 extended permit udp host 144.254.217.133 eq 5247 any 
access-list 102 extended permit udp host 72.163.215.148 eq 5246 any 
access-list 102 extended permit udp host 72.163.215.148 eq 5247 any 
access-list 102 extended permit udp host 72.163.215.149 eq 5246 any 
access-list 102 extended permit udp host 72.163.215.149 eq 5247 any 
access-list 102 extended permit esp host 64.103.209.131 host 115.112.60.222 
access-list 102 extended permit udp host 64.103.209.131 host 115.112.60.222 eq isakmp 
access-list 102 extended permit udp host 64.103.209.132 host 115.112.95.246 eq isakmp 
access-list 102 extended permit udp host 64.104.1.4 eq 5246 any 
access-list 102 extended permit udp host 64.104.1.4 eq 5247 any 
access-list 102 extended permit udp host 64.104.1.5 eq 5246 any 
access-list 102 extended permit udp host 64.104.1.5 eq 5247 any 
access-list 102 extended permit udp host 171.70.192.180 eq 5246 any 
access-list 102 extended permit udp host 171.70.192.180 eq 5247 any 
access-list 102 extended permit udp host 171.70.192.181 eq 5246 any 
access-list 102 extended permit udp host 171.70.192.181 eq 5247 any 
access-list 102 extended permit esp host 64.104.83.33 host 61.47.80.142 
access-list 102 extended permit udp host 64.104.83.33 host 61.47.80.142 eq isakmp 
access-list 102 extended permit gre any host 64.103.36.18 
access-list 102 extended permit gre host 10.75.186.145 host 64.104.127.65 
access-list 102 extended permit esp host 64.104.213.241 host 203.174.180.250 
access-list 102 extended permit udp host 64.104.213.241 host 203.174.180.250 eq isakmp 
access-list 102 extended permit udp host 64.104.213.241 host 203.174.180.250 eq 4500 
access-list 102 extended permit esp host 64.104.213.241 host 203.174.181.154 
access-list 102 extended permit udp host 64.104.213.241 host 203.174.181.154 eq isakmp 
access-list 102 extended permit udp host 64.104.213.241 host 203.174.181.154 eq 4500 
access-list 102 extended permit udp 171.71.216.0 255.255.248.0 host 128.107.87.52 eq 3478 
access-list 102 extended permit udp 171.71.224.0 255.255.248.0 host 128.107.87.52 eq 3478 
access-list 102 extended permit udp 171.71.232.0 255.255.255.0 host 128.107.87.52 eq 3478 
access-list 102 extended permit tcp 171.71.216.0 255.255.248.0 host 128.107.87.52 eq 3478 
access-list 102 extended permit tcp 171.71.224.0 255.255.248.0 host 128.107.87.52 eq 3478 
access-list 102 extended permit tcp 171.71.232.0 255.255.255.0 host 128.107.87.52 eq 3478 
access-list 102 extended permit udp 171.71.216.0 255.255.248.0 host 128.107.87.53 eq 3478 
access-list 102 extended permit udp 171.71.224.0 255.255.248.0 host 128.107.87.53 eq 3478 
access-list 102 extended permit udp 171.71.232.0 255.255.255.0 host 128.107.87.53 eq 3478 
access-list 102 extended permit tcp 171.71.216.0 255.255.248.0 host 128.107.87.53 eq 3478 
access-list 102 extended permit tcp 171.71.224.0 255.255.248.0 host 128.107.87.53 eq 3478 
access-list 102 extended permit tcp 171.71.232.0 255.255.255.0 host 128.107.87.53 eq 3478 
access-list 102 extended permit udp 128.107.138.240 255.255.255.240 host 128.107.87.52 eq 3478 
access-list 102 extended permit udp 128.107.138.240 255.255.255.240 host 128.107.87.53 eq 3478 
access-list 102 extended permit udp host 171.68.46.60 172.17.153.128 255.255.255.240 eq 902 
access-list 102 extended permit udp host 171.68.46.60 172.17.153.144 255.255.255.240 eq 902 
access-list 102 extended permit udp host 171.71.238.13 4.53.16.224 255.255.255.252 eq isakmp 
access-list 102 extended permit esp host 171.71.238.13 4.53.16.224 255.255.255.252 
access-list 102 extended permit udp host 171.71.238.13 4.59.196.36 255.255.255.252 eq isakmp 
access-list 102 extended permit esp host 171.71.238.13 4.59.196.36 255.255.255.252 
access-list 102 extended permit udp host 171.71.238.13 4.71.24.88 255.255.255.252 eq isakmp 
access-list 102 extended permit esp host 171.71.238.13 4.71.24.88 255.255.255.252 
access-list 102 extended permit udp host 171.71.238.13 4.71.160.52 255.255.255.252 eq isakmp 
access-list 102 extended permit esp host 171.71.238.13 4.71.160.52 255.255.255.252 
access-list 102 extended permit udp host 171.71.238.13 4.79.204.224 255.255.255.252 eq isakmp 
access-list 102 extended permit esp host 171.71.238.13 4.79.204.224 255.255.255.252 
access-list 102 extended permit udp host 171.71.238.13 4.71.120.184 255.255.255.252 eq isakmp 
access-list 102 extended permit esp host 171.71.238.13 4.71.120.184 255.255.255.252 
access-list 102 extended permit udp host 64.102.252.253 94.103.18.124 255.255.255.252 eq isakmp 
access-list 102 extended permit esp host 64.102.252.253 94.103.18.124 255.255.255.252 
access-list 102 extended permit udp host 171.71.238.13 94.103.18.124 255.255.255.252 eq isakmp 
access-list 102 extended permit esp host 171.71.238.13 94.103.18.124 255.255.255.252 
access-list 102 extended permit esp host 64.103.35.189 host 194.170.166.186 
access-list 102 extended permit udp host 64.103.35.189 host 194.170.166.186 eq isakmp 
access-list 102 extended permit esp host 64.103.35.61 host 194.170.166.186 
access-list 102 extended permit udp host 64.103.35.61 host 194.170.166.186 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 85.154.235.170 
access-list 102 extended permit udp host 64.103.35.189 host 85.154.235.170 eq isakmp 
access-list 102 extended permit esp host 64.103.35.61 host 82.178.19.74 
access-list 102 extended permit udp host 64.103.35.61 host 82.178.19.74 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 91.151.226.5 
access-list 102 extended permit udp host 64.103.35.189 host 91.151.226.5 eq isakmp 
access-list 102 extended permit udp 10.50.179.0 255.255.255.0 144.254.51.80 255.255.255.240 eq 6001 
access-list 102 extended permit udp 10.50.179.0 255.255.255.0 144.254.51.80 255.255.255.240 eq 1719 
access-list 102 extended permit udp 10.50.179.0 255.255.255.0 144.254.51.80 255.255.255.240 eq 5050 
access-list 102 extended permit udp 10.50.179.0 255.255.255.0 144.254.51.80 255.255.255.240 eq 2776 
access-list 102 extended permit udp 10.50.179.0 255.255.255.0 144.254.51.80 255.255.255.240 eq 2777 
access-list 102 extended permit udp 10.50.179.0 255.255.255.0 144.254.51.80 255.255.255.240 range 50000 54999 
access-list 102 extended permit tcp any host 128.107.87.37 eq smtp 
access-list 102 extended permit udp host 10.88.170.102 host 128.107.81.84 eq isakmp 
access-list 102 extended permit gre any host 10.115.8.79 
access-list 102 extended permit gre any host 10.115.8.80 
access-list 102 extended permit gre any host 10.81.225.208 
access-list 102 extended permit gre any host 10.81.225.209 
access-list 102 extended permit esp host 10.89.46.254 host 128.107.81.84 
access-list 102 extended permit udp host 10.89.46.254 host 128.107.81.84 eq isakmp 
access-list 102 extended permit gre host 10.76.237.97 host 72.163.216.168 
access-list 102 extended permit gre host 10.77.114.137 host 72.163.216.168 
access-list 102 extended permit gre host 10.144.0.1 host 64.103.36.241 
access-list 102 extended permit gre host 10.83.6.114 host 64.102.254.10 
access-list 102 extended permit udp any host 128.107.82.105 eq 6006 
access-list 102 extended permit udp 10.62.72.0 255.255.252.0 host 64.103.24.40 eq 443 
access-list 102 extended permit udp host 10.50.179.6 host 144.254.51.85 
access-list 102 extended permit udp host 10.50.185.135 host 144.254.51.85 
access-list 102 extended permit udp host 10.50.183.6 host 144.254.51.85 
access-list 102 extended permit udp host 10.50.179.6 host 144.254.51.86 
access-list 102 extended permit udp host 10.50.185.135 host 144.254.51.86 
access-list 102 extended permit udp host 10.50.183.6 host 144.254.51.86 
access-list 102 extended permit udp host 144.254.146.9 host 194.60.106.87 eq isakmp 
access-list 102 extended permit udp any 144.254.51.64 255.255.255.240 eq snmp 
access-list 102 extended permit udp any 144.254.51.64 255.255.255.240 eq 1719 
access-list 102 extended permit udp any 144.254.51.64 255.255.255.240 range 2776 2777 
access-list 102 extended permit udp any 144.254.51.64 255.255.255.240 range 4000 65000 
access-list 102 extended permit tcp any object-group sj_alpha_vcse eq 2776 
access-list 102 extended permit tcp any object-group sj_alpha_vcse eq 5061 
access-list 102 extended permit udp any object-group sj_alpha_vcse eq 1719 
access-list 102 extended permit udp any object-group sj_alpha_vcse eq 2776 
access-list 102 extended permit udp any object-group sj_alpha_vcse eq 2777 
access-list 102 extended permit udp any object-group sj_alpha_vcse range 50000 52399 
access-list 102 extended permit udp host 64.100.209.212 host 64.102.249.41 
access-list 102 extended permit udp host 64.100.209.212 host 64.102.249.42 
access-list 102 extended permit udp host 64.100.209.212 host 64.102.249.43 
access-list 102 extended permit udp host 64.100.209.212 host 64.102.249.44 
access-list 102 extended permit udp host 64.100.209.213 host 64.102.249.41 
access-list 102 extended permit udp host 64.100.209.213 host 64.102.249.42 
access-list 102 extended permit udp host 64.100.209.213 host 64.102.249.43 
access-list 102 extended permit udp host 64.100.209.213 host 64.102.249.44 
access-list 102 extended permit udp host 64.100.209.214 host 64.102.249.41 
access-list 102 extended permit udp host 64.100.209.214 host 64.102.249.42 
access-list 102 extended permit udp host 64.100.209.214 host 64.102.249.43 
access-list 102 extended permit udp host 64.100.209.214 host 64.102.249.44 
access-list 102 extended permit tcp any host 128.107.82.105 eq 2776 
access-list 102 extended permit tcp any host 128.107.82.105 eq 5061 
access-list 102 extended permit udp any host 128.107.82.105 eq 1719 
access-list 102 extended permit udp any host 128.107.82.105 eq 2776 
access-list 102 extended permit udp any host 128.107.82.105 eq 2777 
access-list 102 extended permit udp any host 128.107.82.105 range 50000 52399 
access-list 102 extended permit udp 128.107.138.240 255.255.255.240 any range 16000 32000 
access-list 102 extended permit udp 128.107.139.16 255.255.255.240 any range 16000 32000 
access-list 102 extended permit udp 128.107.139.16 255.255.255.240 any eq 3478 
access-list 102 extended permit udp any any eq 3478 
access-list 102 extended permit udp host 171.70.192.164 any eq isakmp 
access-list 102 extended permit udp host 171.70.192.165 any eq isakmp 
access-list 102 extended permit esp host 64.104.77.181 host 211.25.222.190 
access-list 102 extended permit udp host 64.104.77.181 host 211.25.222.190 eq isakmp 
access-list 102 extended permit udp host 64.104.77.181 host 211.25.222.190 eq 4500 
access-list 102 extended permit esp host 64.104.77.181 host 175.139.202.53 
access-list 102 extended permit udp host 64.104.77.181 host 175.139.202.53 eq isakmp 
access-list 102 extended permit udp host 64.104.77.181 host 175.139.202.53 eq 4500 
access-list 102 extended permit udp host 144.254.146.9 host 193.254.166.5 eq isakmp 
access-list 102 extended permit esp host 64.104.77.181 host 211.25.222.182 
access-list 102 extended permit udp host 64.104.77.181 host 211.25.222.182 eq isakmp 
access-list 102 extended permit udp host 64.104.77.181 host 211.25.222.182 eq 4500 
access-list 102 extended permit esp host 64.104.77.181 host 211.25.222.186 
access-list 102 extended permit udp host 64.104.77.181 host 211.25.222.186 eq isakmp 
access-list 102 extended permit udp host 64.104.77.181 host 211.25.222.186 eq 4500 
access-list 102 extended permit ip any object-group dmz_loopbacks-singapore-1 
access-list 102 extended permit ip any object-group dmz_loopbacks-hk-1 
access-list 102 extended permit ip any object-group dmz_loopbacks-bgl-1 
access-list 102 extended permit ip any object-group dmz_loopbacks-isr-1 
access-list 102 extended permit ip any object-group dmz_loopbacks-japan-1 
access-list 102 extended permit ip any object-group dmz_loopbacks-aus-1 
access-list 102 extended permit ip any object-group dmz_loopbacks-ams-1 
access-list 102 extended permit ip any object-group ext_loopbacks_rtp 
access-list 102 extended permit ip any object-group dmz_loopbacks-bxb-1 
access-list 102 extended permit ip any object-group dmz_loopbacks-rich-1 
access-list 102 extended permit ip any object-group dmz_loopbacks-brnt-1 
access-list 102 extended permit ip any object-group dmz_loopbacks-vancouver-1 
access-list 102 extended permit ip any object-group dmz_loopbacks-rcdn9-1 
access-list 102 extended permit ip any object-group dmz_loopbacks-alln-1 
access-list 102 extended permit ip any object-group dmz_loopbacks-shanghai-1 
access-list 102 extended permit ip any object-group dmz_loopbacks-sjc-1 
access-list 102 extended permit ip any 72.163.216.200 255.255.255.248 
access-list 102 extended permit eigrp any any 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 any range 33434 33600 
access-list 102 extended permit udp object-group skinny_cm-alpha-1 host 128.107.233.36 range 1024 65525 
access-list 102 extended permit udp 128.107.96.0 255.255.224.0 host 128.107.241.124 eq mobile-ip 
access-list 102 extended permit udp 171.70.230.0 255.255.254.0 host 128.107.241.124 eq mobile-ip 
access-list 102 extended permit udp 171.70.236.0 255.255.252.0 host 128.107.241.124 eq mobile-ip 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 host 128.107.233.36 range 20480 32767 
access-list 102 extended permit udp any host 64.104.94.175 range 1024 65535 
access-list 102 extended permit udp any host 128.107.83.102 range 1024 65535 
access-list 102 extended permit udp any any eq ntp 
access-list 102 extended permit udp host 10.81.255.1 host 64.102.240.212 eq 2055 
access-list 102 extended permit udp host 10.81.255.2 host 64.102.240.212 eq 2055 
access-list 102 extended permit udp host 10.81.255.1 host 64.102.240.214 eq 2055 
access-list 102 extended permit udp host 10.81.255.2 host 64.102.240.214 eq 2055 
access-list 102 extended permit udp host 10.81.255.1 host 64.102.240.213 eq 2055 
access-list 102 extended permit udp host 10.81.255.1 host 64.102.240.215 eq 2055 
access-list 102 extended permit udp host 10.81.255.2 host 64.102.240.213 eq 2055 
access-list 102 extended permit udp host 10.81.255.2 host 64.102.240.215 eq 2055 
access-list 102 extended permit udp host 172.17.153.17 host 128.107.225.20 eq 2055 
access-list 102 extended permit udp host 172.17.153.18 host 128.107.225.20 eq 2055 
access-list 102 extended permit udp host 172.17.153.17 host 128.107.225.26 eq 2055 
access-list 102 extended permit udp host 172.17.153.18 host 128.107.225.26 eq 2055 
access-list 102 extended permit udp host 172.17.153.17 host 128.107.225.24 eq 2055 
access-list 102 extended permit udp host 172.17.153.18 host 128.107.225.24 eq 2055 
access-list 102 extended permit udp host 10.64.63.11 host 72.163.216.245 eq 2055 
access-list 102 extended permit udp host 10.64.63.12 host 72.163.216.245 eq 2055 
access-list 102 extended permit udp host 10.64.63.11 host 72.163.216.253 eq 2055 
access-list 102 extended permit udp host 10.64.63.12 host 72.163.216.253 eq 2055 
access-list 102 extended permit udp object-group eam_monitors-global-1 object-group dmz_dns-sjc-1 eq 3567 
access-list 102 extended permit udp object-group eam_monitors-global-1 object-group dmz_dns-rtp-1 eq 3567 
access-list 102 extended permit udp object-group eam_monitors-global-1 object-group dmz_dns-sjc-1 eq snmp 
access-list 102 extended permit udp object-group eam_monitors-global-1 object-group dmz_dns-aln3-1 eq 3567 
access-list 102 extended permit udp object-group Internal_TandbergVCS-TYO-1 object-group DMZ_TandbergVCE-TYO-1 eq 2776 
access-list 102 extended permit udp object-group Internal_TandbergVCS-TYO-1 object-group DMZ_TandbergVCE-TYO-1 eq 2777 
access-list 102 extended permit udp object-group Internal_TandbergVCS-TYO-1 object-group DMZ_TandbergVCE-TYO-1 eq 6001 
access-list 102 extended permit udp object-group Internal_TandbergVCS-TYO-1 object-group DMZ_TandbergVCE-TYO-1 eq 7001 
access-list 102 extended permit udp object-group Internal_TandbergVCS-BGL-1 object-group DMZ_TandbergVCE-BGL-1 eq 2776 
access-list 102 extended permit udp object-group Internal_TandbergVCS-BGL-1 object-group DMZ_TandbergVCE-BGL-1 eq 2777 
access-list 102 extended permit udp object-group Internal_TandbergVCS-BGL-1 object-group DMZ_TandbergVCE-BGL-1 eq 6001 
access-list 102 extended permit udp object-group Internal_TandbergVCS-BGL-1 object-group DMZ_TandbergVCE-BGL-1 eq 7001 
access-list 102 extended permit udp any 12.46.104.0 255.255.254.0 eq domain 
access-list 102 extended permit tcp any 12.46.104.0 255.255.254.0 eq domain 
access-list 102 extended permit icmp any host 72.163.0.234 echo-reply 
access-list 102 extended permit icmp any host 72.163.0.242 echo-reply 
access-list 102 extended permit gre host 10.89.128.74 host 10.101.14.26 
access-list 102 extended permit esp host 72.163.215.46 any 
access-list 102 extended permit udp host 72.163.19.145 any eq isakmp 
access-list 102 extended permit udp host 171.70.192.2 any eq isakmp 
access-list 102 extended permit esp 144.254.48.0 255.255.255.0 host 80.254.144.195 
access-list 102 extended permit udp 144.254.48.0 255.255.255.0 host 80.254.144.195 eq isakmp 
access-list 102 extended permit esp 144.254.49.0 255.255.255.0 host 80.254.144.195 
access-list 102 extended permit udp 144.254.49.0 255.255.255.0 host 80.254.144.195 eq isakmp 
access-list 102 extended permit tcp 171.68.11.64 255.255.255.192 72.163.4.128 255.255.255.128 eq 6021 
access-list 102 extended permit tcp 66.187.220.0 255.255.254.0 host 72.163.5.143 eq https 
access-list 102 extended permit tcp host 64.103.26.59 134.24.132.0 255.255.255.0 eq 7000 
access-list 102 extended permit tcp host 64.103.26.59 134.24.132.0 255.255.255.0 eq www 
access-list 102 extended permit tcp host 64.103.26.59 134.24.132.0 255.255.255.0 eq https 
access-list 102 extended permit udp host 10.61.32.8 host 64.103.38.4 eq 2055 
access-list 102 extended permit udp host 10.61.32.9 host 64.103.38.4 eq 2055 
access-list 102 extended permit udp host 128.107.83.82 any range 1024 65535 
access-list 102 extended permit udp host 64.104.94.172 any range 1024 65535 
access-list 102 extended permit udp host 64.103.26.172 any range 1024 65535 
access-list 102 extended permit udp host 10.52.207.254 host 64.103.26.92 eq snmp 
access-list 102 extended permit udp host 10.52.207.254 host 64.103.26.93 eq snmp 
access-list 102 extended permit udp host 10.52.207.254 host 64.103.26.94 eq snmp 
access-list 102 extended permit udp host 144.254.240.11 host 64.103.26.92 eq snmp 
access-list 102 extended permit udp host 144.254.240.11 host 64.103.26.93 eq snmp 
access-list 102 extended permit udp host 144.254.240.11 host 64.103.26.94 eq snmp 
access-list 102 extended permit esp host 64.103.35.61 host 193.253.216.11 
access-list 102 extended permit udp host 64.103.35.61 host 193.253.216.11 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 193.253.216.11 eq 4500 
access-list 102 extended permit udp host 144.254.220.197 any eq isakmp 
access-list 102 extended permit udp host 144.254.220.198 any eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 82.205.120.165 eq isakmp 
access-list 102 extended permit esp host 64.103.35.61 host 86.57.245.254 
access-list 102 extended permit udp host 64.103.35.61 host 86.57.245.254 eq 4500 
access-list 102 extended permit udp host 64.103.35.61 host 86.57.245.254 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 82.149.94.42 eq isakmp 
access-list 102 extended permit esp host 64.103.209.131 any 
access-list 102 extended permit esp host 64.103.209.132 any 
access-list 102 extended permit udp host 64.103.209.131 any eq isakmp 
access-list 102 extended permit udp host 64.103.209.132 any eq isakmp 
access-list 102 extended permit udp host 64.103.209.131 any eq 4500 
access-list 102 extended permit udp host 64.103.209.132 any eq 4500 
access-list 102 extended permit udp host 10.66.129.35 host 64.104.252.101 eq 2055 
access-list 102 extended permit udp host 10.66.129.34 host 64.104.252.101 eq 2055 
access-list 102 extended permit udp host 10.56.223.129 host 192.118.76.50 eq 2055 
access-list 102 extended permit udp host 10.56.223.130 host 192.118.76.50 eq 2055 
access-list 102 extended permit udp host 10.101.14.10 host 72.163.0.116 eq 2055 
access-list 102 extended permit udp host 10.101.14.10 host 72.163.0.117 eq 2055 
access-list 102 extended permit udp host 10.101.14.11 host 72.163.0.116 eq 2055 
access-list 102 extended permit udp host 10.101.14.11 host 72.163.0.117 eq 2055 
access-list 102 extended permit udp host 10.35.173.70 host 152.178.2.36 
access-list 102 extended permit udp host 10.35.173.70 host 152.178.2.59 
access-list 102 extended permit udp host 10.35.173.71 host 152.178.2.36 
access-list 102 extended permit udp host 10.35.173.71 host 152.178.2.59 
access-list 102 extended permit udp host 10.35.173.72 host 152.178.2.36 
access-list 102 extended permit udp host 10.35.173.72 host 152.178.2.59 
access-list 102 extended permit udp any host 152.178.2.36 
access-list 102 extended permit udp any host 152.178.2.59 
access-list 102 extended permit udp any host 152.178.2.37 
access-list 102 extended permit tcp host 10.70.225.143 object-group ispgw_loopbacks-tokyo-1 eq bgp 
access-list 102 extended permit tcp host 10.70.225.144 object-group ispgw_loopbacks-tokyo-1 eq bgp 
access-list 102 extended permit udp host 10.70.225.143 object-group ispgw_loopbacks-tokyo-1 eq 2055 
access-list 102 extended permit udp host 10.70.225.144 object-group ispgw_loopbacks-tokyo-1 eq 2055 
access-list 102 extended permit udp host 10.70.225.119 host 64.104.46.244 eq 2055 
access-list 102 extended permit udp host 10.70.225.120 host 64.104.46.244 eq 2055 
access-list 102 extended permit ip any host 171.69.10.13 
access-list 102 extended permit udp any object-group multicast_networks-global-1 gt 1023 
access-list 102 extended permit udp host 10.101.206.43 host 173.37.148.188 eq 2055 
access-list 102 extended permit udp host 10.101.206.44 host 173.37.148.188 eq 2055 
access-list 102 extended permit udp host 10.101.206.43 host 173.37.148.189 eq 2055 
access-list 102 extended permit udp host 10.101.206.44 host 173.37.148.189 eq 2055 
access-list 102 extended permit udp host 10.123.20.65 host 173.36.112.68 eq 2055 
access-list 102 extended permit udp host 10.123.20.66 host 173.36.112.68 eq 2055 
access-list 102 extended permit pim any any 
access-list 102 extended permit tcp host 128.107.239.93 host 10.75.225.8 eq bgp 
access-list 102 extended permit tcp host 128.107.239.93 host 64.104.159.129 eq bgp 
access-list 102 extended permit tcp host 128.107.239.93 host 10.68.1.7 eq bgp 
access-list 102 extended permit tcp host 128.107.239.93 host 10.56.72.33 eq bgp 
access-list 102 extended permit tcp host 128.107.239.93 host 10.70.65.103 eq bgp 
access-list 102 extended permit tcp host 128.107.239.93 host 10.86.230.65 eq bgp 
access-list 102 extended permit tcp host 128.107.239.93 host 10.59.15.225 eq bgp 
access-list 102 extended permit tcp host 10.59.15.225 host 128.107.239.93 eq bgp 
access-list 102 extended permit tcp host 10.70.65.103 host 128.107.239.93 eq bgp 
access-list 102 extended permit tcp host 10.56.72.33 host 128.107.239.93 eq bgp 
access-list 102 extended permit tcp host 10.86.230.65 host 128.107.239.93 eq bgp 
access-list 102 extended permit tcp host 10.75.225.8 host 128.107.239.93 eq bgp 
access-list 102 extended permit tcp host 64.104.159.129 host 128.107.239.93 eq bgp 
access-list 102 extended permit tcp host 10.68.1.7 host 128.107.239.93 eq bgp 
access-list 102 extended permit tcp host 10.58.15.225 host 128.107.239.93 eq bgp 
access-list 102 extended permit tcp any host 128.107.239.102 eq bgp 
access-list 102 extended permit udp host 171.70.121.17 host 128.107.83.68 range 18000 19000 
access-list 102 extended permit udp host 171.70.121.62 host 128.107.83.68 range 18000 19000 
access-list 102 extended permit udp host 171.70.121.63 host 128.107.83.68 range 18000 19000 
access-list 102 extended permit tcp host 171.70.121.16 host 128.107.83.68 eq 3337 
access-list 102 extended permit udp host 171.70.121.16 host 128.107.83.68 range 18000 18200 
access-list 102 extended permit tcp host 171.70.121.63 host 128.107.83.68 eq 3336 
access-list 102 extended permit tcp host 171.70.121.63 host 128.107.83.68 eq 3337 
access-list 102 extended permit udp host 171.70.121.63 host 128.107.83.68 range 19000 19100 
access-list 102 extended permit tcp host 171.70.121.17 host 128.107.83.68 eq 3336 
access-list 102 extended permit tcp host 171.70.121.17 host 128.107.83.68 eq 3337 
access-list 102 extended permit udp host 171.70.121.17 host 128.107.83.68 range 19000 19100 
access-list 102 extended permit tcp host 171.70.121.62 host 128.107.83.68 eq 3336 
access-list 102 extended permit tcp host 171.70.121.62 host 128.107.83.68 eq 3337 
access-list 102 extended permit udp host 171.70.121.62 host 128.107.83.68 range 19000 19100 
access-list 102 extended permit tcp host 171.70.121.31 host 128.107.83.68 eq 3336 
access-list 102 extended permit tcp host 171.70.121.31 host 128.107.83.68 eq 8080 
access-list 102 extended permit tcp host 171.70.121.31 host 128.107.83.68 eq https 
access-list 102 extended permit tcp host 171.70.121.31 host 128.107.83.68 eq h323 
access-list 102 extended permit tcp host 171.70.121.31 host 128.107.83.68 range 1024 1100 
access-list 102 extended permit udp host 171.70.121.31 host 128.107.83.68 eq 1719 
access-list 102 extended permit tcp 66.187.220.0 255.255.254.0 host 128.107.74.22 eq https 
access-list 102 extended permit tcp host 64.100.21.69 host 128.107.74.167 eq https 
access-list 102 extended permit tcp host 64.100.21.69 host 128.107.74.168 eq https 
access-list 102 extended permit udp host 128.107.201.199 any 
access-list 102 extended permit udp host 128.107.201.200 any 
access-list 102 extended permit udp host 128.107.201.201 any 
access-list 102 extended permit udp 128.107.201.228 255.255.255.252 any 
access-list 102 extended permit udp host 128.107.201.217 any 
access-list 102 extended permit udp 128.107.201.218 255.255.255.254 any 
access-list 102 extended permit tcp host 172.17.153.63 host 192.168.203.201 eq bgp 
access-list 102 extended permit tcp host 172.17.153.63 host 10.56.72.33 eq bgp 
access-list 102 extended permit tcp host 172.17.153.63 host 10.59.15.225 eq bgp 
access-list 102 extended permit tcp host 172.17.153.63 host 64.104.159.129 eq bgp 
access-list 102 extended permit tcp host 172.17.153.63 host 64.104.159.131 eq bgp 
access-list 102 extended permit tcp host 172.17.153.63 host 10.75.225.8 eq bgp 
access-list 102 extended permit tcp host 172.17.153.63 host 10.75.225.193 eq bgp 
access-list 102 extended permit tcp host 172.17.153.63 host 10.75.225.194 eq bgp 
access-list 102 extended permit tcp host 172.17.153.63 host 10.68.1.7 eq bgp 
access-list 102 extended permit tcp host 172.17.153.63 host 10.86.230.65 eq bgp 
access-list 102 extended permit tcp host 172.17.153.63 host 10.70.65.103 eq bgp 
access-list 102 extended permit tcp object-group oer_bgp_gw-global-1 host 172.17.153.63 eq bgp 
access-list 102 extended permit gre host 144.254.134.249 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.141.185 host 64.103.36.241 
access-list 102 extended permit gre host 10.49.68.18 host 64.103.36.241 
access-list 102 extended permit gre host 10.49.66.99 host 64.103.36.241 
access-list 102 extended permit gre host 10.49.217.250 host 64.103.36.18 
access-list 102 extended permit gre any host 72.163.216.158 
access-list 102 extended permit gre any host 64.104.127.60 
access-list 102 extended permit gre any host 64.104.252.227 
access-list 102 extended permit gre any host 64.104.44.33 
access-list 102 extended permit gre any host 72.163.249.17 
access-list 102 extended permit gre any host 72.163.216.156 
access-list 102 extended permit gre host 10.74.164.145 host 64.104.127.65 
access-list 102 extended permit esp host 10.71.150.62 host 64.104.44.33 
access-list 102 extended permit ah host 10.71.150.62 host 64.104.44.33 
access-list 102 extended permit udp host 10.71.150.62 host 64.104.44.33 eq isakmp 
access-list 102 extended permit gre host 10.49.66.101 host 64.103.36.241 
access-list 102 extended permit 41 host 171.69.7.186 host 128.107.240.254 
access-list 102 extended permit 41 host 10.60.19.126 host 128.107.240.254 
access-list 102 extended permit tcp host 10.66.129.10 host 64.104.252.229 eq bgp 
access-list 102 extended permit udp host 10.49.215.178 host 64.103.36.18 eq isakmp 
access-list 102 extended deny tcp any object-group smtp_servers-linksys-1 eq smtp 
access-list 102 extended permit tcp object-group internal_smtp-global-1 any eq smtp 
access-list 102 extended permit tcp any object-group dmz_smtp-global-1 eq smtp 
access-list 102 extended permit tcp object-group datacenters-global-1 any eq smtp 
access-list 102 extended permit tcp object-group dc_waivers-global-1 any eq smtp 
access-list 102 extended permit tcp object-group snmp_managers-global-1 object-group dmz_smtp-global-1 eq 6554 
access-list 102 extended permit udp any object-group proxy_servers-ams-1 gt 1023 
access-list 102 extended permit udp any object-group proxy_servers-syd-1 gt 1023 
access-list 102 extended permit udp any object-group proxy_servers-rtp-1 gt 1023 
access-list 102 extended permit udp any object-group proxy_servers-sjc-1 gt 1023 
access-list 102 extended permit udp any host 64.100.8.230 gt 1023 
access-list 102 extended permit esp any 192.133.204.0 255.255.255.0 
access-list 102 extended permit esp any 192.133.198.0 255.255.254.0 
access-list 102 extended permit udp any 192.133.204.0 255.255.255.0 eq isakmp 
access-list 102 extended permit udp any 192.133.198.0 255.255.254.0 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 192.100.123.248 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 195.68.63.137 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 213.164.164.16 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 194.179.83.78 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 194.179.83.78 
access-list 102 extended permit udp host 144.254.146.9 host 194.74.94.194 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 159.134.20.49 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 194.65.103.250 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 213.132.255.13 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 196.205.27.97 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 195.4.2.70 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 195.4.2.71 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 141.191.5.26 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 171.18.48.1 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 171.18.30.83 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 163.156.213.29 eq isakmp 
access-list 102 extended permit udp host 64.104.14.233 host 14.37.25.250 eq isakmp 
access-list 102 extended permit udp host 64.104.14.232 host 14.37.25.250 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 82.159.191.18 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 187.141.14.114 eq isakmp 
access-list 102 extended permit udp host 64.104.77.181 any eq isakmp 
access-list 102 extended permit esp host 64.104.77.181 host 211.25.222.218 
access-list 102 extended permit udp host 64.104.77.181 host 211.25.222.218 eq isakmp 
access-list 102 extended permit udp host 64.104.77.181 host 211.25.222.218 eq 4500 
access-list 102 extended permit udp host 64.103.35.189 host 82.45.149.150 eq isakmp 
access-list 102 extended permit udp any host 64.104.44.131 range 16384 32768 
access-list 102 extended permit tcp host 10.68.3.51 host 64.104.44.131 eq sip 
access-list 102 extended permit udp host 10.68.3.51 host 64.104.44.131 eq sip 
access-list 102 extended permit tcp host 10.68.3.53 host 64.104.44.131 eq sip 
access-list 102 extended permit udp host 10.68.3.53 host 64.104.44.131 eq sip 
access-list 102 extended permit tcp host 10.68.3.55 host 64.104.44.131 eq sip 
access-list 102 extended permit udp host 10.68.3.55 host 64.104.44.131 eq sip 
access-list 102 extended permit tcp host 10.68.3.57 host 64.104.44.131 eq sip 
access-list 102 extended permit udp host 10.68.3.57 host 64.104.44.131 eq sip 
access-list 102 extended permit tcp host 64.100.25.127 any eq smtp 
access-list 102 extended permit gre host 10.33.226.193 host 172.17.153.20 
access-list 102 extended permit gre host 10.33.226.193 host 172.17.153.65 
access-list 102 extended permit gre host 10.18.228.1 host 172.17.153.20 
access-list 102 extended permit gre host 10.18.228.2 host 172.17.153.65 
access-list 102 extended permit udp host 64.101.73.215 host 64.102.245.77 eq isakmp 
access-list 102 extended permit esp host 172.23.81.197 host 64.100.8.163 
access-list 102 extended permit ah host 172.23.81.197 host 64.100.8.163 
access-list 102 extended permit udp host 172.23.81.197 host 64.100.8.163 eq isakmp 
access-list 102 extended permit udp host 172.23.81.197 host 64.100.8.163 eq 4500 
access-list 102 extended permit udp any host 208.22.56.125 range 48129 48137 
access-list 102 extended permit udp any host 206.156.53.143 range 48129 48137 
access-list 102 extended permit udp any host 208.22.56.74 range 48129 48137 
access-list 102 extended permit udp any 160.43.250.0 255.255.255.0 range 48129 48137 
access-list 102 extended permit udp any 206.156.53.0 255.255.255.0 range 48129 48137 
access-list 102 extended permit udp any 205.216.112.0 255.255.255.0 range 48129 48137 
access-list 102 extended permit udp any 208.22.56.0 255.255.255.0 range 48129 48137 
access-list 102 extended permit udp any 208.22.57.0 255.255.255.0 range 48129 48137 
access-list 102 extended permit udp any 69.191.192.0 255.255.255.0 range 48129 48137 
access-list 102 extended permit tcp host 64.102.223.36 host 64.102.248.3 
access-list 102 extended permit tcp host 64.102.223.37 host 64.102.248.3 
access-list 102 extended permit tcp host 64.102.223.38 host 64.102.248.3 
access-list 102 extended permit tcp host 64.102.223.36 host 64.102.248.21 eq 5620 
access-list 102 extended permit tcp host 64.102.223.37 host 64.102.248.21 eq 5620 
access-list 102 extended permit tcp host 64.102.223.38 host 64.102.248.21 eq 5620 
access-list 102 extended permit udp any host 64.102.248.5 range 16384 65535 
access-list 102 extended permit udp host 10.95.26.78 host 128.107.81.84 eq isakmp 
access-list 102 extended permit udp host 128.107.200.83 any eq isakmp 
access-list 102 extended permit udp host 128.107.200.84 any eq isakmp 
access-list 102 extended permit udp host 128.107.200.85 any eq isakmp 
access-list 102 extended permit udp host 72.163.215.128 any eq isakmp 
access-list 102 extended permit esp host 72.163.215.128 any 
access-list 102 extended permit udp host 72.163.215.129 any eq isakmp 
access-list 102 extended permit esp host 72.163.215.129 any 
access-list 102 extended permit udp host 72.163.215.41 any eq isakmp 
access-list 102 extended permit udp host 128.107.81.134 any range 1024 65535 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.231 eq www 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.231 eq https 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.228 eq https 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.228 eq www 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.229 eq https 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.229 eq www 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.230 eq https 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.230 eq www 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.233 eq https 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.233 eq www 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.234 eq https 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.234 eq www 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.235 eq https 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.235 eq www 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.236 eq https 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.236 eq www 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.237 eq https 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.237 eq www 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.238 eq https 
access-list 102 extended permit tcp host 171.68.155.30 host 128.107.246.238 eq www 
access-list 102 extended permit ah host 128.107.156.155 host 206.112.117.35 
access-list 102 extended permit esp host 206.112.117.35 host 128.107.156.155 
access-list 102 extended permit gre host 10.65.166.34 host 72.163.216.156 
access-list 102 extended permit udp 10.49.217.128 255.255.255.128 64.103.38.128 255.255.255.224 eq 902 
access-list 102 extended permit udp 10.49.217.128 255.255.255.128 64.103.38.128 255.255.255.224 eq 903 
access-list 102 extended permit udp host 144.254.146.9 host 158.190.195.29 eq isakmp 
access-list 102 extended permit udp host 171.71.129.43 host 206.112.117.35 eq isakmp 
access-list 102 extended permit esp host 171.71.129.43 host 206.112.117.35 
access-list 102 extended permit udp host 171.71.129.43 host 206.112.117.35 eq 4500 
access-list 102 extended permit udp host 171.71.129.43 host 206.112.117.35 eq 10000 
access-list 102 extended permit ah host 171.71.129.43 host 206.112.117.35 
access-list 102 extended permit udp host 64.103.69.6 host 195.89.28.178 eq isakmp 
access-list 102 extended permit udp host 64.103.69.6 host 195.89.28.178 eq 4500 
access-list 102 extended permit udp host 64.103.69.6 host 195.89.28.178 eq 10000 
access-list 102 extended permit tcp host 64.103.69.6 host 195.89.28.178 eq 10000 
access-list 102 extended permit udp host 64.103.69.7 host 195.89.28.178 eq isakmp 
access-list 102 extended permit udp host 64.103.69.7 host 195.89.28.178 eq 4500 
access-list 102 extended permit udp host 64.103.69.7 host 195.89.28.178 eq 10000 
access-list 102 extended permit tcp host 64.103.69.7 host 195.89.28.178 eq 10000 
access-list 102 extended permit udp host 171.71.9.61 host 63.81.120.147 eq isakmp 
access-list 102 extended permit esp host 171.71.9.61 host 63.81.120.147 
access-list 102 extended permit udp host 171.71.9.61 host 63.81.120.147 eq 4500 
access-list 102 extended permit udp host 171.71.9.61 host 63.81.120.147 eq 10000 
access-list 102 extended permit ah host 171.71.9.61 host 63.81.120.147 
access-list 102 extended permit udp any host 128.107.85.180 range 16384 32768 
access-list 102 extended permit udp any host 128.107.85.180 eq 1967 
access-list 102 extended permit esp host 72.163.247.99 host 116.225.68.162 
access-list 102 extended permit udp host 72.163.247.99 host 116.225.68.162 eq isakmp 
access-list 102 extended permit udp host 72.163.247.99 host 116.225.68.162 eq 4500 
access-list 102 extended permit esp host 10.92.241.210 host 128.107.81.84 
access-list 102 extended permit ah host 10.92.241.210 host 128.107.81.84 
access-list 102 extended permit udp host 10.92.241.210 host 128.107.81.84 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 195.226.219.236 eq isakmp 
access-list 102 extended permit udp host 171.71.9.61 host 206.112.117.35 eq isakmp 
access-list 102 extended permit esp host 171.71.9.61 host 206.112.117.35 
access-list 102 extended permit udp host 171.71.9.61 host 206.112.117.35 eq 4500 
access-list 102 extended permit udp host 171.71.9.61 host 206.112.117.35 eq 10000 
access-list 102 extended permit ah host 171.71.9.61 host 206.112.117.35 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.7.1 eq isakmp 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.8.1 eq isakmp 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.83.1 eq isakmp 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.84.1 eq isakmp 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.85.1 eq isakmp 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.86.1 eq isakmp 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.87.1 eq isakmp 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.88.1 eq isakmp 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.90.1 eq isakmp 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.90.1 eq 4500 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.3.1 eq 4500 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.4.1 eq 4500 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.5.1 eq 4500 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.6.1 eq 4500 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.7.1 eq 4500 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.8.1 eq 4500 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.83.1 eq 4500 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.84.1 eq 4500 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.85.1 eq 4500 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.86.1 eq 4500 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.87.1 eq 4500 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.88.1 eq 4500 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.3.1 eq isakmp 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.4.1 eq isakmp 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.5.1 eq isakmp 
access-list 102 extended permit udp 10.32.44.192 255.255.255.224 host 208.54.6.1 eq isakmp 
access-list 102 extended permit gre host 10.68.170.177 host 64.104.95.129 
access-list 102 extended permit icmp any host 128.107.236.38 echo-reply 
access-list 102 extended permit esp object-group cclc_internal-sjc-1 object-group cclc_external-sjc-1 
access-list 102 extended permit tcp object-group cclc_internal-sjc-1 object-group cclc_external-sjc-1 eq 10000 
access-list 102 extended permit udp object-group cclc_internal-sjc-1 object-group cclc_external-sjc-1 eq isakmp 
access-list 102 extended permit udp object-group cclc_internal-sjc-1 object-group cclc_external-sjc-1 eq 62514 
access-list 102 extended permit udp any host 128.107.81.134 range 1024 65535 
access-list 102 extended permit udp any host 128.107.81.136 range 1024 65535 
access-list 102 extended permit udp host 128.107.81.199 any range 1024 65535 
access-list 102 extended permit udp host 128.107.81.198 any range 1024 65535 
access-list 102 extended permit udp any host 128.107.85.176 range 16384 65535 
access-list 102 extended permit udp any host 173.37.193.4 range 16384 65535 
access-list 102 extended permit udp 10.0.0.0 255.0.0.0 host 128.107.83.11 gt 16000 
access-list 102 extended permit udp host 144.254.146.9 host 172.22.121.90 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 145.253.32.85 eq isakmp 
access-list 102 extended permit esp host 72.163.247.99 host 61.142.98.158 
access-list 102 extended permit udp host 72.163.247.99 host 61.142.98.158 eq isakmp 
access-list 102 extended permit udp host 171.68.106.20 any eq isakmp 
access-list 102 extended permit udp host 171.68.106.20 any eq 4500 
access-list 102 extended permit udp host 171.68.106.20 any eq 10000 
access-list 102 extended permit udp host 171.68.106.20 any eq 443 
access-list 102 extended permit udp host 171.68.106.21 any eq isakmp 
access-list 102 extended permit udp host 171.68.106.21 any eq 4500 
access-list 102 extended permit udp host 171.68.106.21 any eq 10000 
access-list 102 extended permit udp host 171.68.106.21 any eq 443 
access-list 102 extended permit esp host 171.68.106.20 any 
access-list 102 extended permit esp host 171.68.106.21 any 
access-list 102 extended permit udp 172.20.70.0 255.255.255.0 72.163.7.128 255.255.255.240 eq 3478 
access-list 102 extended permit udp 172.20.70.0 255.255.255.0 72.163.7.80 255.255.255.240 eq 3478 
access-list 102 extended permit udp 172.20.70.0 255.255.255.0 72.163.7.96 255.255.255.224 eq 3478 
access-list 102 extended permit udp 172.23.183.0 255.255.255.0 72.163.7.128 255.255.255.240 eq 3478 
access-list 102 extended permit udp 172.23.183.0 255.255.255.0 72.163.7.80 255.255.255.240 eq 3478 
access-list 102 extended permit udp 172.23.183.0 255.255.255.0 72.163.7.96 255.255.255.224 eq 3478 
access-list 102 extended permit udp 172.20.70.0 255.255.255.0 72.163.7.128 255.255.255.240 eq 4500 
access-list 102 extended permit udp 172.20.70.0 255.255.255.0 72.163.7.80 255.255.255.240 eq 4500 
access-list 102 extended permit udp 172.20.70.0 255.255.255.0 72.163.7.96 255.255.255.224 eq 4500 
access-list 102 extended permit udp 172.23.183.0 255.255.255.0 72.163.7.128 255.255.255.240 eq 4500 
access-list 102 extended permit udp 172.23.183.0 255.255.255.0 72.163.7.80 255.255.255.240 eq 4500 
access-list 102 extended permit udp 172.23.183.0 255.255.255.0 72.163.7.96 255.255.255.224 eq 4500 
access-list 102 extended permit udp host 144.254.146.9 host 85.89.243.118 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 212.105.95.101 eq isakmp 
access-list 102 extended permit tcp host 10.63.224.21 host 64.103.26.78 eq 5443 
access-list 102 extended permit tcp host 10.63.224.21 host 64.103.26.78 eq 9080 
access-list 102 extended permit udp 10.0.0.0 255.0.0.0 host 64.103.39.11 gt 16383 
access-list 102 extended permit udp host 10.32.0.46 host 64.103.39.4 eq 16384 
access-list 102 extended permit udp host 10.32.0.46 host 64.103.39.4 eq 16388 
access-list 102 extended permit udp host 10.32.0.46 host 64.103.39.3 eq 16384 
access-list 102 extended permit udp host 10.32.0.46 host 64.103.39.3 eq 16388 
access-list 102 extended permit udp host 10.52.147.66 host 64.103.36.18 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 80.163.119.234 eq isakmp 
access-list 102 extended permit udp host 216.128.60.189 host 80.88.249.24 eq isakmp 
access-list 102 extended permit esp host 72.163.215.130 any 
access-list 102 extended permit udp host 72.163.215.130 any eq isakmp 
access-list 102 extended permit udp host 10.52.147.122 host 64.103.36.18 eq isakmp 
access-list 102 extended permit udp host 10.61.118.156 10.105.26.0 255.255.255.0 eq 902 
access-list 102 extended permit udp any 64.103.27.96 255.255.255.224 eq isakmp 
access-list 102 extended permit udp any 64.103.27.96 255.255.255.224 eq 4500 
access-list 102 extended permit udp any host 64.103.27.69 eq isakmp 
access-list 102 extended permit udp any host 64.103.27.69 eq 4500 
access-list 102 extended permit esp any 64.103.27.96 255.255.255.224 
access-list 102 extended permit esp any host 64.103.27.69 
access-list 102 extended permit esp host 10.104.194.6 host 72.163.216.158 
access-list 102 extended permit udp host 10.104.194.6 host 72.163.216.158 eq isakmp 
access-list 102 extended permit udp host 10.104.59.59 host 72.163.216.158 eq isakmp 
access-list 102 extended permit udp host 10.76.11.253 host 72.163.216.158 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 193.7.146.6 eq isakmp 
access-list 102 extended permit udp host 64.102.57.17 host 214.3.220.11 eq isakmp 
access-list 102 extended permit udp host 64.102.57.17 host 214.3.220.11 eq 4500 
access-list 102 extended permit udp host 64.102.57.17 host 214.3.220.11 eq 10000 
access-list 102 extended permit tcp host 64.102.57.17 host 214.3.220.11 eq 10000 
access-list 102 extended permit udp host 64.102.57.17 host 214.3.220.11 eq 16969 
access-list 102 extended permit tcp host 64.102.57.17 host 214.3.220.11 eq 16969 
access-list 102 extended permit udp host 64.102.57.17 host 214.3.220.10 eq isakmp 
access-list 102 extended permit udp host 64.102.57.17 host 214.3.220.10 eq 4500 
access-list 102 extended permit udp host 64.102.57.17 host 214.3.220.10 eq 10000 
access-list 102 extended permit tcp host 64.102.57.17 host 214.3.220.10 eq 10000 
access-list 102 extended permit udp host 64.102.57.17 host 214.3.220.10 eq 16969 
access-list 102 extended permit tcp host 64.102.57.17 host 214.3.220.10 eq 16969 
access-list 102 extended permit udp host 64.102.57.17 host 214.3.140.10 eq isakmp 
access-list 102 extended permit udp host 64.102.57.17 host 214.3.140.10 eq 4500 
access-list 102 extended permit udp host 64.102.57.17 host 214.3.140.10 eq 10000 
access-list 102 extended permit tcp host 64.102.57.17 host 214.3.140.10 eq 10000 
access-list 102 extended permit udp host 64.102.57.17 host 214.3.140.10 eq 16969 
access-list 102 extended permit tcp host 64.102.57.17 host 214.3.140.10 eq 16969 
access-list 102 extended permit udp host 64.102.57.17 host 214.3.140.11 eq isakmp 
access-list 102 extended permit udp host 64.102.57.17 host 214.3.140.11 eq 4500 
access-list 102 extended permit udp host 64.102.57.17 host 214.3.140.11 eq 10000 
access-list 102 extended permit tcp host 64.102.57.17 host 214.3.140.11 eq 10000 
access-list 102 extended permit udp host 64.102.57.17 host 214.3.140.11 eq 16969 
access-list 102 extended permit tcp host 64.102.57.17 host 214.3.140.11 eq 16969 
access-list 102 extended permit udp host 144.254.146.18 any eq isakmp 
access-list 102 extended permit udp host 144.254.146.22 any eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 193.129.184.129 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 62.90.200.222 eq isakmp 
access-list 102 extended permit esp host 64.103.35.61 host 62.146.143.22 
access-list 102 extended permit esp host 64.103.35.189 host 62.146.143.22 
access-list 102 extended permit udp host 64.103.35.61 host 62.146.143.22 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 62.146.143.22 eq isakmp 
access-list 102 extended permit esp host 72.163.130.100 any 
access-list 102 extended permit esp host 72.163.215.41 any 
access-list 102 extended permit udp host 10.77.202.75 host 206.73.105.18 eq isakmp 
access-list 102 extended permit udp host 10.77.202.37 host 206.73.105.18 eq isakmp 
access-list 102 extended permit udp host 10.77.202.61 host 206.73.105.18 eq isakmp 
access-list 102 extended permit udp host 10.77.202.43 host 206.73.105.18 eq isakmp 
access-list 102 extended permit udp host 10.77.203.193 host 206.73.105.18 eq isakmp 
access-list 102 extended permit udp host 10.77.203.68 host 206.73.105.18 eq isakmp 
access-list 102 extended permit udp host 10.77.202.193 host 206.73.105.18 eq isakmp 
access-list 102 extended permit udp host 10.77.202.75 host 206.73.105.18 eq 2746 
access-list 102 extended permit udp host 10.77.202.37 host 206.73.105.18 eq 2746 
access-list 102 extended permit udp host 10.77.202.61 host 206.73.105.18 eq 2746 
access-list 102 extended permit udp host 10.77.202.43 host 206.73.105.18 eq 2746 
access-list 102 extended permit udp host 10.77.203.193 host 206.73.105.18 eq 2746 
access-list 102 extended permit udp host 10.77.203.68 host 206.73.105.18 eq 2746 
access-list 102 extended permit udp host 10.77.202.193 host 206.73.105.18 eq 2746 
access-list 102 extended permit udp host 10.77.202.75 host 206.73.105.18 eq 18233 
access-list 102 extended permit udp host 10.77.202.37 host 206.73.105.18 eq 18233 
access-list 102 extended permit udp host 10.77.202.61 host 206.73.105.18 eq 18233 
access-list 102 extended permit udp host 10.77.202.43 host 206.73.105.18 eq 18233 
access-list 102 extended permit udp host 10.77.203.193 host 206.73.105.18 eq 18233 
access-list 102 extended permit udp host 10.77.203.68 host 206.73.105.18 eq 18233 
access-list 102 extended permit udp host 10.77.202.193 host 206.73.105.18 eq 18233 
access-list 102 extended permit udp host 10.77.202.75 host 206.73.105.18 eq 18234 
access-list 102 extended permit udp host 10.77.202.37 host 206.73.105.18 eq 18234 
access-list 102 extended permit udp host 10.77.202.61 host 206.73.105.18 eq 18234 
access-list 102 extended permit udp host 10.77.202.43 host 206.73.105.18 eq 18234 
access-list 102 extended permit udp host 10.77.203.193 host 206.73.105.18 eq 18234 
access-list 102 extended permit udp host 10.77.203.68 host 206.73.105.18 eq 18234 
access-list 102 extended permit udp host 10.77.202.193 host 206.73.105.18 eq 18234 
access-list 102 extended permit tcp host 10.77.202.75 host 206.73.105.18 eq 500 
access-list 102 extended permit tcp host 10.77.202.37 host 206.73.105.18 eq 500 
access-list 102 extended permit tcp host 10.77.202.61 host 206.73.105.18 eq 500 
access-list 102 extended permit tcp host 10.77.202.43 host 206.73.105.18 eq 500 
access-list 102 extended permit tcp host 10.77.203.193 host 206.73.105.18 eq 500 
access-list 102 extended permit tcp host 10.77.203.68 host 206.73.105.18 eq 500 
access-list 102 extended permit tcp host 10.77.202.193 host 206.73.105.18 eq 500 
access-list 102 extended permit tcp host 10.77.202.75 host 206.73.105.18 eq 264 
access-list 102 extended permit tcp host 10.77.202.37 host 206.73.105.18 eq 264 
access-list 102 extended permit tcp host 10.77.202.61 host 206.73.105.18 eq 264 
access-list 102 extended permit tcp host 10.77.202.43 host 206.73.105.18 eq 264 
access-list 102 extended permit tcp host 10.77.203.193 host 206.73.105.18 eq 264 
access-list 102 extended permit tcp host 10.77.203.68 host 206.73.105.18 eq 264 
access-list 102 extended permit tcp host 10.77.202.193 host 206.73.105.18 eq 264 
access-list 102 extended permit tcp host 10.77.202.75 host 206.73.105.18 eq 18231 
access-list 102 extended permit tcp host 10.77.202.37 host 206.73.105.18 eq 18231 
access-list 102 extended permit tcp host 10.77.202.61 host 206.73.105.18 eq 18231 
access-list 102 extended permit tcp host 10.77.202.43 host 206.73.105.18 eq 18231 
access-list 102 extended permit tcp host 10.77.203.193 host 206.73.105.18 eq 18231 
access-list 102 extended permit tcp host 10.77.203.68 host 206.73.105.18 eq 18231 
access-list 102 extended permit tcp host 10.77.202.193 host 206.73.105.18 eq 18231 
access-list 102 extended permit tcp host 10.77.202.75 host 206.73.105.18 eq 18232 
access-list 102 extended permit tcp host 10.77.202.37 host 206.73.105.18 eq 18232 
access-list 102 extended permit tcp host 10.77.202.61 host 206.73.105.18 eq 18232 
access-list 102 extended permit tcp host 10.77.202.43 host 206.73.105.18 eq 18232 
access-list 102 extended permit tcp host 10.77.203.193 host 206.73.105.18 eq 18232 
access-list 102 extended permit tcp host 10.77.203.68 host 206.73.105.18 eq 18232 
access-list 102 extended permit tcp host 10.77.202.193 host 206.73.105.18 eq 18232 
access-list 102 extended permit esp host 10.77.202.75 host 206.73.105.18 
access-list 102 extended permit esp host 10.77.202.37 host 206.73.105.18 
access-list 102 extended permit esp host 10.77.202.61 host 206.73.105.18 
access-list 102 extended permit esp host 10.77.202.43 host 206.73.105.18 
access-list 102 extended permit esp host 10.77.203.193 host 206.73.105.18 
access-list 102 extended permit esp host 10.77.203.68 host 206.73.105.18 
access-list 102 extended permit esp host 10.77.202.193 host 206.73.105.18 
access-list 102 extended permit ah host 10.77.202.75 host 206.73.105.18 
access-list 102 extended permit ah host 10.77.202.37 host 206.73.105.18 
access-list 102 extended permit ah host 10.77.202.61 host 206.73.105.18 
access-list 102 extended permit ah host 10.77.202.43 host 206.73.105.18 
access-list 102 extended permit ah host 10.77.203.193 host 206.73.105.18 
access-list 102 extended permit ah host 10.77.203.68 host 206.73.105.18 
access-list 102 extended permit ah host 10.77.202.193 host 206.73.105.18 
access-list 102 extended permit esp host 10.77.203.203 host 206.73.105.18 
access-list 102 extended permit ah host 10.77.203.203 host 206.73.105.18 
access-list 102 extended permit tcp host 10.77.203.203 host 206.73.105.18 eq 264 
access-list 102 extended permit tcp host 10.77.203.203 host 206.73.105.18 eq 500 
access-list 102 extended permit tcp host 10.77.203.203 host 206.73.105.18 eq 18231 
access-list 102 extended permit tcp host 10.77.203.203 host 206.73.105.18 eq 18232 
access-list 102 extended permit udp host 10.77.203.203 host 206.73.105.18 eq isakmp 
access-list 102 extended permit udp host 10.77.203.203 host 206.73.105.18 eq 2746 
access-list 102 extended permit udp host 10.77.203.203 host 206.73.105.18 eq 18233 
access-list 102 extended permit udp host 10.77.203.203 host 206.73.105.18 eq 18234 
access-list 102 extended permit udp host 144.254.220.150 any eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 193.23.33.4 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 41.251.67.162 
access-list 102 extended permit udp host 64.103.35.189 host 41.251.67.162 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 41.251.67.162 eq 4500 
access-list 102 extended permit gre host 144.254.136.104 host 64.103.36.241 
access-list 102 extended permit udp host 64.103.35.189 host 80.165.21.229 eq isakmp 
access-list 102 extended permit udp host 216.128.60.189 host 80.88.249.25 eq isakmp 
access-list 102 extended permit esp host 64.103.35.61 host 80.232.218.192 
access-list 102 extended permit udp host 64.103.35.61 host 80.232.218.192 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 196.207.241.49 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 41.214.8.169 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 196.203.29.250 eq isakmp 
access-list 102 extended permit esp host 64.103.35.61 host 62.153.117.154 
access-list 102 extended permit udp host 64.103.35.61 host 62.153.117.154 eq isakmp 
access-list 102 extended permit esp host 64.103.35.61 host 193.253.227.84 
access-list 102 extended permit udp host 64.103.35.61 host 193.253.227.84 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 193.253.227.84 eq 4500 
access-list 102 extended permit udp host 64.103.35.61 host 93.190.253.194 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 80.65.75.37 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 80.65.75.37 
access-list 102 extended permit icmp 64.102.14.0 255.255.255.192 10.81.52.0 255.255.255.240 
access-list 102 extended permit icmp any host 64.102.241.135 echo-reply 
access-list 102 extended permit icmp any host 64.102.241.134 echo-reply 
access-list 102 extended permit icmp any host 64.102.246.5 echo-reply 
access-list 102 extended permit icmp any host 72.163.4.28 echo-reply 
access-list 102 extended permit icmp any host 173.37.144.100 echo-reply 
access-list 102 extended permit tcp host 64.102.14.8 10.81.52.0 255.255.255.240 eq ssh 
access-list 102 extended permit tcp host 64.102.14.8 10.81.52.0 255.255.255.240 range 900 910 
access-list 102 extended permit udp host 64.102.14.8 10.81.52.0 255.255.255.240 range 900 910 
access-list 102 extended permit tcp host 64.102.14.8 10.81.52.0 255.255.255.240 eq www 
access-list 102 extended permit tcp host 64.102.14.8 10.81.52.0 255.255.255.240 eq https 
access-list 102 extended permit tcp host 64.102.14.8 10.81.52.0 255.255.255.240 eq 27010 
access-list 102 extended permit tcp any 64.103.38.192 255.255.255.224 eq ssh 
access-list 102 extended permit tcp any 64.103.38.192 255.255.255.224 eq https 
access-list 102 extended permit icmp any 64.103.38.192 255.255.255.224 
access-list 102 extended permit udp any 64.103.38.192 255.255.255.224 eq isakmp 
access-list 102 extended permit esp any 64.103.38.192 255.255.255.224 
access-list 102 extended permit ah any 64.103.38.192 255.255.255.224 
access-list 102 extended permit udp any 64.103.38.192 255.255.255.224 eq 4500 
access-list 102 extended permit tcp host 10.63.224.21 host 64.103.38.235 eq 5443 
access-list 102 extended permit esp host 64.103.35.61 host 89.162.145.2 
access-list 102 extended permit udp host 64.103.35.61 host 89.162.145.2 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 41.209.15.186 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 212.123.18.140 eq isakmp 
access-list 102 extended permit esp host 64.103.35.61 host 193.95.99.218 
access-list 102 extended permit esp host 64.104.88.231 host 61.91.245.114 
access-list 102 extended permit udp host 64.104.88.231 host 61.91.245.114 eq isakmp 
access-list 102 extended permit esp host 64.104.14.248 host 122.29.248.175 
access-list 102 extended permit udp host 64.104.14.248 host 122.29.248.175 eq isakmp 
access-list 102 extended permit esp host 64.104.14.247 host 211.122.197.174 
access-list 102 extended permit udp host 64.104.14.247 host 211.122.197.174 eq isakmp 
access-list 102 extended permit esp host 64.104.14.247 host 114.179.84.158 
access-list 102 extended permit udp host 64.104.14.247 host 114.179.84.158 eq isakmp 
access-list 102 extended permit esp host 64.104.14.248 host 114.179.84.158 
access-list 102 extended permit udp host 64.104.14.248 host 114.179.84.158 eq isakmp 
access-list 102 extended permit esp host 64.104.14.249 host 202.139.138.209 
access-list 102 extended permit udp host 64.104.14.249 host 202.139.138.209 eq isakmp 
access-list 102 extended permit udp host 64.104.14.249 host 202.139.138.209 eq 4500 
access-list 102 extended permit esp host 64.104.14.232 host 59.17.183.46 
access-list 102 extended permit udp host 64.104.14.232 host 59.17.183.46 eq isakmp 
access-list 102 extended permit esp host 64.104.14.233 host 59.17.183.46 
access-list 102 extended permit udp host 64.104.14.233 host 59.17.183.46 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 62.28.47.246 eq isakmp 
access-list 102 extended permit udp object-group cognio_vpn_external-rtp-1 object-group cognio_vpn_internal-rtp-1 eq isakmp 
access-list 102 extended permit udp object-group cognio_vpn_external-rtp-1 object-group cognio_vpn_internal-rtp-1 eq 10000 
access-list 102 extended permit udp host 64.103.35.61 host 62.149.65.253 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 62.149.65.253 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 62.162.40.202 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 212.185.76.61 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 200.169.116.9 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 89.121.2.198 
access-list 102 extended permit udp host 64.103.35.189 host 89.121.2.198 eq isakmp 
access-list 102 extended permit icmp 10.52.196.0 255.255.255.0 host 212.183.133.181 echo 
access-list 102 extended permit esp 10.52.196.0 255.255.255.0 host 212.183.133.177 
access-list 102 extended permit udp 10.52.196.0 255.255.255.0 host 212.183.133.177 eq isakmp 
access-list 102 extended permit udp 10.52.196.0 255.255.255.0 host 212.183.133.177 eq 4500 
access-list 102 extended permit udp 10.52.196.0 255.255.255.0 host 212.183.133.182 eq ntp 
access-list 102 extended permit udp host 144.254.146.9 host 193.227.215.137 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 192.168.218.20 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 62.168.66.84 eq isakmp 
access-list 102 extended permit gre host 144.254.135.233 host 64.103.36.241 
access-list 102 extended permit gre host 10.76.244.3 host 72.163.216.168 
access-list 102 extended permit gre host 144.254.142.233 host 64.103.36.241 
access-list 102 extended permit gre host 10.53.207.241 host 64.103.36.241 
access-list 102 extended permit gre host 10.53.207.253 host 64.103.36.241 
access-list 102 extended permit gre host 10.54.99.1 host 64.103.36.241 
access-list 102 extended permit gre host 10.53.207.243 host 64.103.36.241 
access-list 102 extended permit gre host 10.53.207.245 host 64.103.36.241 
access-list 102 extended permit gre host 10.49.68.2 host 64.103.36.241 
access-list 102 extended permit gre host 10.49.68.3 host 64.103.36.241 
access-list 102 extended permit gre host 10.54.43.130 host 64.103.36.241 
access-list 102 extended permit gre host 192.133.211.33 host 10.81.255.11 
access-list 102 extended permit gre host 192.133.211.34 host 10.81.255.20 
access-list 102 extended permit gre host 10.81.255.11 host 192.133.211.33 
access-list 102 extended permit gre host 10.81.255.20 host 192.133.211.34 
access-list 102 extended permit gre host 10.75.220.225 host 64.104.127.65 
access-list 102 extended permit gre host 10.71.55.193 host 64.104.44.97 
access-list 102 extended permit gre host 10.53.207.247 host 64.103.36.241 
access-list 102 extended permit gre host 10.53.207.249 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.178.209 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.138.217 host 64.103.36.241 
access-list 102 extended permit gre host 10.48.100.66 host 64.103.36.241 
access-list 102 extended permit gre host 216.128.58.249 host 64.103.36.241 
access-list 102 extended permit gre host 10.52.245.39 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.137.211 host 64.103.36.241 
access-list 102 extended permit gre host 10.59.22.241 host 64.103.36.241 
access-list 102 extended permit gre host 10.49.68.9 host 64.103.36.241 
access-list 102 extended permit gre host 10.66.139.124 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.130.185 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.130.121 host 64.103.36.241 
access-list 102 extended permit gre host 10.62.68.33 host 64.103.36.241 
access-list 102 extended permit gre host 10.53.209.1 host 64.103.36.241 
access-list 102 extended permit udp host 64.103.35.61 host 195.97.150.221 eq isakmp 
access-list 102 extended permit gre host 144.254.137.233 host 64.103.36.241 
access-list 102 extended permit udp host 64.103.35.61 host 195.97.150.221 eq 4500 
access-list 102 extended permit gre host 10.66.226.193 host 64.104.252.65 
access-list 102 extended permit udp host 10.77.79.58 any range 16000 32000 
access-list 102 extended permit udp host 144.254.146.9 host 196.192.6.24 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 196.192.6.24 eq 4500 
access-list 102 extended permit udp host 144.254.146.9 host 196.192.6.28 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 196.192.6.28 eq 4500 
access-list 102 extended permit udp host 144.254.146.9 host 168.140.182.10 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 80.254.144.140 
access-list 102 extended permit udp host 64.103.35.189 host 80.254.144.140 eq isakmp 
access-list 102 extended permit esp host 64.103.35.61 host 80.254.144.140 
access-list 102 extended permit udp host 64.103.35.61 host 80.254.144.140 eq isakmp 
access-list 102 extended permit udp object-group VCS_Controls_TME_labs object-group sjc_ace_vcse range 7000 7020 
access-list 102 extended permit udp object-group VCS_Controls_TME_labs object-group sjc_ace_vcse eq 2776 
access-list 102 extended permit udp object-group VCS_Controls_TME_labs object-group sjc_ace_vcse eq 2777 
access-list 102 extended permit udp object-group VCS_Controls_TME_labs object-group sjc_ace_vcse range 56000 57000 
access-list 102 extended permit udp object-group VCS_Controls_TME_labs eq 3478 object-group sjc_ace_vcse 
access-list 102 extended permit udp host 64.104.213.240 host 203.174.191.118 eq isakmp 
access-list 102 extended permit esp host 64.104.213.240 host 203.174.191.118 
access-list 102 extended permit gre host 10.49.66.97 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.142.57 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.143.17 host 64.103.36.241 
access-list 102 extended permit udp host 216.128.60.197 host 194.170.166.186 eq isakmp 
access-list 102 extended permit udp host 216.128.60.189 host 194.170.166.186 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 62.160.254.30 eq isakmp 
access-list 102 extended permit esp host 64.104.123.9 host 125.215.161.66 
access-list 102 extended permit udp host 64.104.123.9 host 125.215.161.66 eq isakmp 
access-list 102 extended permit udp host 64.104.123.9 host 125.215.161.66 eq 4500 
access-list 102 extended permit gre host 10.79.181.195 host 64.104.127.65 
access-list 102 extended permit gre host 72.163.216.168 host 10.104.145.4 
access-list 102 extended permit gre host 10.105.19.243 host 72.163.216.168 
access-list 102 extended permit gre host 216.128.58.185 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.140.25 host 64.103.36.241 
access-list 102 extended permit udp host 144.254.146.9 host 147.114.226.99 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 194.62.232.117 eq isakmp 
access-list 102 extended permit gre host 144.254.143.41 host 64.103.36.241 
access-list 102 extended permit esp host 64.103.35.61 host 195.222.34.182 
access-list 102 extended permit udp host 64.103.35.61 host 195.222.34.182 eq isakmp 
access-list 102 extended permit udp host 10.61.2.114 host 64.103.36.18 eq isakmp 
access-list 102 extended permit udp 172.16.8.0 255.255.255.0 host 128.107.236.88 eq snmp 
access-list 102 extended permit udp 172.16.8.0 255.255.255.0 host 128.107.236.88 eq 10162 
access-list 102 extended permit udp 172.16.8.0 255.255.255.0 host 128.107.236.88 eq 902 
access-list 102 extended permit esp host 10.76.45.30 host 72.163.216.158 
access-list 102 extended permit udp host 10.76.45.30 host 72.163.216.158 eq isakmp 
access-list 102 extended permit esp host 64.103.35.61 host 62.68.38.110 
access-list 102 extended permit udp host 64.103.35.61 host 62.68.38.110 eq isakmp 
access-list 102 extended permit esp host 64.103.35.61 host 62.68.39.158 
access-list 102 extended permit udp host 64.103.35.61 host 62.68.39.158 eq isakmp 
access-list 102 extended permit udp host 64.102.24.232 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.102.24.221 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.102.2.31 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.102.2.22 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.102.122.103 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.102.122.102 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.100.36.167 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.100.36.166 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.100.24.204 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.100.24.203 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.100.145.251 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.100.145.250 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.100.36.175 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.100.36.176 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.100.36.177 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.100.24.207 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.100.24.208 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.100.24.209 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.100.145.252 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.100.145.253 host 64.102.244.136 range 16384 32767 
access-list 102 extended permit udp host 64.102.24.232 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.102.24.221 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.102.2.31 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.102.2.22 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.102.122.103 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.102.122.102 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.100.36.167 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.100.36.166 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.100.24.204 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.100.24.203 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.100.145.251 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.100.145.250 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.100.36.175 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.100.36.176 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.100.36.177 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.100.24.207 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.100.24.208 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.100.24.209 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.100.145.252 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp host 64.100.145.253 host 64.102.244.137 range 16384 32767 
access-list 102 extended permit udp any host 64.104.249.165 range 16384 32768 
access-list 102 extended permit udp any host 64.104.249.174 range 16384 32768 
access-list 102 extended permit gre host 10.91.120.62 host 64.102.254.10 
access-list 102 extended permit gre host 10.66.139.124 host 64.102.240.233 
access-list 102 extended permit gre host 10.66.139.124 host 64.102.240.234 
access-list 102 extended permit udp any 64.100.0.0 255.255.248.0 eq isakmp 
access-list 102 extended permit gre 10.101.0.0 255.255.128.0 host 128.107.235.30 
access-list 102 extended permit gre 10.123.0.0 255.255.0.0 host 128.107.235.30 
access-list 102 extended permit gre host 144.254.138.97 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.142.105 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.97.250 host 64.103.36.241 
access-list 102 extended permit udp host 64.102.244.54 host 64.102.244.53 eq isakmp 
access-list 102 extended permit udp any host 64.100.13.55 eq 443 
access-list 102 extended permit udp any host 64.100.13.56 eq 443 
access-list 102 extended permit udp any host 64.100.13.57 eq 443 
access-list 102 extended permit udp any host 64.100.13.58 eq 443 
access-list 102 extended permit udp any host 64.100.13.59 eq 443 
access-list 102 extended permit udp any host 64.100.13.60 eq 443 
access-list 102 extended permit udp any host 64.100.13.61 eq 443 
access-list 102 extended permit udp any host 64.100.13.62 eq 443 
access-list 102 extended permit udp any host 64.100.13.63 eq 443 
access-list 102 extended permit udp any host 64.100.13.64 eq 443 
access-list 102 extended permit udp any host 64.100.13.65 eq 443 
access-list 102 extended permit udp any host 64.100.13.66 eq 443 
access-list 102 extended permit udp any host 64.100.13.67 eq 443 
access-list 102 extended permit udp any host 64.100.13.68 eq 443 
access-list 102 extended permit udp any host 64.100.13.69 eq 443 
access-list 102 extended permit udp any host 64.100.13.70 eq 443 
access-list 102 extended permit udp any host 64.100.13.71 eq 443 
access-list 102 extended permit udp any host 64.100.13.72 eq 443 
access-list 102 extended permit udp any host 64.100.13.73 eq 443 
access-list 102 extended permit udp any host 64.100.13.74 eq 443 
access-list 102 extended permit udp any host 64.100.13.75 eq 443 
access-list 102 extended permit udp any host 64.100.13.76 eq 443 
access-list 102 extended permit udp any host 64.100.13.77 eq 443 
access-list 102 extended permit udp any host 64.100.13.78 eq 443 
access-list 102 extended permit udp any host 64.100.13.79 eq 443 
access-list 102 extended permit udp any host 64.100.13.80 eq 443 
access-list 102 extended permit udp any host 64.100.13.81 eq 443 
access-list 102 extended permit udp any host 64.100.13.82 eq 443 
access-list 102 extended permit udp any host 64.100.13.83 eq 443 
access-list 102 extended permit udp any host 64.100.13.84 eq 443 
access-list 102 extended permit udp any host 64.100.13.85 eq 443 
access-list 102 extended permit udp any host 64.100.13.86 eq 443 
access-list 102 extended permit udp any host 64.100.13.87 eq 443 
access-list 102 extended permit udp any host 64.100.13.88 eq 443 
access-list 102 extended permit udp any host 64.100.13.89 eq 443 
access-list 102 extended permit udp any host 64.100.13.90 eq 443 
access-list 102 extended permit udp any host 64.100.13.91 eq 443 
access-list 102 extended permit udp any host 64.100.13.92 eq 443 
access-list 102 extended permit udp any host 64.100.13.93 eq 443 
access-list 102 extended permit udp any host 64.100.13.94 eq 443 
access-list 102 extended permit udp any host 64.100.13.95 eq 443 
access-list 102 extended permit udp any host 64.100.13.96 eq 443 
access-list 102 extended permit udp any host 64.100.13.97 eq 443 
access-list 102 extended permit udp any host 64.100.13.98 eq 443 
access-list 102 extended permit udp any host 64.100.13.99 eq 443 
access-list 102 extended permit udp any host 64.100.13.100 eq 443 
access-list 102 extended permit udp any host 64.100.13.101 eq 443 
access-list 102 extended permit udp any host 64.100.13.102 eq 443 
access-list 102 extended permit udp any host 64.100.13.103 eq 443 
access-list 102 extended permit udp any host 64.100.13.104 eq 443 
access-list 102 extended permit udp host 64.102.222.6 any eq 4500 
access-list 102 extended permit udp host 161.44.249.84 host 170.65.129.7 eq isakmp 
access-list 102 extended permit esp host 161.44.249.84 host 170.65.129.7 
access-list 102 extended permit udp host 161.44.249.84 host 170.65.129.7 eq 4500 
access-list 102 extended permit udp host 161.44.249.84 host 170.65.129.7 eq 10000 
access-list 102 extended permit ah host 161.44.249.84 host 170.65.129.7 
access-list 102 extended permit udp host 64.102.222.4 any eq 4500 
access-list 102 extended permit udp host 64.102.222.5 any eq 4500 
access-list 102 extended permit udp host 64.102.222.7 any eq 4500 
access-list 102 extended permit udp host 64.102.222.8 any eq 4500 
access-list 102 extended permit udp host 64.102.222.9 any eq 4500 
access-list 102 extended permit udp host 64.102.222.10 any eq 4500 
access-list 102 extended permit udp host 64.102.222.11 any eq 4500 
access-list 102 extended permit udp host 64.102.222.12 any eq 4500 
access-list 102 extended permit udp host 64.102.222.13 any eq 4500 
access-list 102 extended permit udp host 64.102.222.14 any eq 4500 
access-list 102 extended permit udp host 64.102.252.253 4.53.16.224 255.255.255.252 eq isakmp 
access-list 102 extended permit esp host 64.102.252.253 4.53.16.224 255.255.255.252 
access-list 102 extended permit udp host 64.102.252.253 4.59.196.36 255.255.255.252 eq isakmp 
access-list 102 extended permit esp host 64.102.252.253 4.59.196.36 255.255.255.252 
access-list 102 extended permit udp host 64.102.252.253 4.71.24.88 255.255.255.252 eq isakmp 
access-list 102 extended permit esp host 64.102.252.253 4.71.24.88 255.255.255.252 
access-list 102 extended permit udp host 64.102.252.253 4.71.160.52 255.255.255.252 eq isakmp 
access-list 102 extended permit esp host 64.102.252.253 4.71.160.52 255.255.255.252 
access-list 102 extended permit udp host 64.102.252.253 4.79.204.224 255.255.255.252 eq isakmp 
access-list 102 extended permit esp host 64.102.252.253 4.79.204.224 255.255.255.252 
access-list 102 extended permit udp host 64.102.252.253 4.71.120.184 255.255.255.252 eq isakmp 
access-list 102 extended permit esp host 64.102.252.253 4.71.120.184 255.255.255.252 
access-list 102 extended permit tcp host 198.135.0.164 any eq ssh 
access-list 102 extended permit tcp host 198.135.0.165 any eq ssh 
access-list 102 extended permit tcp host 198.135.0.166 any eq ssh 
access-list 102 extended permit gre host 10.101.14.16 host 172.17.153.20 
access-list 102 extended permit gre host 10.101.14.17 host 172.17.153.20 
access-list 102 extended permit gre host 172.17.153.20 host 10.101.14.16 
access-list 102 extended permit gre host 172.17.153.20 host 10.101.14.17 
access-list 102 extended permit gre host 10.101.14.16 host 172.17.153.65 
access-list 102 extended permit gre host 10.101.14.17 host 172.17.153.65 
access-list 102 extended permit gre host 172.17.153.65 host 10.101.14.16 
access-list 102 extended permit gre host 172.17.153.65 host 10.101.14.17 
access-list 102 extended permit gre host 10.86.234.13 host 172.17.153.20 
access-list 102 extended permit gre host 10.86.234.13 host 128.107.239.78 
access-list 102 extended permit gre host 10.81.255.20 host 128.107.240.170 
access-list 102 extended permit gre host 10.77.114.97 host 128.107.235.30 
access-list 102 extended permit gre host 10.56.109.173 host 172.17.153.20 
access-list 102 extended permit gre host 10.56.109.173 host 172.17.153.65 
access-list 102 extended permit udp host 128.107.201.239 any 
access-list 102 extended permit gre host 172.17.153.20 host 10.56.72.37 
access-list 102 extended permit gre host 10.56.72.37 host 172.17.153.20 
access-list 102 extended permit gre host 172.17.153.20 host 10.56.109.173 
access-list 102 extended permit gre host 172.17.153.65 host 10.56.109.173 
access-list 102 extended permit gre host 172.17.153.20 host 10.59.15.229 
access-list 102 extended permit gre host 10.59.15.229 host 172.17.153.20 
access-list 102 extended permit gre host 10.61.32.7 host 172.17.153.20 
access-list 102 extended permit gre host 10.70.225.102 host 172.17.153.20 
access-list 102 extended permit gre host 10.81.255.11 host 172.17.153.20 
access-list 102 extended permit gre host 10.66.129.17 host 172.17.153.20 
access-list 102 extended permit gre host 10.86.230.73 host 172.17.153.20 
access-list 102 extended permit gre host 10.89.255.196 host 172.17.153.20 
access-list 102 extended permit gre host 10.64.63.16 host 172.17.153.20 
access-list 102 extended permit gre host 172.17.153.20 host 10.61.32.7 
access-list 102 extended permit gre host 172.17.153.20 host 10.70.225.102 
access-list 102 extended permit gre host 172.17.153.20 host 10.81.255.11 
access-list 102 extended permit gre host 172.17.153.20 host 10.66.129.17 
access-list 102 extended permit gre host 172.17.153.20 host 10.86.230.73 
access-list 102 extended permit gre host 172.17.153.20 host 10.89.255.196 
access-list 102 extended permit gre host 172.17.153.20 host 10.64.63.16 
access-list 102 extended permit gre host 10.101.206.45 host 172.17.153.20 
access-list 102 extended permit gre host 10.101.206.46 host 128.107.240.170 
access-list 102 extended permit gre host 10.64.55.9 host 72.163.216.168 
access-list 102 extended permit gre host 10.76.121.1 host 72.163.216.168 
access-list 102 extended permit gre host 10.76.1.21 host 72.163.216.168 
access-list 102 extended permit gre host 10.76.236.1 host 72.163.216.168 
access-list 102 extended permit gre host 10.76.134.3 host 72.163.216.168 
access-list 102 extended permit icmp any host 64.104.127.182 echo-reply 
access-list 102 extended permit gre any host 128.107.81.84 
access-list 102 extended permit gre any host 10.101.14.26 
access-list 102 extended permit gre any host 198.135.0.108 
access-list 102 extended permit esp host 10.74.69.254 host 64.104.127.60 
access-list 102 extended permit udp host 10.74.69.254 host 64.104.127.60 eq isakmp 
access-list 102 extended permit esp host 10.74.43.142 host 64.104.127.60 
access-list 102 extended permit udp host 10.74.43.142 host 64.104.127.60 eq isakmp 
access-list 102 extended permit esp host 72.163.247.99 host 202.202.14.226 
access-list 102 extended permit udp host 72.163.247.99 host 202.202.14.226 eq isakmp 
access-list 102 extended permit gre host 10.75.1.81 host 64.104.127.65 
access-list 102 extended permit gre host 10.74.162.129 host 64.104.127.65 
access-list 102 extended permit esp host 72.163.247.98 host 61.183.120.22 
access-list 102 extended permit udp host 72.163.247.98 host 61.183.120.22 eq isakmp 
access-list 102 extended permit udp host 10.75.225.204 host 64.104.127.236 eq 2055 
access-list 102 extended permit udp host 10.75.225.205 host 64.104.127.236 eq 2055 
access-list 102 extended permit gre host 10.75.2.128 host 64.104.127.65 
access-list 102 extended permit gre host 10.75.0.193 host 64.104.127.65 
access-list 102 extended permit gre host 10.64.55.7 host 72.163.216.168 
access-list 102 extended permit gre host 10.64.55.24 host 72.163.216.168 
access-list 102 extended permit gre host 10.104.17.4 host 72.163.216.168 
access-list 102 extended permit gre host 10.77.79.129 host 72.163.216.168 
access-list 102 extended permit gre host 10.78.207.195 host 72.163.216.168 
access-list 102 extended permit gre host 10.77.113.1 host 72.163.216.168 
access-list 102 extended permit gre host 10.77.114.97 host 72.163.216.168 
access-list 102 extended permit gre host 10.77.116.113 host 72.163.216.168 
access-list 102 extended permit gre host 10.77.120.209 host 72.163.216.168 
access-list 102 extended permit gre host 10.77.96.65 host 72.163.216.168 
access-list 102 extended permit gre host 10.77.105.1 host 72.163.216.168 
access-list 102 extended permit gre host 10.68.169.81 host 64.104.95.129 
access-list 102 extended permit gre host 10.75.225.20 host 64.104.127.65 
access-list 102 extended permit gre 10.74.65.128 255.255.255.128 host 64.104.127.65 
access-list 102 extended permit esp host 72.163.247.99 host 222.178.4.1 
access-list 102 extended permit udp host 72.163.247.99 host 222.178.4.1 eq isakmp 
access-list 102 extended permit gre host 10.75.0.64 host 64.104.127.65 
access-list 102 extended permit gre host 10.78.49.1 host 72.163.216.168 
access-list 102 extended permit gre host 10.76.112.65 host 72.163.216.168 
access-list 102 extended permit gre host 10.78.64.67 host 72.163.216.168 
access-list 102 extended permit gre host 10.76.144.129 host 72.163.216.168 
access-list 102 extended permit gre host 10.74.98.1 host 64.104.127.65 
access-list 102 extended permit esp host 72.163.247.98 host 221.224.201.178 
access-list 102 extended permit udp host 72.163.247.98 host 221.224.201.178 eq isakmp 
access-list 102 extended permit esp host 72.163.247.99 host 58.211.57.218 
access-list 102 extended permit udp host 72.163.247.99 host 58.211.57.218 eq isakmp 
access-list 102 extended permit esp host 72.163.247.99 host 219.149.10.202 
access-list 102 extended permit udp host 72.163.247.99 host 219.149.10.202 eq isakmp 
access-list 102 extended permit esp host 10.74.194.34 host 64.104.127.60 
access-list 102 extended permit udp host 10.74.194.34 host 64.104.127.60 eq isakmp 
access-list 102 extended permit udp host 72.163.247.99 host 59.46.172.198 eq isakmp 
access-list 102 extended permit gre host 64.104.127.65 host 10.75.32.1 
access-list 102 extended permit gre host 171.69.86.80 object-group microsoft_gre_support-sjc-1 
access-list 102 extended permit udp host 64.101.31.6 host 65.74.0.194 eq isakmp 
access-list 102 extended permit udp host 64.101.31.10 host 65.74.0.194 eq isakmp 
access-list 102 extended permit esp host 64.101.31.6 host 174.34.83.106 
access-list 102 extended permit udp host 64.101.31.6 host 174.34.83.106 eq isakmp 
access-list 102 extended permit esp host 64.101.31.10 host 174.34.83.106 
access-list 102 extended permit udp host 64.101.31.10 host 174.34.83.106 eq isakmp 
access-list 102 extended permit gre 10.78.0.0 255.255.0.0 host 128.107.235.30 
access-list 102 extended permit gre 10.76.0.0 255.254.0.0 host 128.107.235.30 
access-list 102 extended permit gre 10.64.0.0 255.254.0.0 host 128.107.235.30 
access-list 102 extended permit gre host 10.68.80.1 host 64.104.95.129 
access-list 102 extended permit esp host 10.79.31.3 host 222.127.10.155 
access-list 102 extended permit udp host 10.79.31.3 host 222.127.10.155 eq isakmp 
access-list 102 extended permit udp host 10.79.31.3 host 222.127.10.155 eq 4500 
access-list 102 extended permit gre host 10.75.8.145 host 64.104.127.65 
access-list 102 extended permit gre host 10.68.97.7 host 64.104.95.129 
access-list 102 extended permit gre host 10.77.120.209 host 128.107.235.30 
access-list 102 extended permit gre host 10.78.207.195 host 128.107.235.30 
access-list 102 extended permit gre 10.21.192.0 255.255.192.0 host 128.107.235.30 
access-list 102 extended permit gre host 10.92.96.3 host 128.107.235.30 
access-list 102 extended permit gre host 72.163.98.39 host 192.84.63.20 
access-list 102 extended permit gre host 128.107.240.170 host 10.81.255.20 
access-list 102 extended permit tcp host 172.18.133.235 host 64.100.8.212 eq bgp 
access-list 102 extended permit gre host 72.163.98.39 host 192.58.227.70 
access-list 102 extended permit gre host 10.66.216.64 host 64.104.252.65 
access-list 102 extended permit gre host 10.67.38.129 host 64.104.252.65 
access-list 102 extended permit gre host 172.17.153.20 host 10.66.129.144 
access-list 102 extended permit gre host 128.107.240.170 host 10.66.129.144 
access-list 102 extended permit udp host 10.66.129.139 host 64.104.252.100 eq 2055 
access-list 102 extended permit udp host 10.66.129.140 host 64.104.252.100 eq 2055 
access-list 102 extended permit gre host 10.62.58.177 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.140.49 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.140.137 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.139.249 host 64.103.36.241 
access-list 102 extended permit esp host 64.103.35.61 host 84.124.78.178 
access-list 102 extended permit udp host 64.103.35.61 host 84.124.78.178 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 41.250.250.139 
access-list 102 extended permit udp host 64.103.35.189 host 41.250.250.139 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 41.250.250.139 eq 4500 
access-list 102 extended permit gre host 216.128.58.153 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.128.89 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.130.153 host 64.103.36.241 
access-list 102 extended permit gre host 10.113.20.1 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.141.177 host 64.103.36.241 
access-list 102 extended permit gre host 216.128.58.121 host 64.103.36.241 
access-list 102 extended permit gre host 10.50.31.33 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.138.113 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.141.49 host 64.103.36.241 
access-list 102 extended permit gre host 10.113.15.225 host 64.103.36.241 
access-list 102 extended permit gre host 10.61.32.7 host 172.17.153.65 
access-list 102 extended permit gre host 216.128.58.49 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.138.89 host 64.103.36.241 
access-list 102 extended permit udp host 171.70.144.141 host 64.104.249.138 range 8995 8996 
access-list 102 extended permit udp host 171.70.144.141 host 64.104.249.139 range 8995 8996 
access-list 102 extended permit udp host 171.70.144.141 host 64.104.249.140 range 8995 8996 
access-list 102 extended permit udp host 171.70.144.142 host 64.104.249.138 range 8995 8996 
access-list 102 extended permit udp host 171.70.144.142 host 64.104.249.139 range 8995 8996 
access-list 102 extended permit udp host 171.70.144.142 host 64.104.249.140 range 8995 8996 
access-list 102 extended permit udp host 171.70.144.143 host 64.104.249.138 range 8995 8996 
access-list 102 extended permit udp host 171.70.144.143 host 64.104.249.139 range 8995 8996 
access-list 102 extended permit udp host 171.70.144.143 host 64.104.249.140 range 8995 8996 
access-list 102 extended permit gre host 10.75.5.225 host 64.104.127.65 
access-list 102 extended permit gre host 10.75.6.225 host 64.104.127.65 
access-list 102 extended permit gre host 144.254.131.153 host 64.103.36.241 
access-list 102 extended permit gre host 10.52.22.15 host 64.103.36.241 
access-list 102 extended permit gre host 10.51.39.241 host 64.103.36.241 
access-list 102 extended permit gre host 10.48.101.24 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.140.249 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.139.121 host 64.103.36.241 
access-list 102 extended permit udp host 64.103.35.61 host 195.222.180.118 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 83.90.193.122 
access-list 102 extended permit udp host 64.103.35.189 host 83.90.193.122 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 91.112.142.182 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 88.43.51.42 eq isakmp 
access-list 102 extended permit udp any host 128.107.85.172 range 16384 65535 
access-list 102 extended permit udp any eq 4000 host 128.107.85.172 range 16384 18000 
access-list 102 extended permit udp any host 64.104.94.38 range 16384 65535 
access-list 102 extended permit udp any eq 4000 host 64.104.94.38 range 16384 18000 
access-list 102 extended permit udp any host 64.103.39.115 range 16384 65535 
access-list 102 extended permit udp any eq 4000 host 64.103.39.115 range 16384 18000 
access-list 102 extended permit esp host 64.103.35.61 host 213.135.235.201 
access-list 102 extended permit udp host 64.103.35.61 host 213.135.235.201 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 213.135.235.201 eq 4500 
access-list 102 extended permit udp host 64.103.35.61 host 202.141.252.211 eq isakmp 
access-list 102 extended permit gre host 144.254.135.185 host 64.103.36.241 
access-list 102 extended permit udp host 64.103.35.189 host 196.20.69.18 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 196.20.69.18 eq 4500 
access-list 102 extended permit gre host 144.254.128.25 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.137.145 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.137.121 host 64.103.36.241 
access-list 102 extended permit gre 64.103.12.128 255.255.255.240 any 
access-list 102 extended permit tcp 64.103.12.128 255.255.255.240 any eq pptp 
access-list 102 extended permit udp host 171.71.10.125 host 63.67.145.5 eq isakmp 
access-list 102 extended permit udp host 64.101.31.6 host 65.74.0.192 eq isakmp 
access-list 102 extended permit udp host 64.101.31.10 host 65.74.0.192 eq isakmp 
access-list 102 extended permit udp host 63.67.145.5 host 171.71.10.125 eq isakmp 
access-list 102 extended permit udp host 64.101.65.49 host 170.248.184.135 eq isakmp 
access-list 102 extended permit udp host 64.101.65.49 host 170.248.184.136 eq isakmp 
access-list 102 extended permit udp host 64.101.65.49 host 170.252.11.250 eq isakmp 
access-list 102 extended permit gre 64.102.35.0 255.255.255.128 object-group hp_vendor_vpn-global-1 
access-list 102 extended permit udp 64.102.35.0 255.255.255.128 object-group hp_vendor_vpn-global-1 eq isakmp 
access-list 102 extended permit udp 64.102.35.0 255.255.255.128 object-group hp_vendor_vpn-global-1 eq 4500 
access-list 102 extended permit udp 64.102.35.0 255.255.255.128 object-group hp_vendor_vpn-global-1 eq 1701 
access-list 102 extended permit esp host 64.102.253.90 host 69.223.230.140 
access-list 102 extended permit udp host 64.102.253.90 host 69.223.230.140 eq isakmp 
access-list 102 extended permit esp host 64.102.253.94 host 69.223.230.140 
access-list 102 extended permit udp host 64.102.253.94 host 69.223.230.140 eq isakmp 
access-list 102 extended permit esp host 16.212.56.1 host 171.71.148.74 
access-list 102 extended permit udp host 64.101.65.46 host 161.225.129.30 eq isakmp 
access-list 102 extended permit udp host 171.70.112.212 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.222 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.213 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.223 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.214 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.224 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.215 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.225 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.216 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.226 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.217 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.227 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.218 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.228 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.219 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.229 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.204 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.204 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.205 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.205 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.68.38.28 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.68.38.29 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 72.163.36.151 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 72.163.36.152 host 128.107.240.56 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.212 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.222 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.213 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.223 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.214 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.224 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.215 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.225 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.216 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.226 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.217 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.227 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.218 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.228 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.219 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.229 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.204 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.204 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.70.112.205 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.68.196.205 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.68.38.28 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 171.68.38.29 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 72.163.36.151 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp host 72.163.36.152 host 128.107.240.57 range 16384 32767 
access-list 102 extended permit udp any object-group uc_verizon_sip_trunk-rtp-1 range 16384 32767 
access-list 102 extended permit udp any object-group uc_verizon_sip_trunk-sjc-1 range 16384 32767 
access-list 102 extended permit udp any object-group uc_verizon_sip_trunk-sjc-alpha range 16384 32767 
access-list 102 extended permit udp any object-group uc_verizon_sip_trunk-ams-1 range 16384 32767 
access-list 102 extended permit udp host 144.254.146.9 host 62.190.154.7 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 212.118.128.233 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 212.45.162.132 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 212.185.76.33 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 86.66.33.147 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 147.114.44.83 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 193.127.200.22 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 171.18.10.10 eq isakmp 
access-list 102 extended permit udp host 64.101.31.6 host 67.105.95.188 eq isakmp 
access-list 102 extended permit udp host 64.101.31.10 host 67.105.95.188 eq isakmp 
access-list 102 extended permit esp host 171.71.3.14 host 68.118.31.23 
access-list 102 extended permit udp host 171.71.3.14 host 68.118.31.23 eq isakmp 
access-list 102 extended permit esp host 171.71.3.14 host 63.148.170.30 
access-list 102 extended permit udp host 171.71.3.14 host 63.148.170.30 eq isakmp 
access-list 102 extended permit esp host 171.71.3.26 host 68.118.31.23 
access-list 102 extended permit udp host 171.71.3.26 host 68.118.31.23 eq isakmp 
access-list 102 extended permit esp host 171.71.3.26 host 63.148.170.30 
access-list 102 extended permit udp host 171.71.3.26 host 63.148.170.30 eq isakmp 
access-list 102 extended permit gre host 10.68.12.15 host 128.107.240.24 
access-list 102 extended permit gre host 10.68.12.15 host 128.107.240.170 
access-list 102 extended permit gre host 128.107.240.24 host 10.68.12.15 
access-list 102 extended permit gre host 128.107.240.170 host 10.68.12.15 
access-list 102 extended permit udp 10.35.176.0 255.255.255.0 host 128.107.235.138 eq snmp 
access-list 102 extended permit udp 10.35.176.0 255.255.255.0 host 128.107.235.138 eq syslog 
access-list 102 extended permit udp 10.35.176.0 255.255.255.0 host 128.107.235.138 eq 9161 
access-list 102 extended permit udp 10.35.173.128 255.255.255.128 host 128.107.235.138 eq snmp 
access-list 102 extended permit udp 10.35.173.128 255.255.255.128 host 128.107.235.138 eq syslog 
access-list 102 extended permit udp 10.35.173.128 255.255.255.128 host 128.107.235.138 eq 9161 
access-list 102 extended permit udp 10.35.176.0 255.255.255.0 host 128.107.235.139 eq snmp 
access-list 102 extended permit udp 10.35.176.0 255.255.255.0 host 128.107.235.139 eq syslog 
access-list 102 extended permit udp 10.35.176.0 255.255.255.0 host 128.107.235.139 eq 9161 
access-list 102 extended permit udp 10.35.173.128 255.255.255.128 host 128.107.235.139 eq snmp 
access-list 102 extended permit udp 10.35.173.128 255.255.255.128 host 128.107.235.139 eq syslog 
access-list 102 extended permit udp 10.35.173.128 255.255.255.128 host 128.107.235.139 eq 9161 
access-list 102 extended permit udp 10.35.176.0 255.255.255.0 host 128.107.235.140 eq snmp 
access-list 102 extended permit udp 10.35.176.0 255.255.255.0 host 128.107.235.140 eq syslog 
access-list 102 extended permit udp 10.35.176.0 255.255.255.0 host 128.107.235.140 eq 9161 
access-list 102 extended permit udp 10.35.173.128 255.255.255.128 host 128.107.235.140 eq snmp 
access-list 102 extended permit udp 10.35.173.128 255.255.255.128 host 128.107.235.140 eq syslog 
access-list 102 extended permit udp 10.35.173.128 255.255.255.128 host 128.107.235.140 eq 9161 
access-list 102 extended permit udp 10.35.176.0 255.255.255.0 host 128.107.235.141 eq snmp 
access-list 102 extended permit udp 10.35.176.0 255.255.255.0 host 128.107.235.141 eq syslog 
access-list 102 extended permit udp 10.35.176.0 255.255.255.0 host 128.107.235.141 eq 9161 
access-list 102 extended permit udp 10.35.173.128 255.255.255.128 host 128.107.235.141 eq snmp 
access-list 102 extended permit udp 10.35.173.128 255.255.255.128 host 128.107.235.141 eq syslog 
access-list 102 extended permit udp 10.35.173.128 255.255.255.128 host 128.107.235.141 eq 9161 
access-list 102 extended permit udp 10.35.176.0 255.255.255.0 host 128.107.235.142 eq snmp 
access-list 102 extended permit udp 10.35.176.0 255.255.255.0 host 128.107.235.142 eq syslog 
access-list 102 extended permit udp 10.35.176.0 255.255.255.0 host 128.107.235.142 eq 9161 
access-list 102 extended permit udp 10.35.173.128 255.255.255.128 host 128.107.235.142 eq snmp 
access-list 102 extended permit udp 10.35.173.128 255.255.255.128 host 128.107.235.142 eq syslog 
access-list 102 extended permit udp 10.35.173.128 255.255.255.128 host 128.107.235.142 eq 9161 
access-list 102 extended permit udp host 171.70.146.140 172.17.153.128 255.255.255.240 eq 902 
access-list 102 extended permit udp host 171.70.146.140 172.17.153.144 255.255.255.240 eq 902 
access-list 102 extended permit udp host 10.92.240.142 host 128.107.81.84 eq isakmp 
access-list 102 extended permit udp host 171.70.121.31 host 128.107.83.68 range 1024 65535 
access-list 102 extended permit tcp host 171.70.121.31 host 128.107.83.68 range 1024 4999 
access-list 102 extended permit udp host 171.70.121.16 host 128.107.83.68 range 18000 19000 
access-list 102 extended permit tcp host 171.70.121.16 host 128.107.83.68 range 1024 4999 
access-list 102 extended permit udp host 171.70.121.17 host 128.107.83.68 range 19000 19250 
access-list 102 extended permit tcp host 171.70.121.17 host 128.107.83.68 range 1024 4999 
access-list 102 extended permit udp host 171.70.121.62 host 128.107.83.68 range 19000 19250 
access-list 102 extended permit tcp host 171.70.121.62 host 128.107.83.68 range 1024 4999 
access-list 102 extended permit udp host 171.70.121.63 host 128.107.83.68 range 19000 19250 
access-list 102 extended permit tcp host 171.70.121.63 host 128.107.83.68 range 1024 4999 
access-list 102 extended permit udp any host 202.95.106.170 
access-list 102 extended permit udp any host 194.0.215.36 
access-list 102 extended permit udp any host 194.0.215.35 
access-list 102 extended permit udp any host 203.166.11.98 
access-list 102 extended permit gre host 10.67.54.97 host 64.104.252.65 
access-list 102 extended permit udp any host 194.0.215.242 
access-list 102 extended permit udp any host 194.0.215.210 
access-list 102 extended permit gre host 10.66.139.124 host 128.107.235.30 
access-list 102 extended permit gre host 10.66.139.124 host 64.104.95.129 
access-list 102 extended permit udp host 64.101.188.126 host 12.49.117.253 eq isakmp 
access-list 102 extended permit esp host 64.101.188.126 host 12.49.117.253 
access-list 102 extended permit udp host 64.101.188.126 host 12.49.117.253 eq 4500 
access-list 102 extended permit udp host 64.101.188.126 host 12.49.117.253 eq 10000 
access-list 102 extended permit ah host 64.101.188.126 host 12.49.117.253 
access-list 102 extended permit udp host 64.104.14.232 host 61.118.178.189 eq isakmp 
access-list 102 extended permit udp host 64.104.14.233 host 61.118.178.189 eq isakmp 
access-list 102 extended permit udp any host 128.107.87.53 eq 3478 
access-list 102 extended permit udp host 64.101.137.40 host 162.119.64.200 eq isakmp 
access-list 102 extended permit udp host 64.101.137.40 host 162.119.64.200 eq 10000 
access-list 102 extended permit udp host 64.101.137.40 host 162.119.64.200 eq 4500 
access-list 102 extended permit udp host 64.101.137.40 host 162.119.232.200 eq isakmp 
access-list 102 extended permit udp host 64.101.137.40 host 162.119.232.200 eq 10000 
access-list 102 extended permit udp host 64.101.137.40 host 162.119.232.200 eq 4500 
access-list 102 extended permit udp host 64.101.31.6 host 69.178.6.1 eq isakmp 
access-list 102 extended permit udp host 64.101.31.10 host 69.178.6.1 eq isakmp 
access-list 102 extended permit udp any host 64.103.36.18 eq isakmp 
access-list 102 extended permit udp host 10.76.12.48 host 72.163.216.158 eq isakmp 
access-list 102 extended permit tcp host 128.107.191.10 host 64.103.37.170 eq https 
access-list 102 extended permit tcp host 128.107.191.32 host 64.103.37.170 eq https 
access-list 102 extended permit tcp host 128.107.191.114 host 64.103.37.170 eq https 
access-list 102 extended permit tcp host 72.163.56.102 host 64.103.37.170 eq ldaps 
access-list 102 extended permit tcp host 72.163.56.103 host 64.103.37.170 eq ldaps 
access-list 102 extended permit udp host 10.60.4.118 host 64.103.36.18 eq isakmp 
access-list 102 extended permit udp host 10.74.43.26 host 64.104.127.60 eq isakmp 
access-list 102 extended permit esp host 10.74.43.30 host 64.104.127.60 
access-list 102 extended permit udp host 10.74.43.30 host 64.104.127.60 eq isakmp 
access-list 102 extended permit esp host 72.163.247.98 host 220.249.125.11 
access-list 102 extended permit udp host 72.163.247.98 host 220.249.125.11 eq isakmp 
access-list 102 extended permit esp host 72.163.247.98 host 113.204.103.178 
access-list 102 extended permit udp host 72.163.247.98 host 113.204.103.178 eq isakmp 
access-list 102 extended permit esp host 10.76.45.26 host 72.163.216.158 
access-list 102 extended permit ah host 10.76.45.26 host 72.163.216.158 
access-list 102 extended permit udp host 10.76.45.26 host 72.163.216.158 eq isakmp 
access-list 102 extended permit esp host 72.163.247.98 host 120.36.2.74 
access-list 102 extended permit udp host 72.163.247.98 host 120.36.2.74 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 82.45.149.150 eq isakmp 
access-list 102 extended permit esp host 64.104.81.209 host 203.210.210.95 
access-list 102 extended permit udp host 64.104.81.209 host 203.210.210.95 eq isakmp 
access-list 102 extended permit esp any host 114.112.188.82 
access-list 102 extended permit udp any host 114.112.188.82 eq isakmp 
access-list 102 extended permit udp any host 114.112.188.82 eq 4500 
access-list 102 extended permit esp host 10.74.43.38 host 64.104.127.60 
access-list 102 extended permit udp host 10.74.43.38 host 64.104.127.60 eq isakmp 
access-list 102 extended permit esp host 72.163.247.98 host 59.46.64.130 
access-list 102 extended permit udp host 72.163.247.98 host 59.46.64.130 eq isakmp 
access-list 102 extended permit gre host 10.74.160.145 host 64.104.127.65 
access-list 102 extended permit gre host 10.66.139.124 host 64.104.127.65 
access-list 102 extended permit esp any host 59.151.117.90 
access-list 102 extended permit udp any host 59.151.117.90 eq isakmp 
access-list 102 extended permit udp any host 59.151.117.90 eq 4500 
access-list 102 extended permit gre host 10.75.12.81 host 64.104.127.65 
access-list 102 extended permit esp host 10.74.69.198 host 64.104.127.60 
access-list 102 extended permit udp host 10.74.69.198 host 64.104.127.60 eq isakmp 
access-list 102 extended permit esp host 10.74.43.86 host 64.104.127.60 
access-list 102 extended permit udp host 10.74.43.86 host 64.104.127.60 eq isakmp 
access-list 102 extended permit esp host 72.163.247.98 host 222.82.144.158 
access-list 102 extended permit udp host 72.163.247.98 host 222.82.144.158 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 188.225.178.102 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 217.21.8.90 eq isakmp 
access-list 102 extended permit esp host 72.163.247.98 host 219.144.162.132 
access-list 102 extended permit udp host 72.163.247.98 host 219.144.162.132 eq isakmp 
access-list 102 extended permit esp host 72.163.247.98 host 219.144.162.134 
access-list 102 extended permit udp host 72.163.247.98 host 219.144.162.134 eq isakmp 
access-list 102 extended permit esp host 72.163.247.99 host 221.224.165.178 
access-list 102 extended permit udp host 72.163.247.99 host 221.224.165.178 eq isakmp 
access-list 102 extended permit udp host 72.163.247.99 host 121.15.174.170 eq isakmp 
access-list 102 extended permit udp host 72.163.247.99 host 121.35.10.151 eq isakmp 
access-list 102 extended permit esp host 72.163.247.99 host 218.17.93.134 
access-list 102 extended permit udp host 72.163.247.99 host 218.17.93.134 eq isakmp 
access-list 102 extended permit esp host 72.163.247.99 host 61.142.98.129 
access-list 102 extended permit udp host 72.163.247.99 host 61.142.98.129 eq isakmp 
access-list 102 extended permit udp host 171.70.192.44 any eq 4500 
access-list 102 extended permit udp host 171.70.192.45 any eq 4500 
access-list 102 extended permit udp host 171.70.192.46 any eq 4500 
access-list 102 extended permit udp host 171.70.192.51 any eq 4500 
access-list 102 extended permit udp host 171.71.3.42 any eq isakmp 
access-list 102 extended permit udp host 171.71.3.42 any eq 4500 
access-list 102 extended permit udp host 64.101.65.46 host 161.225.176.10 eq isakmp 
access-list 102 extended permit udp host 72.163.248.241 any eq isakmp 
access-list 102 extended permit gre host 10.62.84.1 host 64.103.36.241 
access-list 102 extended permit udp host 10.50.177.18 host 144.254.51.84 range 902 903 
access-list 102 extended permit gre host 10.78.224.30 host 72.163.216.158 
access-list 102 extended permit udp host 10.52.196.145 host 67.105.198.21 eq 36121 
access-list 102 extended permit udp host 10.34.130.10 host 128.107.241.118 range 1024 65525 
access-list 102 extended permit udp host 10.35.22.18 host 128.107.81.144 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.18 host 128.107.81.145 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.18 host 128.107.241.119 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.18 host 128.107.233.36 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.31 host 128.107.81.144 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.31 host 128.107.81.145 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.31 host 128.107.241.119 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.31 host 128.107.233.36 range snmp snmptrap 
access-list 102 extended permit udp host 171.70.93.61 host 128.107.81.144 range snmp snmptrap 
access-list 102 extended permit udp host 171.70.93.61 host 128.107.81.145 range snmp snmptrap 
access-list 102 extended permit udp host 171.70.93.61 host 128.107.241.119 range snmp snmptrap 
access-list 102 extended permit udp host 171.70.93.61 host 128.107.233.36 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.76 host 128.107.81.144 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.76 host 128.107.81.145 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.76 host 128.107.241.119 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.76 host 128.107.233.36 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.77 host 128.107.81.144 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.77 host 128.107.81.145 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.77 host 128.107.241.119 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.77 host 128.107.233.36 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.78 host 128.107.81.144 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.78 host 128.107.81.145 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.78 host 128.107.241.119 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.78 host 128.107.233.36 range snmp snmptrap 
access-list 102 extended permit udp any host 64.104.94.62 range 1024 65535 
access-list 102 extended permit udp host 10.34.130.10 host 128.107.233.36 range 1024 65525 
access-list 102 extended permit udp host 10.34.130.10 host 128.107.241.123 range 1024 65525 
access-list 102 extended permit udp host 10.32.134.145 host 128.107.235.195 eq ntp 
access-list 102 extended permit tcp host 171.69.100.127 host 131.107.0.144 eq pptp 
access-list 102 extended permit tcp host 171.69.100.47 host 131.107.0.144 eq pptp 
access-list 102 extended permit tcp host 171.69.100.127 host 205.248.102.75 eq pptp 
access-list 102 extended permit tcp host 171.69.100.47 host 205.248.102.75 eq pptp 
access-list 102 extended permit gre host 171.69.100.127 host 131.107.0.144 
access-list 102 extended permit gre host 171.69.100.47 host 131.107.0.144 
access-list 102 extended permit gre host 171.69.100.127 host 205.248.102.75 
access-list 102 extended permit gre host 171.69.100.47 host 205.248.102.75 
access-list 102 extended permit tcp host 171.69.101.210 object-group microsoft_vpn_support-sjc-1 eq pptp 
access-list 102 extended permit gre host 171.69.101.210 object-group microsoft_vpn_support-sjc-1 
access-list 102 extended permit tcp host 171.69.100.127 object-group microsoft_vpn_support-sjc-1 eq pptp 
access-list 102 extended permit gre host 171.69.100.127 object-group microsoft_vpn_support-sjc-1 
access-list 102 extended permit tcp host 171.69.100.47 object-group microsoft_vpn_support-sjc-1 eq pptp 
access-list 102 extended permit gre host 171.69.100.47 object-group microsoft_vpn_support-sjc-1 
access-list 102 extended permit udp host 171.71.3.34 host 198.217.224.209 eq isakmp 
access-list 102 extended permit udp host 171.71.3.34 host 198.217.224.209 eq 10000 
access-list 102 extended permit udp host 171.71.3.34 host 198.217.224.217 eq isakmp 
access-list 102 extended permit udp host 171.71.3.34 host 198.217.224.217 eq 10000 
access-list 102 extended permit ah host 171.71.3.34 host 198.217.224.209 
access-list 102 extended permit ah host 171.71.3.34 host 198.217.224.217 
access-list 102 extended permit udp any host 64.100.9.36 eq isakmp 
access-list 102 extended permit udp any host 64.100.9.36 eq 4500 
access-list 102 extended permit esp any host 64.100.9.36 
access-list 102 extended permit udp any host 65.221.127.67 eq isakmp 
access-list 102 extended permit udp any host 65.221.127.68 eq isakmp 
access-list 102 extended permit udp any host 63.117.49.4 eq isakmp 
access-list 102 extended permit esp any host 65.221.127.67 
access-list 102 extended permit esp any host 65.221.127.68 
access-list 102 extended permit esp any host 63.117.49.4 
access-list 102 extended permit udp host 65.221.127.67 any eq 10000 
access-list 102 extended permit udp host 65.221.127.68 any eq 10000 
access-list 102 extended permit udp host 63.117.49.4 any eq 10000 
access-list 102 extended permit tcp host 65.221.127.67 any eq 10000 
access-list 102 extended permit tcp host 65.221.127.68 any eq 10000 
access-list 102 extended permit tcp host 63.117.49.4 any eq 10000 
access-list 102 extended permit tcp host 65.221.127.67 any eq 4500 
access-list 102 extended permit tcp host 65.221.127.68 any eq 4500 
access-list 102 extended permit tcp host 63.117.49.4 any eq 4500 
access-list 102 extended permit udp object-group tac_vpn_concentrators-rtp-1 any eq isakmp 
access-list 102 extended permit udp object-group tac_vpn_concentrators-rtp-1 any eq 4500 
access-list 102 extended permit udp host 64.102.156.97 any eq isakmp 
access-list 102 extended permit udp host 64.102.156.97 any eq 4500 
access-list 102 extended permit gre object-group tac_vpn_concentrators-rtp-1 any 
access-list 102 extended permit esp host 128.107.132.57 host 211.129.153.46 
access-list 102 extended permit udp host 128.107.132.57 host 211.129.153.46 eq isakmp 
access-list 102 extended permit esp host 128.107.130.212 host 211.129.153.46 
access-list 102 extended permit udp host 128.107.130.212 host 211.129.153.46 eq isakmp 
access-list 102 extended permit esp 64.102.26.128 255.255.255.224 any 
access-list 102 extended permit gre 64.102.26.128 255.255.255.224 any 
access-list 102 extended permit udp 64.102.26.128 255.255.255.224 any eq isakmp 
access-list 102 extended permit udp 64.102.26.128 255.255.255.224 any eq 10000 
access-list 102 extended permit udp 64.102.26.128 255.255.255.224 any eq 2746 
access-list 102 extended permit udp 64.102.26.128 255.255.255.224 any eq 4500 
access-list 102 extended permit tcp 64.102.26.128 255.255.255.224 any eq 4500 
access-list 102 extended permit tcp 64.102.26.128 255.255.255.224 any eq pptp 
access-list 102 extended permit tcp host 64.100.53.240 any eq smtp 
access-list 102 extended permit gre 64.102.26.32 255.255.255.224 any 
access-list 102 extended permit esp 64.102.26.32 255.255.255.224 any 
access-list 102 extended permit udp 64.102.26.32 255.255.255.224 any eq isakmp 
access-list 102 extended permit udp 64.102.26.32 255.255.255.224 any eq 10000 
access-list 102 extended permit udp 64.102.26.32 255.255.255.224 any eq 2746 
access-list 102 extended permit udp 64.102.26.32 255.255.255.224 any eq 4500 
access-list 102 extended permit gre 10.97.0.0 255.255.0.0 host 64.102.240.233 
access-list 102 extended permit esp host 64.104.77.181 host 110.170.20.162 
access-list 102 extended permit udp host 64.104.77.181 host 110.170.20.162 eq isakmp 
access-list 102 extended permit esp host 72.163.247.98 host 115.236.30.155 
access-list 102 extended permit udp host 72.163.247.98 host 115.236.30.155 eq isakmp 
access-list 102 extended permit esp host 64.104.77.181 host 124.155.203.226 
access-list 102 extended permit udp host 64.104.77.181 host 124.155.203.226 eq isakmp 
access-list 102 extended permit esp any 64.100.13.0 255.255.255.0 
access-list 102 extended permit udp any 64.100.13.0 255.255.255.0 eq isakmp 
access-list 102 extended permit udp any 64.100.13.0 255.255.255.0 eq 4500 
access-list 102 extended permit esp any host 64.102.255.129 
access-list 102 extended permit udp any host 64.102.255.129 eq isakmp 
access-list 102 extended permit udp any host 64.102.255.129 eq 4500 
access-list 102 extended permit esp any 64.100.12.0 255.255.255.0 
access-list 102 extended permit udp any 64.100.12.0 255.255.255.0 eq isakmp 
access-list 102 extended permit udp any 64.100.12.0 255.255.255.0 eq 4500 
access-list 102 extended permit udp host 64.102.148.31 host 167.206.7.6 eq isakmp 
access-list 102 extended permit udp host 64.102.148.31 host 74.128.1.100 eq isakmp 
access-list 102 extended permit udp host 64.102.44.39 host 70.151.45.80 eq isakmp 
access-list 102 extended permit udp host 10.76.181.226 64.100.12.0 255.255.255.224 eq isakmp 
access-list 102 extended permit udp host 10.56.21.5 host 144.160.96.132 eq isakmp 
access-list 102 extended permit udp host 10.56.21.5 host 144.160.96.132 eq 4500 
access-list 102 extended permit gre 10.66.0.0 255.254.0.0 host 64.104.252.65 
access-list 102 extended permit gre 10.74.42.0 255.255.255.128 host 64.104.127.65 
access-list 102 extended permit esp host 64.103.35.61 host 86.108.15.21 
access-list 102 extended permit esp host 64.103.35.189 host 86.108.15.21 
access-list 102 extended permit udp host 64.103.35.61 host 86.108.15.21 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 86.108.15.21 eq isakmp 
access-list 102 extended permit esp host 64.103.35.61 host 168.187.152.34 
access-list 102 extended permit udp host 64.103.35.61 host 168.187.152.34 eq isakmp 
access-list 102 extended permit udp host 64.102.57.50 host 205.128.1.35 eq isakmp 
access-list 102 extended permit udp host 64.102.57.50 host 4.36.129.34 eq isakmp 
access-list 102 extended permit udp host 64.102.57.56 host 163.251.239.60 eq 4500 
access-list 102 extended permit udp host 64.102.57.56 host 163.251.208.35 eq 4500 
access-list 102 extended permit udp host 64.102.57.56 host 163.251.239.60 eq isakmp 
access-list 102 extended permit udp host 64.102.57.56 host 163.251.208.35 eq isakmp 
access-list 102 extended permit gre any 128.107.226.192 255.255.255.192 
access-list 102 extended permit udp any 128.107.226.192 255.255.255.192 eq 4500 
access-list 102 extended permit udp any 128.107.226.192 255.255.255.192 eq isakmp 
access-list 102 extended permit gre any 128.107.237.192 255.255.255.192 
access-list 102 extended permit udp any 128.107.237.192 255.255.255.192 eq 4500 
access-list 102 extended permit udp any 128.107.237.192 255.255.255.192 eq isakmp 
access-list 102 extended permit esp any 128.107.250.160 255.255.255.224 
access-list 102 extended permit gre any 128.107.250.160 255.255.255.224 
access-list 102 extended permit udp any 128.107.250.160 255.255.255.224 eq isakmp 
access-list 102 extended permit udp any 128.107.208.0 255.255.240.0 eq isakmp 
access-list 102 extended permit udp any 128.107.64.0 255.255.248.0 eq isakmp 
access-list 102 extended permit udp any 128.107.88.0 255.255.248.0 eq isakmp 
access-list 102 extended permit esp any 128.107.88.0 255.255.248.0 
access-list 102 extended permit udp any host 121.156.51.170 eq 554 
access-list 102 extended permit udp any host 114.31.43.220 eq 554 
access-list 102 extended permit udp host 171.71.3.10 any eq isakmp 
access-list 102 extended permit udp host 171.71.3.14 any eq isakmp 
access-list 102 extended permit udp host 171.71.3.26 any eq isakmp 
access-list 102 extended permit esp host 72.163.247.99 any 
access-list 102 extended permit udp host 72.163.247.99 host 222.128.66.85 eq isakmp 
access-list 102 extended permit udp host 72.163.247.99 host 218.16.64.199 eq isakmp 
access-list 102 extended permit tcp host 64.103.146.65 host 144.230.95.78 eq 500 
access-list 102 extended permit udp host 64.103.146.65 host 144.230.95.78 eq isakmp 
access-list 102 extended permit udp host 64.103.146.65 host 144.230.95.78 eq 10001 
access-list 102 extended permit esp host 64.104.172.43 host 211.141.83.92 
access-list 102 extended permit udp host 64.104.172.43 host 211.141.83.92 eq isakmp 
access-list 102 extended permit udp host 64.104.172.43 host 211.141.83.92 eq 50 
access-list 102 extended permit udp host 64.104.172.43 host 211.141.83.92 eq 10000 
access-list 102 extended permit gre host 10.104.17.4 host 128.107.235.30 
access-list 102 extended permit esp host 10.76.160.21 host 115.248.164.65 
access-list 102 extended permit udp host 10.76.160.21 host 115.248.164.65 eq isakmp 
access-list 102 extended permit udp host 10.76.160.21 host 115.248.164.65 eq 4500 
access-list 102 extended permit gre host 10.104.145.4 host 72.163.216.168 
access-list 102 extended permit gre host 10.77.17.1 host 72.163.216.168 
access-list 102 extended permit gre host 10.78.207.145 host 72.163.216.168 
access-list 102 extended permit gre host 10.66.139.124 host 72.163.216.168 
access-list 102 extended permit esp host 10.78.242.253 host 72.163.216.158 
access-list 102 extended permit ah host 10.78.242.253 host 72.163.216.158 
access-list 102 extended permit udp host 10.78.242.253 host 72.163.216.158 eq isakmp 
access-list 102 extended permit tcp host 10.76.68.36 host 208.90.57.40 eq smtp 
access-list 102 extended permit tcp host 10.76.68.37 host 208.90.57.40 eq smtp 
access-list 102 extended permit tcp host 10.76.68.38 host 208.90.57.40 eq smtp 
access-list 102 extended permit tcp host 10.76.68.39 host 208.90.57.40 eq smtp 
access-list 102 extended permit tcp host 10.76.68.40 host 208.90.57.40 eq smtp 
access-list 102 extended permit tcp host 10.76.68.41 host 208.90.57.40 eq smtp 
access-list 102 extended permit tcp host 10.76.68.42 host 208.90.57.40 eq smtp 
access-list 102 extended permit tcp host 10.76.68.43 host 208.90.57.40 eq smtp 
access-list 102 extended permit tcp host 10.76.68.44 host 208.90.57.40 eq smtp 
access-list 102 extended permit tcp host 10.76.68.125 host 208.90.57.40 eq smtp 
access-list 102 extended permit tcp host 10.76.68.132 host 208.90.57.40 eq smtp 
access-list 102 extended permit tcp host 10.76.68.133 host 208.90.57.40 eq smtp 
access-list 102 extended permit tcp host 10.76.68.151 host 208.90.57.40 eq smtp 
access-list 102 extended permit tcp host 10.76.68.36 host 208.90.57.41 eq smtp 
access-list 102 extended permit tcp host 10.76.68.37 host 208.90.57.41 eq smtp 
access-list 102 extended permit tcp host 10.76.68.38 host 208.90.57.41 eq smtp 
access-list 102 extended permit tcp host 10.76.68.39 host 208.90.57.41 eq smtp 
access-list 102 extended permit tcp host 10.76.68.40 host 208.90.57.41 eq smtp 
access-list 102 extended permit tcp host 10.76.68.41 host 208.90.57.41 eq smtp 
access-list 102 extended permit tcp host 10.76.68.42 host 208.90.57.41 eq smtp 
access-list 102 extended permit tcp host 10.76.68.43 host 208.90.57.41 eq smtp 
access-list 102 extended permit tcp host 10.76.68.44 host 208.90.57.41 eq smtp 
access-list 102 extended permit tcp host 10.76.68.125 host 208.90.57.41 eq smtp 
access-list 102 extended permit tcp host 10.76.68.132 host 208.90.57.41 eq smtp 
access-list 102 extended permit tcp host 10.76.68.133 host 208.90.57.41 eq smtp 
access-list 102 extended permit tcp host 10.76.68.151 host 208.90.57.41 eq smtp 
access-list 102 extended permit esp host 72.163.171.2 any 
access-list 102 extended permit esp host 72.163.171.4 any 
access-list 102 extended permit udp host 10.76.47.34 host 72.163.216.158 eq isakmp 
access-list 102 extended permit esp host 10.76.160.21 host 220.227.79.140 
access-list 102 extended permit udp host 10.76.160.21 host 220.227.79.140 eq isakmp 
access-list 102 extended permit udp host 10.76.160.21 host 220.227.79.140 eq 4500 
access-list 102 extended permit esp host 72.163.130.103 any 
access-list 102 extended permit esp host 72.163.215.43 any 
access-list 102 extended permit esp host 64.104.123.12 any 
access-list 102 extended permit udp host 64.104.123.12 host 222.72.93.88 eq isakmp 
access-list 102 extended permit udp host 64.104.123.12 host 58.211.113.223 eq isakmp 
access-list 102 extended permit udp host 72.163.247.99 host 218.16.64.200 eq isakmp 
access-list 102 extended permit udp any host 64.103.39.112 range 1024 65535 
access-list 102 extended permit udp 144.254.10.160 255.255.255.224 any eq isakmp 
access-list 102 extended permit udp 144.254.10.160 255.255.255.224 any eq 10000 
access-list 102 extended permit udp 144.254.10.160 255.255.255.224 any eq 2746 
access-list 102 extended permit udp 144.254.10.160 255.255.255.224 any eq 4001 
access-list 102 extended permit gre 144.254.10.160 255.255.255.224 any 
access-list 102 extended permit esp 144.254.10.160 255.255.255.224 any 
access-list 102 extended permit ah 144.254.10.160 255.255.255.224 any 
access-list 102 extended permit tcp 144.254.10.160 255.255.255.224 any eq 10000 
access-list 102 extended permit udp 144.254.10.160 255.255.255.224 any eq 4500 
access-list 102 extended permit udp object-group csg-china-networks host 4.71.43.149 eq sip 
access-list 102 extended permit udp object-group csg-china-networks host 4.71.43.150 range 8192 65535 
access-list 102 extended permit gre 64.104.15.198 255.255.255.254 any 
access-list 102 extended deny gre 64.104.15.192 255.255.255.240 any 
access-list 102 extended deny gre host 64.104.15.223 any 
access-list 102 extended permit gre 64.104.15.192 255.255.255.224 any 
access-list 102 extended permit esp 64.104.15.198 255.255.255.254 any 
access-list 102 extended deny esp 64.104.15.192 255.255.255.240 any 
access-list 102 extended deny esp host 64.104.15.223 any 
access-list 102 extended permit esp 64.104.15.192 255.255.255.224 any 
access-list 102 extended permit udp 64.104.15.198 255.255.255.254 any eq isakmp 
access-list 102 extended deny udp 64.104.15.192 255.255.255.240 any eq isakmp 
access-list 102 extended deny udp host 64.104.15.223 any eq isakmp 
access-list 102 extended permit udp 64.104.15.192 255.255.255.224 any eq isakmp 
access-list 102 extended permit udp 64.104.15.198 255.255.255.254 any eq 2746 
access-list 102 extended deny udp 64.104.15.192 255.255.255.240 any eq 2746 
access-list 102 extended deny udp host 64.104.15.223 any eq 2746 
access-list 102 extended permit udp 64.104.15.192 255.255.255.224 any eq 2746 
access-list 102 extended permit udp 64.104.15.198 255.255.255.254 any eq 10000 
access-list 102 extended deny udp 64.104.15.192 255.255.255.240 any eq 10000 
access-list 102 extended deny udp host 64.104.15.223 any eq 10000 
access-list 102 extended permit udp 64.104.15.192 255.255.255.224 any eq 10000 
access-list 102 extended permit tcp 64.104.15.198 255.255.255.254 any eq 4500 
access-list 102 extended deny tcp 64.104.15.192 255.255.255.240 any eq 4500 
access-list 102 extended deny tcp host 64.104.15.223 any eq 4500 
access-list 102 extended permit tcp 64.104.15.192 255.255.255.224 any eq 4500 
access-list 102 extended permit tcp 64.104.15.198 255.255.255.254 any eq pptp 
access-list 102 extended deny tcp 64.104.15.192 255.255.255.240 any eq pptp 
access-list 102 extended deny tcp host 64.104.15.223 any eq pptp 
access-list 102 extended permit tcp 64.104.15.192 255.255.255.224 any eq pptp 
access-list 102 extended permit gre 64.104.200.96 255.255.255.224 any 
access-list 102 extended permit udp 64.104.200.96 255.255.255.224 any eq isakmp 
access-list 102 extended permit udp 64.104.200.96 255.255.255.224 any eq 10000 
access-list 102 extended permit udp 64.104.200.96 255.255.255.224 any eq 2746 
access-list 102 extended permit udp 64.104.200.96 255.255.255.224 any eq 4001 
access-list 102 extended permit esp host 10.66.33.2 host 64.104.252.227 
access-list 102 extended permit udp host 10.66.33.2 host 64.104.252.227 eq isakmp 
access-list 102 extended permit udp host 64.104.235.9 host 202.95.97.78 eq isakmp 
access-list 102 extended permit udp host 64.104.235.9 host 202.95.84.204 eq isakmp 
access-list 102 extended permit udp host 64.104.235.9 host 202.95.97.78 eq 4500 
access-list 102 extended permit udp host 64.104.235.9 host 202.95.84.204 eq 4500 
access-list 102 extended permit esp host 64.104.235.9 host 202.95.97.78 
access-list 102 extended permit esp host 64.104.235.9 host 202.95.84.204 
access-list 102 extended permit udp host 10.66.125.6 host 64.104.252.227 eq isakmp 
access-list 102 extended permit tcp any 199.19.191.64 255.255.255.192 range sip 5061 
access-list 102 extended permit tcp any 199.19.191.64 255.255.255.192 eq h323 
access-list 102 extended permit udp any 199.19.191.64 255.255.255.192 eq 1719 
access-list 102 extended permit udp any 199.19.191.64 255.255.255.192 range 16384 32767 
access-list 102 extended permit udp any host 202.81.18.160 eq 8889 
access-list 102 extended permit udp host 64.104.219.21 host 202.3.193.130 eq isakmp 
access-list 102 extended permit esp host 64.104.213.240 host 165.228.215.186 
access-list 102 extended permit udp host 64.104.213.240 host 165.228.215.186 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 109.73.245.21 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 109.73.245.17 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 109.73.245.17 eq 4500 
access-list 102 extended permit gre host 12.5.186.16 host 128.107.240.24 
access-list 102 extended permit icmp host 12.5.186.16 host 128.107.240.24 echo 
access-list 102 extended permit icmp host 12.5.186.16 host 128.107.240.24 echo-reply 
access-list 102 extended permit gre host 128.107.240.24 host 12.5.186.16 
access-list 102 extended permit icmp host 128.107.240.24 host 12.5.186.16 echo 
access-list 102 extended permit icmp host 128.107.240.24 host 12.5.186.16 echo-reply 
access-list 102 extended permit udp host 173.37.115.19 10.101.164.0 255.255.255.0 eq 902 
access-list 102 extended permit udp 171.71.182.128 255.255.255.192 gt 1023 10.61.46.128 255.255.255.128 gt 1023 
access-list 102 extended permit udp any host 144.254.51.152 range 5246 5247 
access-list 102 extended permit udp any host 144.254.51.153 range 5246 5247 
access-list 102 extended permit udp any host 64.100.13.106 range 5246 5247 
access-list 102 extended permit udp any host 64.100.13.107 range 5246 5247 
access-list 102 extended permit udp any host 64.100.2.3 range 5246 5247 
access-list 102 extended permit udp any host 64.100.2.8 range 5246 5247 
access-list 102 extended permit udp any host 64.100.2.9 range 5246 5247 
access-list 102 extended permit udp any host 64.102.255.229 range 5246 5247 
access-list 102 extended permit udp any host 64.103.27.135 range 5246 5247 
access-list 102 extended permit icmp any host 128.107.227.197 echo-reply 
access-list 102 extended permit icmp host 172.27.204.107 host 128.107.250.227 echo-reply 
access-list 102 extended permit icmp host 172.27.204.107 host 128.107.250.228 echo-reply 
access-list 102 extended permit gre host 10.52.151.25 host 172.17.153.20 
access-list 102 extended permit gre host 10.52.151.26 host 172.17.153.65 
access-list 102 extended permit tcp host 10.63.224.21 host 64.103.38.235 eq 9080 
access-list 102 extended permit udp 173.38.144.0 255.255.254.0 host 64.103.24.40 eq 443 
access-list 102 extended permit gre host 128.107.240.170 host 10.89.255.196 
access-list 102 extended permit gre host 128.107.240.170 host 10.86.230.73 
access-list 102 extended permit gre host 128.107.240.170 host 10.59.15.229 
access-list 102 extended permit gre host 128.107.240.170 host 10.56.72.37 
access-list 102 extended permit gre host 128.107.240.170 host 10.68.1.10 
access-list 102 extended permit gre host 128.107.240.170 host 10.75.225.201 
access-list 102 extended permit gre host 128.107.240.170 host 10.61.32.7 
access-list 102 extended permit gre host 128.107.240.170 host 10.81.255.11 
access-list 102 extended permit gre host 10.75.225.201 host 128.107.240.170 
access-list 102 extended permit gre host 10.68.1.10 host 128.107.240.170 
access-list 102 extended permit icmp host 12.5.186.16 host 128.107.240.170 echo-reply 
access-list 102 extended permit icmp host 12.5.186.16 host 128.107.240.170 echo 
access-list 102 extended permit gre host 12.5.186.16 host 128.107.240.170 
access-list 102 extended permit gre host 10.64.63.16 host 128.107.240.170 
access-list 102 extended permit gre host 10.89.255.196 host 128.107.240.170 
access-list 102 extended permit gre host 10.86.230.73 host 128.107.240.170 
access-list 102 extended permit gre host 10.66.129.17 host 128.107.240.170 
access-list 102 extended permit gre host 10.81.255.11 host 128.107.240.170 
access-list 102 extended permit gre host 10.70.225.102 host 128.107.240.170 
access-list 102 extended permit gre host 10.61.32.7 host 128.107.240.170 
access-list 102 extended permit gre host 10.59.15.229 host 128.107.240.170 
access-list 102 extended permit gre host 10.56.72.37 host 128.107.240.170 
access-list 102 extended permit gre host 128.107.240.170 host 10.64.63.16 
access-list 102 extended permit gre host 128.107.240.170 host 10.75.11.176 
access-list 102 extended permit gre host 128.107.240.170 host 10.70.225.102 
access-list 102 extended permit gre host 128.107.240.170 host 10.66.129.17 
access-list 102 extended permit gre host 10.225.51.65 host 64.104.127.65 
access-list 102 extended permit gre host 10.49.68.11 host 64.103.36.241 
access-list 102 extended permit gre any host 64.102.254.10 
access-list 102 extended permit esp host 64.104.77.181 host 203.107.248.198 
access-list 102 extended permit udp host 64.104.77.181 host 203.107.248.198 eq isakmp 
access-list 102 extended permit udp host 64.104.77.181 host 203.107.248.198 eq 4500 
access-list 102 extended permit gre host 10.49.68.10 host 64.103.36.241 
access-list 102 extended permit udp host 72.163.248.180 range 5246 5247 any 
access-list 102 extended permit udp host 72.163.248.181 range 5246 5247 any 
access-list 102 extended permit gre host 144.254.143.106 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.143.105 host 64.103.36.241 
access-list 102 extended permit udp host 64.104.119.132 eq 5246 any 
access-list 102 extended permit udp host 64.104.119.132 eq 5247 any 
access-list 102 extended permit udp host 64.104.119.133 eq 5246 any 
access-list 102 extended permit udp host 64.104.119.133 eq 5247 any 
access-list 102 extended permit udp host 64.104.119.134 eq 5246 any 
access-list 102 extended permit udp host 64.104.119.134 eq 5247 any 
access-list 102 extended permit gre host 10.141.3.161 host 64.104.44.97 
access-list 102 extended permit esp host 144.254.146.9 host 193.254.166.5 
access-list 102 extended permit gre host 10.76.237.96 host 72.163.216.168 
access-list 102 extended permit gre host 10.75.222.130 host 64.104.127.65 
access-list 102 extended permit gre host 10.75.222.146 host 64.104.127.60 
access-list 102 extended permit gre host 10.75.222.146 host 72.163.249.17 
access-list 102 extended permit udp host 171.70.192.3 any eq isakmp 
access-list 102 extended permit udp host 171.70.192.5 any eq isakmp 
access-list 102 extended permit udp host 171.70.192.6 any eq isakmp 
access-list 102 extended permit udp host 171.70.192.7 any eq isakmp 
access-list 102 extended permit udp host 171.70.192.8 any eq isakmp 
access-list 102 extended permit udp host 128.107.200.65 any eq isakmp 
access-list 102 extended permit udp host 128.107.200.66 any eq isakmp 
access-list 102 extended permit udp host 128.107.200.67 any eq isakmp 
access-list 102 extended permit udp host 128.107.200.68 any eq isakmp 
access-list 102 extended permit udp host 128.107.200.69 any eq isakmp 
access-list 102 extended permit udp host 128.107.200.70 any eq isakmp 
access-list 102 extended permit udp host 128.107.200.75 any eq isakmp 
access-list 102 extended permit udp host 128.107.200.97 any eq isakmp 
access-list 102 extended permit udp host 128.107.200.98 any eq isakmp 
access-list 102 extended permit udp host 128.107.200.98 any eq 848 
access-list 102 extended permit udp host 128.107.200.100 any eq isakmp 
access-list 102 extended permit udp host 128.107.200.100 any eq 848 
access-list 102 extended permit udp host 12.5.186.2 any eq isakmp 
access-list 102 extended permit udp host 12.5.186.3 any eq isakmp 
access-list 102 extended permit udp host 64.102.253.66 any eq isakmp 
access-list 102 extended permit udp host 64.102.253.67 any eq isakmp 
access-list 102 extended permit udp host 12.159.148.23 any eq isakmp 
access-list 102 extended permit udp host 12.159.148.24 any eq isakmp 
access-list 102 extended permit udp host 144.254.220.185 any eq isakmp 
access-list 102 extended permit udp host 144.254.220.186 any eq isakmp 
access-list 102 extended permit udp host 192.118.79.33 any eq isakmp 
access-list 102 extended permit udp host 192.118.79.34 any eq isakmp 
access-list 102 extended permit udp host 64.104.15.225 any eq isakmp 
access-list 102 extended permit udp host 64.104.15.226 any eq isakmp 
access-list 102 extended permit udp host 64.104.229.1 any eq isakmp 
access-list 102 extended permit udp host 64.104.229.2 any eq isakmp 
access-list 102 extended permit udp host 64.104.123.19 any eq isakmp 
access-list 102 extended permit udp host 64.104.123.20 any eq isakmp 
access-list 102 extended permit udp host 64.104.82.1 any eq isakmp 
access-list 102 extended permit udp host 64.104.82.2 any eq isakmp 
access-list 102 extended permit udp host 128.107.200.101 any eq 4500 
access-list 102 extended permit udp host 128.107.200.101 any eq isakmp 
access-list 102 extended permit udp host 64.102.253.73 any eq isakmp 
access-list 102 extended permit udp host 64.102.253.74 any eq isakmp 
access-list 102 extended permit udp host 12.5.186.5 any eq isakmp 
access-list 102 extended permit udp host 12.159.148.27 any eq isakmp 
access-list 102 extended permit udp host 10.35.22.18 host 64.104.94.50 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.22.31 host 64.104.94.50 range snmp snmptrap 
access-list 102 extended permit udp host 171.70.93.61 host 64.104.94.50 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.76 host 64.104.94.50 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.77 host 64.104.94.50 range snmp snmptrap 
access-list 102 extended permit udp host 10.35.48.78 host 64.104.94.50 range snmp snmptrap 
access-list 102 extended permit udp host 172.19.90.141 object-group dmzdc_gw-rtp-1 eq snmp 
access-list 102 extended permit udp host 172.19.90.141 object-group dmzdc_gw-sjc-1 eq snmp 
access-list 102 extended permit udp object-group eam_monitors-global-1 object-group dmz_dns-rch-1 eq snmp 
access-list 102 extended permit udp object-group eam_monitors-global-1 object-group dmz_dns-rch-1 eq 3567 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-bgl-1 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-singapore-1 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-hk-1 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-isr-1 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-japan-1 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-aus-1 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-ams-1 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-rtp-1 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-bxb-1 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-rich-1 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-brnt-1 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-sjc-1 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-vancouver-1 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-rcdn9-1 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-alln-1 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-shanghai-1 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 object-group dmz_networks-aer01-1 eq snmp 
access-list 102 extended deny udp any any eq snmp 
access-list 102 extended deny udp any any eq snmptrap 
access-list 102 extended permit udp host 172.19.61.51 host 172.17.153.37 eq snmp 
access-list 102 extended permit udp host 172.19.61.51 host 172.17.153.7 eq snmp 
access-list 102 extended permit udp host 172.19.61.51 host 172.17.153.8 eq snmp 
access-list 102 extended permit tcp host 171.71.177.236 host 128.107.234.208 eq smtp 
access-list 102 extended permit tcp host 171.71.177.236 host 128.107.234.209 eq smtp 
access-list 102 extended permit esp host 64.104.14.232 host 64.104.14.232 
access-list 102 extended permit udp host 64.104.14.232 host 64.104.14.232 eq isakmp 
access-list 102 extended permit udp host 10.71.150.34 host 64.104.44.33 eq isakmp 
access-list 102 extended permit udp 64.103.182.192 255.255.255.224 host 202.140.146.49 eq isakmp 
access-list 102 extended permit ah 64.103.182.192 255.255.255.224 host 192.8.194.7 
access-list 102 extended permit udp 64.103.182.192 255.255.255.224 host 192.8.194.7 eq isakmp 
access-list 102 extended permit udp 64.103.12.128 255.255.255.240 any eq isakmp 
access-list 102 extended permit udp 64.103.12.128 255.255.255.240 any eq 4500 
access-list 102 extended permit udp 64.103.12.128 255.255.255.240 any eq 10000 
access-list 102 extended permit tcp any 10.81.52.32 255.255.255.224 eq ssh 
access-list 102 extended permit tcp any 10.81.52.32 255.255.255.224 eq 8443 
access-list 102 extended permit udp host 171.71.180.209 10.81.52.32 255.255.255.224 eq snmp 
access-list 102 extended permit udp object-group snmp_managers-global-1 10.81.52.32 255.255.255.224 eq snmp 
access-list 102 extended permit tcp host 171.71.180.209 10.81.52.32 255.255.255.224 eq ftp 
access-list 102 extended permit tcp host 171.71.180.209 10.81.52.32 255.255.255.224 eq ftp-data 
access-list 102 extended permit udp any 10.81.52.32 255.255.255.224 eq domain 
access-list 102 extended permit udp host 64.103.102.75 host 66.160.192.157 eq isakmp 
access-list 102 extended permit udp host 171.69.237.147 any eq isakmp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 any eq 8787 
access-list 102 extended permit gre host 10.68.1.10 host 128.107.240.24 
access-list 102 extended permit gre host 128.107.240.24 host 10.68.1.10 
access-list 102 extended permit tcp 64.102.243.128 255.255.255.128 host 171.70.171.68 eq 1433 
access-list 102 extended permit tcp host 171.70.171.68 64.102.243.128 255.255.255.128 eq 1433 
access-list 102 extended permit udp object-group netqos_servers-global-1 object-group dmz_loopbacks-global-1 range snmp snmptrap 
access-list 102 extended permit object-group ion-services object-group ion-networks any 
access-list 102 extended permit udp host 171.70.89.154 172.17.153.0 255.255.255.0 eq snmp 
access-list 102 extended permit udp host 171.70.89.156 172.17.153.0 255.255.255.0 eq snmp 
access-list 102 extended permit udp host 171.70.89.158 172.17.153.0 255.255.255.0 eq snmp 
access-list 102 extended permit udp host 171.70.89.160 172.17.153.0 255.255.255.0 eq snmp 
access-list 102 extended permit udp host 172.19.90.141 172.17.153.0 255.255.255.0 eq snmp 
access-list 102 extended permit udp 173.37.95.192 255.255.255.192 host 64.102.245.251 eq snmp 
access-list 102 extended permit udp 173.37.95.192 255.255.255.192 host 64.102.245.252 eq snmp 
access-list 102 extended permit udp host 64.104.123.92 host 10.75.225.193 eq snmp 
access-list 102 extended permit udp host 64.104.123.92 host 10.75.225.194 eq snmp 
access-list 102 extended permit udp host 171.70.89.160 host 10.75.225.193 eq snmp 
access-list 102 extended permit udp host 171.70.89.160 host 10.75.225.194 eq snmp 
access-list 102 extended permit esp host 64.103.35.189 host 80.235.29.114 
access-list 102 extended permit udp host 64.103.35.189 host 80.235.29.114 eq isakmp 
access-list 102 extended permit gre host 10.68.178.3 host 64.104.95.129 
access-list 102 extended permit gre host 10.74.237.33 host 64.104.127.65 
access-list 102 extended permit gre host 10.67.40.65 host 64.104.252.65 
access-list 102 extended permit esp host 64.103.35.61 host 46.10.158.34 
access-list 102 extended permit udp host 64.103.35.61 host 46.10.158.34 eq isakmp 
access-list 102 extended permit gre host 10.66.232.81 host 64.104.252.65 
access-list 102 extended permit udp host 64.103.35.61 host 213.172.74.138 eq isakmp 
access-list 102 extended permit gre host 144.254.137.57 host 64.103.36.241 
access-list 102 extended permit udp host 64.103.35.189 host 213.172.74.138 eq isakmp 
access-list 102 extended permit gre host 64.103.36.241 host 144.254.136.249 
access-list 102 extended permit gre host 144.254.136.249 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.142.77 host 64.103.36.241 
access-list 102 extended permit gre host 216.128.59.121 host 64.103.36.241 
access-list 102 extended permit gre host 216.128.59.153 host 64.103.36.241 
access-list 102 extended permit udp host 216.128.60.189 host 80.88.240.250 eq isakmp 
access-list 102 extended permit gre host 216.128.59.81 host 64.103.36.241 
access-list 102 extended permit udp host 64.103.35.61 host 195.239.129.234 eq isakmp 
access-list 102 extended permit esp host 64.104.14.247 host 114.143.5.154 
access-list 102 extended permit udp host 64.104.14.247 host 114.143.5.154 eq isakmp 
access-list 102 extended permit udp host 64.104.14.247 host 114.143.5.154 eq 4500 
access-list 102 extended permit gre host 10.66.139.124 host 64.104.44.97 
access-list 102 extended permit udp host 10.71.150.58 host 64.104.44.33 eq isakmp 
access-list 102 extended permit udp host 193.187.218.34 host 144.254.146.9 eq isakmp 
access-list 102 extended permit udp host 196.219.220.161 host 144.254.146.9 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 62.90.86.5 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 82.213.2.186 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 83.211.160.194 
access-list 102 extended permit udp host 64.103.35.189 host 83.211.160.194 eq isakmp 
access-list 102 extended permit udp host 10.89.29.11 host 128.107.233.36 range 1024 65525 
access-list 102 extended permit tcp host 10.53.192.35 host 64.103.39.179 eq 5222 
access-list 102 extended permit tcp host 10.53.192.35 host 64.103.39.179 eq 5269 
access-list 102 extended permit tcp host 10.53.192.35 host 64.103.39.179 eq 5061 
access-list 102 extended permit tcp host 10.53.192.68 host 64.103.39.180 eq 5443 
access-list 102 extended permit gre host 10.53.41.98 host 10.61.32.15 
access-list 102 extended permit tcp any 10.81.52.32 255.255.255.224 eq ftp-data 
access-list 102 extended permit tcp any 10.81.52.32 255.255.255.224 eq ftp 
access-list 102 extended permit tcp object-group raex_subnets-global-1 object-group dmz_loopbacks-global-1 eq ssh 
access-list 102 extended permit icmp object-group raex_subnets-global-1 object-group dmz_loopbacks-global-1 
access-list 102 extended deny icmp any any echo-reply 
access-list 102 extended permit icmp any any unreachable 
access-list 102 extended deny icmp any any time-exceeded 
access-list 102 extended permit icmp any any 
access-list 102 extended permit esp any any 
access-list 102 extended permit udp host 128.107.200.65 any eq 4500 
access-list 102 extended permit udp host 128.107.200.66 any eq 4500 
access-list 102 extended permit udp host 128.107.200.67 any eq 4500 
access-list 102 extended permit udp host 128.107.200.69 any eq 4500 
access-list 102 extended permit udp host 128.107.200.70 any eq 4500 
access-list 102 extended permit udp host 128.107.200.75 any eq 4500 
access-list 102 extended permit udp host 128.107.200.76 any eq 4500 
access-list 102 extended permit udp host 128.107.200.97 any eq 4500 
access-list 102 extended permit udp host 128.107.200.98 any eq 4500 
access-list 102 extended permit udp host 128.107.200.100 any eq 4500 
access-list 102 extended permit udp host 171.69.100.127 host 192.67.48.74 eq isakmp 
access-list 102 extended permit udp host 171.69.100.127 host 192.67.48.74 eq 42000 
access-list 102 extended permit udp host 171.69.100.127 host 192.67.48.75 eq isakmp 
access-list 102 extended permit udp host 171.69.100.127 host 192.67.48.75 eq 42000 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 128.107.245.0 255.255.255.224 eq isakmp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 128.107.245.0 255.255.255.224 eq 10000 
access-list 102 extended permit udp object-group hp_vendor_vpn_int-sjc-1 object-group hp_vendor_vpn_ext-rtp-1 eq isakmp 
access-list 102 extended permit gre host 171.71.120.50 host 199.249.234.77 
access-list 102 extended permit gre 171.68.245.64 255.255.255.192 any 
access-list 102 extended permit udp 171.68.245.64 255.255.255.192 any eq isakmp 
access-list 102 extended permit udp 171.68.245.64 255.255.255.192 any eq 10000 
access-list 102 extended permit udp 171.68.245.64 255.255.255.192 any eq 2746 
access-list 102 extended permit udp 171.68.245.64 255.255.255.192 any eq 4001 
access-list 102 extended permit udp host 171.70.192.14 any eq isakmp 
access-list 102 extended permit udp host 171.70.192.11 any eq isakmp 
access-list 102 extended permit udp host 64.101.65.47 object-group outbound_vpn-sjc-1 eq isakmp 
access-list 102 extended permit udp host 64.101.65.46 host 64.58.6.235 eq isakmp 
access-list 102 extended permit udp object-group agilent_vpn_int-sjc-1 object-group agilent_vpn_ext-sjc-1 eq isakmp 
access-list 102 extended permit udp host 64.102.148.21 host 167.206.7.6 eq isakmp 
access-list 102 extended permit udp host 64.102.148.21 host 74.128.1.100 eq isakmp 
access-list 102 extended permit udp host 64.103.176.18 host 203.127.177.12 eq 4500 
access-list 102 extended permit udp host 64.103.176.18 host 203.127.177.12 eq 62514 
access-list 102 extended permit udp host 64.103.176.18 host 203.127.177.12 eq isakmp 
access-list 102 extended permit udp host 64.103.176.18 host 203.127.177.12 eq 10000 
access-list 102 extended permit udp host 171.71.3.4 any eq isakmp 
access-list 102 extended permit udp host 171.71.3.6 any eq isakmp 
access-list 102 extended permit udp 128.107.201.244 255.255.255.252 any 
access-list 102 extended permit udp host 128.107.201.248 any 
access-list 102 extended permit udp host 128.107.201.249 any 
access-list 102 extended permit udp host 128.107.201.250 any 
access-list 102 extended permit udp host 128.107.201.251 any 
access-list 102 extended permit udp host 128.107.201.252 any 
access-list 102 extended permit udp host 128.107.201.253 any 
access-list 102 extended permit udp host 10.92.240.158 host 128.107.81.84 eq isakmp 
access-list 102 extended permit udp host 10.92.77.158 host 128.107.81.84 eq isakmp 
access-list 102 extended permit udp 64.101.164.128 255.255.255.192 any eq isakmp 
access-list 102 extended permit udp 64.101.164.128 255.255.255.192 any eq 10000 
access-list 102 extended permit udp 64.101.164.128 255.255.255.192 any eq 4500 
access-list 102 extended permit udp host 64.103.35.189 host 81.211.97.178 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 212.39.82.232 255.255.255.248 eq isakmp 
access-list 102 extended permit esp host 10.76.160.21 host 220.225.32.3 
access-list 102 extended permit udp host 10.76.160.21 host 220.225.32.3 eq isakmp 
access-list 102 extended permit udp host 10.76.160.21 host 220.225.32.3 eq 4500 
access-list 102 extended permit udp host 144.254.146.9 host 160.218.24.2 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 62.84.69.201 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 209.239.68.34 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 213.193.62.61 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 194.247.220.5 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 217.91.36.251 
access-list 102 extended permit udp host 64.103.35.189 host 217.91.36.251 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 212.185.189.202 
access-list 102 extended permit udp host 64.103.35.189 host 212.185.189.202 eq isakmp 
access-list 102 extended permit gre object-group hotspot_bbsm-ams-1 host 64.103.36.241 
access-list 102 extended permit gre object-group hotspot_bbsm-hk-1 host 64.104.127.65 
access-list 102 extended permit gre any host 172.17.153.35 
access-list 102 extended permit gre object-group hotspot_bbsm-sing-1 host 64.104.95.129 
access-list 102 extended permit gre object-group outbound_vpn-global-1 host 64.103.36.241 
access-list 102 extended permit gre host 10.48.101.28 host 64.103.36.241 
access-list 102 extended permit udp host 144.254.146.9 host 195.7.16.53 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 82.213.56.18 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 167.153.128.17 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 83.220.126.243 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 213.86.188.2 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 213.158.201.210 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 149.254.201.110 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 195.43.181.28 eq isakmp 
access-list 102 extended permit tcp host 144.254.210.37 host 64.103.36.6 eq 5443 
access-list 102 extended permit tcp host 144.254.210.37 host 64.103.36.6 eq 9080 
access-list 102 extended permit tcp host 144.254.210.37 host 64.103.36.10 eq 5443 
access-list 102 extended permit tcp host 144.254.210.37 host 64.103.36.10 eq 9080 
access-list 102 extended permit udp object-group vpn_concentrator_asa-bxb-1 any eq isakmp 
access-list 102 extended permit udp host 198.135.0.177 any eq isakmp 
access-list 102 extended permit udp host 198.135.0.180 any eq isakmp 
access-list 102 extended permit udp host 198.135.0.181 any eq isakmp 
access-list 102 extended permit gre host 64.103.35.189 host 41.250.250.139 
access-list 102 extended permit udp host 216.128.60.189 host 85.154.235.170 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 89.218.61.6 
access-list 102 extended permit udp host 64.103.35.189 host 89.218.61.6 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 91.212.94.99 
access-list 102 extended permit esp host 64.103.35.61 host 91.212.94.99 
access-list 102 extended permit udp host 64.103.35.189 host 91.212.94.99 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 91.212.94.99 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 91.212.94.99 eq 4500 
access-list 102 extended permit udp host 64.103.35.61 host 91.212.94.99 eq 4500 
access-list 102 extended permit udp host 144.254.146.9 host 193.113.127.101 eq isakmp 
access-list 102 extended permit gre 10.92.0.0 255.252.0.0 host 128.107.235.30 
access-list 102 extended permit gre 172.24.18.0 255.255.254.0 host 128.107.235.30 
access-list 102 extended permit gre 10.88.0.0 255.254.0.0 host 128.107.235.30 
access-list 102 extended permit gre 192.168.165.0 255.255.255.0 host 128.107.235.30 
access-list 102 extended permit gre 171.71.64.0 255.255.255.128 host 128.107.235.30 
access-list 102 extended permit udp host 72.163.198.202 any range 5246 5247 
access-list 102 extended permit gre 10.101.128.0 255.255.224.0 host 128.107.235.30 
access-list 102 extended permit gre host 10.49.68.6 host 64.103.36.241 
access-list 102 extended permit gre host 10.49.68.14 host 64.103.36.241 
access-list 102 extended permit gre host 10.77.116.113 host 128.107.235.30 
access-list 102 extended permit gre 10.200.46.0 255.255.255.240 host 128.107.235.30 
access-list 102 extended permit gre host 172.17.153.20 host 10.101.206.45 
access-list 102 extended permit gre host 128.107.240.170 host 10.101.206.46 
access-list 102 extended permit gre host 10.123.20.67 host 172.17.153.20 
access-list 102 extended permit gre host 10.123.20.68 host 128.107.240.170 
access-list 102 extended permit gre host 172.17.153.20 host 10.123.20.67 
access-list 102 extended permit gre host 128.107.240.170 host 10.123.20.68 
access-list 102 extended permit gre host 10.66.129.144 host 172.17.153.20 
access-list 102 extended permit gre host 10.66.129.144 host 128.107.240.170 
access-list 102 extended permit gre host 10.75.225.201 host 128.107.240.24 
access-list 102 extended permit gre host 128.107.240.24 host 10.75.225.201 
access-list 102 extended permit gre host 10.75.11.176 host 172.17.153.20 
access-list 102 extended permit gre host 10.75.11.176 host 172.17.153.65 
access-list 102 extended permit gre host 172.17.153.20 host 10.75.11.176 
access-list 102 extended permit gre host 172.17.153.65 host 10.75.11.176 
access-list 102 extended permit udp host 72.163.248.204 any eq isakmp 
access-list 102 extended permit udp host 72.163.248.205 any eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 158.190.198.16 eq isakmp 
access-list 102 extended permit gre host 172.17.153.20 host 10.86.234.13 
access-list 102 extended permit gre host 128.107.239.78 host 10.86.234.13 
access-list 102 extended permit gre 10.70.0.0 255.254.0.0 host 64.104.47.236 
access-list 102 extended permit gre 10.70.0.0 255.254.0.0 host 64.104.44.97 
access-list 102 extended permit gre 10.80.0.0 255.240.0.0 host 64.102.240.233 
access-list 102 extended permit gre 10.96.0.0 255.255.0.0 host 64.102.240.233 
access-list 102 extended permit udp object-group vpn_tac_support-global-1 any eq isakmp 
access-list 102 extended permit udp object-group hp_vendor_vpn_int-rtp-1 object-group hp_vendor_vpn_ext-rtp-1 eq isakmp 
access-list 102 extended permit udp host 209.82.96.210 any eq isakmp 
access-list 102 extended permit udp host 209.82.96.210 any eq 10000 
access-list 102 extended permit udp host 12.159.148.18 any eq isakmp 
access-list 102 extended permit udp host 12.159.148.18 any eq 10000 
access-list 102 extended permit udp host 12.159.148.19 any eq isakmp 
access-list 102 extended permit udp host 12.159.148.19 any eq 10000 
access-list 102 extended permit udp host 12.159.148.20 any eq isakmp 
access-list 102 extended permit udp host 12.159.148.20 any eq 10000 
access-list 102 extended permit udp host 12.159.148.21 any eq isakmp 
access-list 102 extended permit udp host 12.159.148.21 any eq 10000 
access-list 102 extended permit udp host 12.159.148.22 any eq isakmp 
access-list 102 extended permit udp host 12.159.148.24 any eq 4500 
access-list 102 extended permit udp host 12.159.148.23 any eq 4500 
access-list 102 extended permit udp any host 198.135.0.108 eq isakmp 
access-list 102 extended permit udp any 198.135.3.128 255.255.255.128 eq snmp 
access-list 102 extended permit esp host 64.104.123.9 host 124.160.35.210 
access-list 102 extended permit udp host 64.104.123.9 host 124.160.35.210 eq isakmp 
access-list 102 extended permit udp host 64.104.208.64 any eq isakmp 
access-list 102 extended permit udp host 64.104.208.65 any eq isakmp 
access-list 102 extended permit udp host 64.104.208.64 any eq 1701 
access-list 102 extended permit udp host 64.104.208.65 any eq 1701 
access-list 102 extended permit udp host 64.104.208.64 any eq 1723 
access-list 102 extended permit udp host 64.104.208.65 any eq 1723 
access-list 102 extended permit udp host 64.104.208.64 any eq 4500 
access-list 102 extended permit udp host 64.104.208.65 any eq 4500 
access-list 102 extended permit udp host 64.103.69.6 host 194.221.37.50 eq isakmp 
access-list 102 extended permit udp host 64.103.69.6 host 194.221.37.50 eq 4500 
access-list 102 extended permit udp host 64.103.69.6 host 194.221.37.50 eq 10000 
access-list 102 extended permit tcp host 64.103.69.6 host 194.221.37.50 eq 10000 
access-list 102 extended permit udp host 64.103.69.7 host 194.221.37.50 eq isakmp 
access-list 102 extended permit udp host 64.103.69.7 host 194.221.37.50 eq 4500 
access-list 102 extended permit udp host 64.103.69.7 host 194.221.37.50 eq 10000 
access-list 102 extended permit tcp host 64.103.69.7 host 194.221.37.50 eq 10000 
access-list 102 extended permit udp host 64.103.69.8 host 194.221.37.50 eq isakmp 
access-list 102 extended permit udp host 64.103.69.8 host 194.221.37.50 eq 4500 
access-list 102 extended permit udp host 64.103.69.8 host 194.221.37.50 eq 10000 
access-list 102 extended permit tcp host 64.103.69.8 host 194.221.37.50 eq 10000 
access-list 102 extended permit udp host 64.103.69.9 host 194.221.37.50 eq isakmp 
access-list 102 extended permit udp host 64.103.69.9 host 194.221.37.50 eq 4500 
access-list 102 extended permit udp host 64.103.69.9 host 194.221.37.50 eq 10000 
access-list 102 extended permit tcp host 64.103.69.9 host 194.221.37.50 eq 10000 
access-list 102 extended permit udp host 64.103.69.8 host 195.89.28.178 eq isakmp 
access-list 102 extended permit udp host 64.103.69.8 host 195.89.28.178 eq 4500 
access-list 102 extended permit udp host 64.103.69.8 host 195.89.28.178 eq 10000 
access-list 102 extended permit tcp host 64.103.69.8 host 195.89.28.178 eq 10000 
access-list 102 extended permit udp host 64.103.69.9 host 195.89.28.178 eq isakmp 
access-list 102 extended permit udp host 64.103.69.9 host 195.89.28.178 eq 4500 
access-list 102 extended permit udp host 64.103.69.9 host 195.89.28.178 eq 10000 
access-list 102 extended permit tcp host 64.103.69.9 host 195.89.28.178 eq 10000 
access-list 102 extended permit gre host 10.49.68.7 host 64.103.36.241 
access-list 102 extended permit udp 173.39.168.0 255.255.248.0 host 202.96.97.240 range 1701 1704 
access-list 102 extended permit udp 10.224.160.0 255.255.224.0 host 202.96.97.240 range 1701 1704 
access-list 102 extended permit udp host 64.104.226.20 host 202.12.242.87 eq isakmp 
access-list 102 extended permit udp host 64.104.226.20 host 202.12.239.87 eq isakmp 
access-list 102 extended permit udp host 64.104.226.20 host 202.12.242.87 eq 5500 
access-list 102 extended permit udp host 64.104.226.20 host 202.12.239.87 eq 5500 
access-list 102 extended permit ah host 64.104.226.20 host 202.12.242.87 
access-list 102 extended permit ah host 64.104.226.20 host 202.12.239.87 
access-list 102 extended permit udp 12.46.104.0 255.255.254.0 host 64.102.255.44 eq domain 
access-list 102 extended permit tcp 12.46.104.0 255.255.254.0 host 64.102.255.44 eq domain 
access-list 102 extended permit udp 12.46.104.0 255.255.254.0 host 128.107.241.185 eq domain 
access-list 102 extended permit tcp 12.46.104.0 255.255.254.0 host 128.107.241.185 eq domain 
access-list 102 extended permit udp host 64.102.14.19 object-group sciatl_dmz_bcp-sciatl-1 eq domain 
access-list 102 extended permit tcp host 64.102.14.14 host 64.102.245.52 eq smtp 
access-list 102 extended permit tcp host 64.102.14.14 host 64.102.245.52 eq 587 
access-list 102 extended permit esp host 64.104.14.248 host 123.220.247.193 
access-list 102 extended permit udp host 64.104.14.248 host 123.220.247.193 eq isakmp 
access-list 102 extended permit esp host 64.104.14.248 host 61.112.161.131 
access-list 102 extended permit udp host 64.104.14.248 host 61.112.161.131 eq isakmp 
access-list 102 extended permit esp host 64.104.14.248 host 61.126.132.31 
access-list 102 extended permit udp host 64.104.14.248 host 61.126.132.31 eq isakmp 
access-list 102 extended permit udp host 64.104.8.21 host 211.129.153.46 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 196.192.9.243 eq isakmp 
access-list 102 extended permit esp host 64.104.77.181 host 122.52.239.153 
access-list 102 extended permit udp host 64.104.77.181 host 122.52.239.153 eq isakmp 
access-list 102 extended permit udp host 64.104.77.181 host 122.52.239.153 eq 4500 
access-list 102 extended permit object-group VCSC-TO-VCSE object-group sj_alpha_vcs_control object-group sj_alpha_vcs_express 
access-list 102 extended permit udp host 10.35.126.29 host 128.107.85.182 object-group webex_as_lab_onetouch_destination_ports 
access-list 102 extended permit udp host 10.35.126.29 host 128.107.85.189 object-group webex_as_lab_onetouch_destination_ports 
access-list 102 extended permit udp host 10.35.63.134 object-group sj_alpha_vcs_express eq 902 
access-list 102 extended permit udp host 10.35.63.114 object-group sj_alpha_vcs_express eq 902 
access-list 102 extended permit gre host 10.68.192.3 host 64.104.95.129 
access-list 102 extended permit gre host 10.78.10.67 host 10.64.63.16 
access-list 102 extended permit esp host 64.104.213.241 host 122.56.107.13 
access-list 102 extended permit udp host 64.104.213.241 host 122.56.107.13 eq isakmp 
access-list 102 extended permit udp host 64.104.213.241 host 122.56.107.13 eq 4500 
access-list 102 extended permit esp host 64.104.213.241 host 203.174.180.249 
access-list 102 extended permit udp host 64.104.213.241 host 203.174.180.249 eq isakmp 
access-list 102 extended permit udp host 64.104.213.241 host 203.174.180.249 eq 4500 
access-list 102 extended permit udp host 171.71.120.50 host 199.249.234.77 eq isakmp 
access-list 102 extended permit udp any host 64.102.254.10 eq isakmp 
access-list 102 extended permit udp host 10.83.117.66 host 64.102.254.10 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 212.82.216.58 
access-list 102 extended permit udp host 64.103.35.189 host 212.82.216.58 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 212.82.216.58 eq 4500 
access-list 102 extended permit gre 173.36.138.128 255.255.255.128 any 
access-list 102 extended permit udp 173.36.138.128 255.255.255.128 any eq isakmp 
access-list 102 extended permit udp 173.36.138.128 255.255.255.128 any eq 4500 
access-list 102 extended permit tcp 173.36.138.128 255.255.255.128 any eq 4500 
access-list 102 extended permit udp 173.36.138.128 255.255.255.128 any eq 2746 
access-list 102 extended permit tcp 173.36.138.128 255.255.255.128 any eq 10000 
access-list 102 extended permit udp 173.36.138.128 255.255.255.128 any eq 10000 
access-list 102 extended permit tcp 173.36.138.128 255.255.255.128 any eq pptp 
access-list 102 extended permit udp any host 173.36.203.18 range 9000 9001 
access-list 102 extended permit udp any host 173.36.203.225 range 9000 9001 
access-list 102 extended permit udp host 64.104.14.232 host 221.245.226.74 eq isakmp 
access-list 102 extended permit udp host 64.104.14.233 host 221.245.226.74 eq isakmp 
access-list 102 extended permit udp host 64.104.14.232 host 61.118.247.199 eq isakmp 
access-list 102 extended permit udp host 64.104.14.233 host 61.118.247.199 eq isakmp 
access-list 102 extended permit udp host 64.104.14.247 host 222.158.224.241 eq isakmp 
access-list 102 extended permit udp host 64.104.14.248 host 222.158.224.241 eq isakmp 
access-list 102 extended permit udp host 64.104.14.247 host 122.1.1.19 eq isakmp 
access-list 102 extended permit udp host 64.104.14.248 host 122.1.1.19 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 80.84.98.41 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 83.234.244.114 eq isakmp 
access-list 102 extended permit udp host 144.254.146.18 host 217.41.21.46 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 80.84.98.41 eq 4500 
access-list 102 extended permit udp host 64.103.35.189 host 61.5.145.186 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 41.220.72.58 
access-list 102 extended permit udp host 64.103.35.189 host 41.220.72.58 eq isakmp 
access-list 102 extended permit esp host 64.104.14.232 host 180.43.108.113 
access-list 102 extended permit esp host 64.104.14.233 host 180.43.108.113 
access-list 102 extended permit udp host 64.104.14.232 host 180.43.108.113 eq isakmp 
access-list 102 extended permit udp host 64.104.14.233 host 180.43.108.113 eq isakmp 
access-list 102 extended permit esp host 72.163.247.99 host 121.15.168.73 
access-list 102 extended permit udp host 72.163.247.99 host 121.15.168.73 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 217.66.233.130 eq isakmp 
access-list 102 extended permit gre host 10.68.160.65 host 64.104.95.129 
access-list 102 extended permit esp host 64.104.77.181 host 222.127.10.155 
access-list 102 extended permit udp host 64.104.77.181 host 222.127.10.155 eq isakmp 
access-list 102 extended permit udp host 64.104.77.181 host 222.127.10.155 eq 4500 
access-list 102 extended permit esp host 64.104.14.247 host 180.43.28.206 
access-list 102 extended permit udp host 64.104.14.247 host 180.43.28.206 eq isakmp 
access-list 102 extended permit esp host 64.104.14.248 host 180.43.28.206 
access-list 102 extended permit udp host 64.104.14.248 host 180.43.28.206 eq isakmp 
access-list 102 extended permit esp host 72.163.247.99 host 116.228.21.214 
access-list 102 extended permit udp host 72.163.247.99 host 116.228.21.214 eq isakmp 
access-list 102 extended permit udp host 72.163.247.99 host 116.228.21.214 eq 4500 
access-list 102 extended permit udp host 10.58.46.50 host 64.103.36.18 eq isakmp 
access-list 102 extended permit udp host 64.104.14.232 object-group japan_site2site_vpn_backup-tokyo-1 eq isakmp 
access-list 102 extended permit udp host 64.104.14.233 object-group japan_site2site_vpn_backup-tokyo-1 eq isakmp 
access-list 102 extended permit udp host 171.71.238.13 217.17.227.200 255.255.255.248 eq isakmp 
access-list 102 extended permit gre host 171.71.238.13 217.17.227.200 255.255.255.248 
access-list 102 extended permit udp host 171.71.238.13 193.188.125.80 255.255.255.252 eq isakmp 
access-list 102 extended permit gre host 171.71.238.13 193.188.125.80 255.255.255.252 
access-list 102 extended permit udp host 64.102.252.253 217.17.227.200 255.255.255.248 eq isakmp 
access-list 102 extended permit gre host 64.102.252.253 217.17.227.200 255.255.255.248 
access-list 102 extended permit udp host 64.102.252.253 193.188.125.80 255.255.255.252 eq isakmp 
access-list 102 extended permit gre host 64.102.252.253 193.188.125.80 255.255.255.252 
access-list 102 extended permit esp host 64.104.14.248 host 211.122.197.174 
access-list 102 extended permit udp host 64.104.14.248 host 211.122.197.174 eq isakmp 
access-list 102 extended permit esp host 64.104.213.242 host 165.228.215.186 
access-list 102 extended permit udp host 64.104.213.242 host 165.228.215.186 eq isakmp 
access-list 102 extended permit esp host 72.163.247.99 host 219.143.103.141 
access-list 102 extended permit udp host 72.163.247.99 host 219.143.103.141 eq isakmp 
access-list 102 extended permit esp host 72.163.247.99 host 219.143.103.142 
access-list 102 extended permit udp host 72.163.247.99 host 219.143.103.142 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 196.203.143.26 
access-list 102 extended permit udp host 64.103.35.189 host 196.203.143.26 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 193.95.99.218 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 213.123.25.242 eq isakmp 
access-list 102 extended permit tcp host 64.102.125.5 host 192.135.250.12 eq 13782 
access-list 102 extended permit tcp host 64.102.125.6 host 192.135.250.12 eq 13782 
access-list 102 extended permit tcp host 64.102.120.12 host 192.135.250.12 eq 13782 
access-list 102 extended permit udp host 64.103.35.61 host 212.123.18.140 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 213.206.37.58 eq isakmp 
access-list 102 extended permit gre host 10.53.41.2 host 64.103.36.241 
access-list 102 extended permit gre host 10.67.45.129 host 64.104.252.65 
access-list 102 extended permit gre host 10.75.32.3 host 64.104.127.65 
access-list 102 extended permit gre host 10.75.10.145 host 64.104.127.65 
access-list 102 extended permit tcp host 172.26.172.170 host 64.102.240.9 eq 5443 
access-list 102 extended permit tcp host 172.26.172.170 host 64.102.240.9 eq 9080 
access-list 102 extended permit gre host 144.254.141.217 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.131.105 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.140.217 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.130.217 host 64.103.36.241 
access-list 102 extended permit esp host 64.103.35.61 host 196.213.110.234 
access-list 102 extended permit udp host 64.103.35.61 host 196.213.110.234 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 145.248.195.33 eq isakmp 
access-list 102 extended permit udp any host 67.148.157.189 eq isakmp 
access-list 102 extended permit esp any host 67.148.157.189 
access-list 102 extended permit udp any host 67.148.157.189 eq 4500 
access-list 102 extended permit udp any host 67.148.157.190 eq isakmp 
access-list 102 extended permit esp any host 67.148.157.190 
access-list 102 extended permit udp any host 67.148.157.190 eq 4500 
access-list 102 extended permit udp any 64.103.27.64 255.255.255.192 eq 4172 
access-list 102 extended permit udp any 64.100.13.0 255.255.255.0 eq 4172 
access-list 102 extended permit udp host 144.254.146.9 host 196.219.213.129 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 196.219.213.129 eq 4500 
access-list 102 extended permit udp host 64.102.57.50 host 216.81.81.71 eq isakmp 
access-list 102 extended permit esp host 64.102.57.50 host 216.81.81.71 
access-list 102 extended permit udp host 64.102.57.50 host 216.81.81.71 eq 4500 
access-list 102 extended permit udp host 144.254.146.9 host 159.50.102.14 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 145.50.39.68 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 217.174.43.4 eq isakmp 
access-list 102 extended permit udp host 64.103.52.34 host 194.0.215.36 range 2776 2777 
access-list 102 extended permit udp host 64.103.52.35 host 194.0.215.36 range 2776 2777 
access-list 102 extended permit udp object-group Internal_TandbergVCS-rtp-1 object-group DMZ_TandbergVCE-rtp-1 eq 2776 
access-list 102 extended permit udp object-group Internal_TandbergVCS-rtp-1 object-group DMZ_TandbergVCE-rtp-1 eq 2777 
access-list 102 extended permit udp object-group Internal_TandbergVCS-rtp-1 object-group DMZ_TandbergVCE-rtp-1 eq 6001 
access-list 102 extended permit udp object-group Internal_TandbergVCS-rtp-1 object-group DMZ_TandbergVCE-rtp-1 eq 7001 
access-list 102 extended permit tcp object-group Internal_TandbergVCS-rtp-1 object-group DMZ_TandbergVCE-rtp-1 eq 2776 
access-list 102 extended permit tcp object-group Internal_TandbergVCS-rtp-1 object-group DMZ_TandbergVCE-rtp-1 eq 7001 
access-list 102 extended permit udp object-group TAA_TandbergVCS_Oslo object-group DMZ_TandbergVCE-ams-1 eq 2776 
access-list 102 extended permit udp object-group TAA_TandbergVCS_Oslo object-group DMZ_TandbergVCE-ams-1 eq 2777 
access-list 102 extended permit udp object-group TAA_TandbergVCS_Oslo object-group DMZ_TandbergVCE-ams-1 eq 6002 
access-list 102 extended permit udp object-group TAA_TandbergVCS_Oslo object-group DMZ_TandbergVCE-ams-1 eq 7002 
access-list 102 extended permit tcp object-group TAA_TandbergVCS_Oslo object-group DMZ_TandbergVCE-ams-1 eq 2776 
access-list 102 extended permit tcp object-group TAA_TandbergVCS_Oslo object-group DMZ_TandbergVCE-ams-1 eq 7002 
access-list 102 extended permit udp object-group TAA_TandbergVCS_Oslo object-group DMZ_TandbergVCE-rtp-1 eq 2776 
access-list 102 extended permit udp object-group TAA_TandbergVCS_Oslo object-group DMZ_TandbergVCE-rtp-1 eq 2777 
access-list 102 extended permit udp object-group TAA_TandbergVCS_Oslo object-group DMZ_TandbergVCE-rtp-1 eq 6011 
access-list 102 extended permit udp object-group TAA_TandbergVCS_Oslo object-group DMZ_TandbergVCE-rtp-1 eq 7011 
access-list 102 extended permit tcp object-group TAA_TandbergVCS_Oslo object-group DMZ_TandbergVCE-rtp-1 eq 2776 
access-list 102 extended permit tcp object-group TAA_TandbergVCS_Oslo object-group DMZ_TandbergVCE-rtp-1 eq 7011 
access-list 102 extended permit udp object-group uc_cucm_subscribers-sjc-1 object-group uc_verizon_sip_trunk-sjc-1 range 16384 32767 
access-list 102 extended permit tcp host 64.100.209.212 object-group DMZ_TandbergVCE-rtp-1 eq 2776 
access-list 102 extended permit tcp host 64.100.209.213 object-group DMZ_TandbergVCE-rtp-1 eq 2776 
access-list 102 extended permit tcp host 64.100.209.214 object-group DMZ_TandbergVCE-rtp-1 eq 2776 
access-list 102 extended permit tcp host 64.100.209.212 object-group DMZ_TandbergVCE-rtp-1 eq 2777 
access-list 102 extended permit tcp host 64.100.209.213 object-group DMZ_TandbergVCE-rtp-1 eq 2777 
access-list 102 extended permit tcp host 64.100.209.214 object-group DMZ_TandbergVCE-rtp-1 eq 2777 
access-list 102 extended permit tcp host 64.100.209.212 object-group DMZ_TandbergVCE-rtp-1 eq 6003 
access-list 102 extended permit tcp host 64.100.209.213 object-group DMZ_TandbergVCE-rtp-1 eq 6003 
access-list 102 extended permit tcp host 64.100.209.214 object-group DMZ_TandbergVCE-rtp-1 eq 6003 
access-list 102 extended permit tcp host 64.100.209.212 object-group DMZ_TandbergVCE-rtp-1 eq 7003 
access-list 102 extended permit tcp host 64.100.209.213 object-group DMZ_TandbergVCE-rtp-1 eq 7003 
access-list 102 extended permit tcp host 64.100.209.214 object-group DMZ_TandbergVCE-rtp-1 eq 7003 
access-list 102 extended permit udp object-group Internal_TandbergVCS-syd-1 object-group DMZ_TandbergVCE-syd-1 eq 2776 
access-list 102 extended permit udp object-group Internal_TandbergVCS-syd-1 object-group DMZ_TandbergVCE-syd-1 eq 2777 
access-list 102 extended permit udp object-group Internal_TandbergVCS-syd-1 object-group DMZ_TandbergVCE-syd-1 eq 6001 
access-list 102 extended permit udp object-group Internal_TandbergVCS-syd-1 object-group DMZ_TandbergVCE-syd-1 eq 7001 
access-list 102 extended permit tcp object-group Internal_TandbergVCS-syd-1 object-group DMZ_TandbergVCE-syd-1 eq 2776 
access-list 102 extended permit tcp object-group Internal_TandbergVCS-syd-1 object-group DMZ_TandbergVCE-syd-1 eq 7001 
access-list 102 extended permit udp host 10.54.64.10 host 144.254.51.2 range 2776 2777 
access-list 102 extended permit udp host 64.102.252.36 eq 5246 any 
access-list 102 extended permit udp host 64.102.252.36 eq 5247 any 
access-list 102 extended permit udp host 64.102.252.37 eq 5246 any 
access-list 102 extended permit udp host 64.102.252.37 eq 5247 any 
access-list 102 extended permit udp object-group Internal_TandbergVCS-sjc-1 object-group DMZ_TandbergVCE-sjc-1 eq 2776 
access-list 102 extended permit udp object-group Internal_TandbergVCS-sjc-1 object-group DMZ_TandbergVCE-sjc-1 eq 2777 
access-list 102 extended permit udp object-group Internal_TandbergVCS-sjc-1 object-group DMZ_TandbergVCE-sjc-1 eq 6001 
access-list 102 extended permit udp object-group Internal_TandbergVCS-sjc-1 object-group DMZ_TandbergVCE-sjc-1 eq 7001 
access-list 102 extended permit tcp object-group Internal_TandbergVCS-sjc-1 object-group DMZ_TandbergVCE-sjc-1 eq 2776 
access-list 102 extended permit tcp object-group Internal_TandbergVCS-sjc-1 object-group DMZ_TandbergVCE-sjc-1 eq 7001 
access-list 102 extended permit gre host 10.105.40.161 host 72.163.216.168 
access-list 102 extended permit gre host 10.75.225.30 host 64.104.127.65 
access-list 102 extended permit udp object-group Internal_TandbergVCS-ams-1 object-group DMZ_TandbergVCE-ams-1 eq 2776 
access-list 102 extended permit udp object-group Internal_TandbergVCS-ams-1 object-group DMZ_TandbergVCE-ams-1 eq 2777 
access-list 102 extended permit udp object-group Internal_TandbergVCS-ams-1 object-group DMZ_TandbergVCE-ams-1 eq 6001 
access-list 102 extended permit udp object-group Internal_TandbergVCS-ams-1 object-group DMZ_TandbergVCE-ams-1 eq 7001 
access-list 102 extended permit tcp object-group Internal_TandbergVCS-ams-1 object-group DMZ_TandbergVCE-ams-1 eq 2776 
access-list 102 extended permit tcp object-group Internal_TandbergVCS-ams-1 object-group DMZ_TandbergVCE-ams-1 eq 7001 
access-list 102 extended permit gre host 10.142.16.241 host 72.163.216.168 
access-list 102 extended permit gre host 10.225.35.65 host 64.104.127.65 
access-list 102 extended permit esp host 64.103.35.61 host 194.0.215.146 
access-list 102 extended permit esp host 64.103.35.189 host 194.0.215.146 
access-list 102 extended permit udp host 64.103.35.61 host 194.0.215.146 eq isakmp 
access-list 102 extended permit udp host 64.103.35.189 host 194.0.215.146 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 65.91.116.19 eq isakmp 
access-list 102 extended permit udp host 144.254.146.9 host 174.141.208.11 eq isakmp 
access-list 102 extended permit gre host 216.128.59.57 host 64.103.36.241 
access-list 102 extended permit gre host 216.128.58.217 host 64.103.36.241 
access-list 102 extended permit gre host 144.254.132.249 host 64.103.36.241 
access-list 102 extended deny udp any any eq sunrpc 
access-list 102 extended deny udp any any eq nfs 
access-list 102 extended deny udp any any eq 4045 
access-list 102 extended permit tcp any host 144.254.51.85 range 6006 6007 
access-list 102 extended permit tcp any host 144.254.51.85 eq 7007 
access-list 102 extended permit tcp any host 144.254.51.86 range 6006 6007 
access-list 102 extended permit tcp any host 144.254.51.86 eq 7007 
access-list 102 extended deny tcp any any range 6000 6063 
access-list 102 extended deny tcp any any eq 2000 
access-list 102 extended deny tcp any any eq ident 
access-list 102 extended deny tcp any any eq bgp 
access-list 102 extended permit udp any any eq 7648 
access-list 102 extended permit udp any any eq 7649 
access-list 102 extended deny udp any any eq xdmcp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 object-group dmz_networks-singapore-1 eq tftp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 object-group dmz_networks-bgl-1 eq tftp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 object-group dmz_networks-hk-1 eq tftp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 object-group dmz_networks-isr-1 eq tftp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 object-group dmz_networks-japan-1 eq tftp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 object-group dmz_networks-aus-1 eq tftp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 object-group dmz_networks-rtp-1 eq tftp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 object-group dmz_networks-bxb-1 eq tftp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 object-group dmz_networks-rich-1 eq tftp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 object-group dmz_networks-brnt-1 eq tftp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 object-group dmz_networks-sjc-1 eq tftp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 object-group dmz_networks-vancouver-1 eq tftp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 object-group dmz_networks-rcdn9-1 eq tftp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 object-group dmz_networks-alln-1 eq tftp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 object-group dmz_networks-shanghai-1 eq tftp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 object-group dmz_networks-aer01-1 eq tftp 
access-list 102 extended permit udp object-group cisco_internal_networks-global-1 any eq domain 
access-list 102 extended deny tcp any any eq smtp 
access-list 102 extended permit tcp object-group cisco_internal_networks-global-1 any 
access-list 102 extended permit tcp 10.54.64.0 255.255.224.0 host 206.16.253.237 eq sip 
access-list 102 extended permit tcp 10.54.64.0 255.255.224.0 host 206.16.253.237 eq 5061 
access-list 102 extended permit tcp 10.54.64.0 255.255.224.0 host 199.101.250.13 eq sip 
access-list 102 extended permit tcp 10.54.64.0 255.255.224.0 host 199.101.250.13 eq 5061 
access-list 102 extended permit udp 10.54.64.0 255.255.224.0 host 144.254.51.2 eq 3478 
access-list 102 extended permit udp host 64.104.240.22 range 5246 5247 any 
access-list 102 extended permit udp host 64.104.240.23 range 5246 5247 any 
access-list 102 extended permit gre host 10.75.86.96 host 64.104.127.65 
access-list 102 extended permit gre host 10.75.86.97 host 64.104.127.65 
access-list 102 extended permit tcp object-group webex-cn-hosts-InterCall-access host 75.78.52.36 eq 5061 
access-list 102 extended permit udp object-group webex-cn-hosts-InterCall-access host 75.78.52.36 eq 5061 
access-list 102 extended permit udp object-group webex-cn-hosts-InterCall-access host 75.78.52.37 gt 1023 
access-list 102 extended permit udp host 171.70.192.182 eq 5246 any 
access-list 102 extended permit udp host 171.70.192.182 eq 5247 any 
access-list 102 extended permit udp host 171.70.192.183 eq 5246 any 
access-list 102 extended permit udp host 171.70.192.183 eq 5247 any 
access-list 102 extended permit udp host 171.70.192.184 eq 5246 any 
access-list 102 extended permit udp host 171.70.192.184 eq 5247 any 
access-list 102 extended permit udp host 171.70.192.185 eq 5246 any 
access-list 102 extended permit udp host 171.70.192.185 eq 5247 any 
access-list 102 extended permit udp host 171.70.192.186 eq 5246 any 
access-list 102 extended permit udp host 171.70.192.186 eq 5247 any 
access-list 102 extended permit udp any host 216.136.156.75 eq 12000 
access-list 102 extended permit udp any 59.151.13.0 255.255.255.0 eq 9000 
access-list 102 extended permit udp any 59.151.14.0 255.255.255.0 eq 9000 
access-list 102 extended permit udp any 59.151.107.0 255.255.255.0 eq 9000 
access-list 102 extended permit udp object-group sj_alpha_vcs_control object-group sj_alpha_vcs_express eq 902 
access-list 102 extended permit udp 10.35.204.0 255.255.255.0 128.107.87.0 255.255.255.0 eq sip 
access-list 102 extended permit udp 10.35.204.0 255.255.255.0 128.107.87.0 255.255.255.0 range 4000 65000 
access-list 102 extended permit udp 10.35.204.0 255.255.255.0 128.107.231.0 255.255.255.0 eq sip 
access-list 102 extended permit udp 10.35.204.0 255.255.255.0 128.107.231.0 255.255.255.0 range 4000 65000 
access-list 102 extended permit tcp 10.35.204.0 255.255.255.0 128.107.87.0 255.255.255.0 eq sip 
access-list 102 extended permit tcp 10.35.204.0 255.255.255.0 128.107.231.0 255.255.255.0 eq sip 
access-list 102 extended permit icmp 10.35.204.0 255.255.255.0 128.107.87.0 255.255.255.0 
access-list 102 extended permit icmp 10.35.204.0 255.255.255.0 128.107.231.0 255.255.255.0 
access-list 102 extended permit udp any host 128.107.82.106 eq 6006 
access-list 102 extended permit tcp any host 128.107.82.106 eq 2776 
access-list 102 extended permit tcp any host 128.107.82.106 eq 5061 
access-list 102 extended permit udp any host 128.107.82.106 eq 1719 
access-list 102 extended permit udp any host 128.107.82.106 eq 2776 
access-list 102 extended permit udp any host 128.107.82.106 eq 2777 
access-list 102 extended permit udp any host 128.107.82.106 range 50000 52399 
access-list 102 extended permit udp any host 128.107.82.106 
access-list 102 extended permit tcp any object-group sng_ace_vcse eq 2776 
access-list 102 extended permit tcp any object-group sng_ace_vcse eq 5061 
access-list 102 extended permit udp any object-group sng_ace_vcse eq 2776 
access-list 102 extended permit udp any object-group sng_ace_vcse eq 2777 
access-list 102 extended permit udp any object-group sng_ace_vcse eq 6001 
access-list 102 extended permit udp any object-group sng_ace_vcse eq 1719 
access-list 102 extended permit udp any object-group sng_ace_vcse range 50000 52399 
access-list 102 extended permit gre host 10.147.100.129 host 64.103.36.241 
access-list 102 extended permit gre host 10.49.68.12 host 64.103.36.241 
access-list 102 extended permit udp host 64.103.35.61 host 93.109.251.86 eq isakmp 
access-list 102 extended permit esp host 144.254.220.189 any 
access-list 102 extended permit udp host 144.254.220.189 any eq isakmp 
access-list 102 extended permit esp host 72.163.247.99 host 58.210.240.126 
access-list 102 extended permit udp host 72.163.247.99 host 58.210.240.126 eq isakmp 
access-list 102 extended permit esp host 64.104.123.9 host 121.171.235.34 
access-list 102 extended permit udp host 64.104.123.9 host 121.171.235.34 eq isakmp 
access-list 102 extended permit udp host 64.104.123.9 host 121.171.235.34 eq 4500 
access-list 102 extended permit udp host 64.103.35.61 host 41.206.22.34 eq isakmp 
access-list 102 extended permit esp host 64.104.88.231 host 120.28.34.166 
access-list 102 extended permit udp host 64.104.88.231 host 120.28.34.166 eq isakmp 
access-list 102 extended permit esp host 66.187.209.105 host 173.36.116.10 
access-list 102 extended permit udp host 66.187.209.105 host 173.36.116.10 eq isakmp 
access-list 102 extended permit udp host 66.187.209.105 host 173.36.116.10 eq 4500 
access-list 102 extended permit gre host 10.105.77.33 host 72.163.216.168 
access-list 102 extended permit gre host 10.64.55.79 host 72.163.216.168 
access-list 102 extended permit gre host 10.70.218.225 host 64.104.44.97 
access-list 102 extended permit gre host 10.49.68.16 host 64.103.36.241 
access-list 102 extended permit gre host 10.105.159.1 host 72.163.216.168 
access-list 102 extended permit gre host 10.68.137.1 host 64.104.95.129 
access-list 102 extended permit udp host 64.104.77.181 host 61.47.104.214 eq isakmp 
access-list 102 extended permit gre host 10.143.14.160 host 72.163.216.168 
access-list 102 extended permit tcp host 171.68.106.20 any eq 2000 
access-list 102 extended permit tcp host 171.68.106.20 any eq 2443 
access-list 102 extended permit tcp host 171.68.106.20 any eq sip 
access-list 102 extended permit tcp host 171.68.106.20 any eq 5061 
access-list 102 extended permit tcp host 171.68.106.20 any eq 3804 
access-list 102 extended permit udp host 171.68.106.20 any eq tftp 
access-list 102 extended permit tcp host 171.68.106.21 any eq 2000 
access-list 102 extended permit tcp host 171.68.106.21 any eq 2443 
access-list 102 extended permit tcp host 171.68.106.21 any eq sip 
access-list 102 extended permit tcp host 171.68.106.21 any eq 5061 
access-list 102 extended permit tcp host 171.68.106.21 any eq 3804 
access-list 102 extended permit udp host 171.68.106.21 any eq tftp 
access-list 102 extended permit udp host 171.68.106.22 any range 16384 32767 
access-list 102 extended permit gre host 10.64.47.164 host 72.163.216.168 
access-list 102 extended permit gre host 10.49.68.4 host 64.103.36.241 
access-list 102 extended permit udp 10.47.0.0 255.255.224.0 173.38.154.224 255.255.255.240 eq 902 
access-list 102 extended permit udp any host 72.163.251.208 eq sip 
access-list 102 extended permit udp any host 72.163.251.209 eq sip 
access-list 102 extended permit udp any host 72.163.251.210 eq sip 
access-list 102 extended permit udp any host 72.163.251.208 eq 5070 
access-list 102 extended permit udp any host 72.163.251.209 eq 5070 
access-list 102 extended permit udp any host 72.163.251.210 eq 5070 
access-list 102 extended permit udp any host 72.163.251.208 range 50000 52900 
access-list 102 extended permit udp any host 72.163.251.209 range 50000 52900 
access-list 102 extended permit udp any host 72.163.251.210 range 50000 52900 
access-list 102 extended permit udp any host 72.163.251.208 
access-list 102 extended permit udp any host 72.163.251.209 
access-list 102 extended permit udp any host 72.163.251.210 
access-list 102 extended permit gre host 10.79.90.160 host 64.104.127.65 
access-list 102 extended deny ip any object-group cisco_internal_networks-global-1 
access-list 102 extended permit udp host 72.163.247.99 host 222.62.77.124 eq isakmp 
access-list 102 extended permit esp host 64.104.83.33 host 61.91.245.114 
access-list 102 extended permit udp host 64.104.83.33 host 61.91.245.114 eq isakmp 
access-list 102 extended permit esp host 64.104.83.33 host 120.28.34.166 
access-list 102 extended permit udp host 64.104.83.33 host 120.28.34.166 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 213.168.31.106 
access-list 102 extended permit udp host 64.103.35.189 host 213.168.31.106 eq isakmp 
access-list 102 extended permit esp host 64.103.35.189 host 195.200.190.106 
access-list 102 extended permit udp host 64.103.35.189 host 195.200.190.106 eq isakmp 
access-list 102 extended permit gre host 144.254.141.25 host 64.103.36.241 
access-list 102 extended permit gre host 10.49.68.24 host 64.103.36.241 
access-list 102 extended permit gre host 10.49.68.27 host 64.103.36.241 
access-list 102 extended permit gre host 10.49.68.26 host 64.103.36.241 
access-list 102 extended permit gre host 10.74.249.65 host 64.104.127.65 
access-list 102 extended permit udp host 171.71.238.13 host 198.32.107.15 eq isakmp 
access-list 102 extended permit udp host 64.102.252.253 host 198.32.107.15 eq isakmp 
access-list 102 extended permit udp 10.50.176.0 255.255.240.0 144.254.51.80 255.255.255.240 eq 6001 
access-list 102 extended permit udp 10.50.176.0 255.255.240.0 144.254.51.80 255.255.255.240 eq 1719 
access-list 102 extended permit udp 10.50.176.0 255.255.240.0 144.254.51.80 255.255.255.240 eq 5050 
access-list 102 extended permit udp 10.50.176.0 255.255.240.0 144.254.51.80 255.255.255.240 eq 2776 
access-list 102 extended permit udp 10.50.176.0 255.255.240.0 144.254.51.80 255.255.255.240 eq 2777 
access-list 102 extended permit udp 10.50.176.0 255.255.240.0 144.254.51.80 255.255.255.240 range 52399 54999 
access-list 102 extended permit udp any host 173.38.154.55 eq 1719 
access-list 102 extended permit udp any host 173.38.154.55 eq 6001 
access-list 102 extended permit udp any host 173.38.154.55 eq 7002 
access-list 102 extended permit udp any host 173.38.154.55 range 4000 65000 
access-list 102 extended permit esp host 64.104.77.181 host 175.139.202.54 
access-list 102 extended permit udp host 64.104.77.181 host 175.139.202.54 eq isakmp 
access-list 102 extended permit udp host 64.104.77.181 host 175.139.202.54 eq 4500 
access-list 102 extended permit gre host 64.104.155.146 host 119.151.96.2 
access-list 102 extended permit esp host 64.104.155.146 host 119.151.96.2 
access-list 102 extended permit udp host 64.104.155.146 host 119.151.96.2 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 80.188.11.74 eq isakmp 
access-list 102 extended permit esp host 64.100.45.169 host 74.217.3.61 
access-list 102 extended permit udp host 64.100.45.169 host 74.217.3.61 eq isakmp 
access-list 102 extended permit udp host 10.101.54.100 any eq 443 
access-list 102 extended permit udp host 10.123.64.93 any eq 443 
access-list 102 extended permit udp host 171.69.7.162 host 50.20.130.93 eq isakmp 
access-list 102 extended permit esp host 171.69.7.162 host 50.20.130.93 
access-list 102 extended permit udp host 171.69.7.162 host 50.20.130.93 eq 4500 
access-list 102 extended permit udp host 171.69.7.185 host 50.20.130.93 eq isakmp 
access-list 102 extended permit esp host 171.69.7.185 host 50.20.130.93 
access-list 102 extended permit udp host 171.69.7.185 host 50.20.130.93 eq 4500 
access-list 102 extended permit udp host 171.71.238.29 host 64.127.109.94 eq isakmp 
access-list 102 extended permit esp host 171.71.238.29 host 64.127.109.94 
access-list 102 extended permit udp host 171.71.238.29 host 64.127.109.94 eq 4500 
access-list 102 extended permit udp host 171.69.7.185 host 64.127.109.94 eq isakmp 
access-list 102 extended permit esp host 171.69.7.185 host 64.127.109.94 
access-list 102 extended permit udp host 171.69.7.185 host 64.127.109.94 eq 4500 
access-list 102 extended permit esp host 64.103.35.189 host 197.254.42.34 
access-list 102 extended permit udp host 64.103.35.189 host 197.254.42.34 eq isakmp 
access-list 102 extended permit esp host 72.163.247.98 host 124.128.225.99 
access-list 102 extended permit udp host 72.163.247.98 host 124.128.225.99 eq isakmp 
access-list 102 extended permit gre host 10.72.33.108 host 64.104.127.65 
access-list 102 extended permit gre host 10.79.89.226 host 64.104.127.65 
access-list 102 extended permit gre host 10.143.28.68 host 72.163.216.168 
access-list 102 extended permit esp host 171.70.203.162 host 184.94.240.210 
access-list 102 extended permit esp host 171.70.203.162 host 184.94.240.211 
access-list 102 extended permit udp host 171.70.203.162 host 184.94.240.210 eq isakmp 
access-list 102 extended permit udp host 171.70.203.162 host 184.94.240.211 eq isakmp 
access-list 102 extended permit udp host 171.71.238.13 host 68.166.109.210 eq isakmp 
access-list 102 extended permit esp host 171.71.238.13 host 68.166.109.210 
access-list 102 extended permit udp host 64.102.252.253 host 68.166.109.210 eq isakmp 
access-list 102 extended permit esp host 64.102.252.253 host 68.166.109.210 
access-list 102 extended permit udp host 192.118.79.52 eq 5246 any 
access-list 102 extended permit udp host 192.118.79.52 eq 5247 any 
access-list 102 extended permit udp host 192.118.79.53 eq 5246 any 
access-list 102 extended permit udp host 192.118.79.53 eq 5247 any 
access-list 102 extended permit udp host 64.103.35.61 host 84.205.102.23 eq isakmp 
access-list 102 extended permit udp host 64.103.35.61 host 84.205.102.23 eq 4500 
access-list 102 extended permit esp host 64.103.35.189 host 221.120.194.254 
access-list 102 extended permit udp host 64.103.35.189 host 221.120.194.254 eq isakmp 
access-list 102 extended permit esp host 64.103.35.61 host 221.120.194.254 
access-list 102 extended permit udp host 64.103.35.61 host 221.120.194.254 eq isakmp 
access-list 102 extended permit esp host 72.163.247.98 host 112.95.169.62 
access-list 102 extended permit udp host 72.163.247.98 host 112.95.169.62 eq isakmp 
access-list 102 extended permit esp host 72.163.247.98 host 58.240.229.98 
access-list 102 extended permit udp host 72.163.247.98 host 58.240.229.98 eq isakmp 
access-list 102 extended permit udp object-group kumo_product_labs-1 object-group amazon_ec2_us-east-1 range 6644 6646 
access-list 102 extended permit udp object-group kumo_product_labs-1 object-group amazon_ec2_us-west-1 range 6644 6646 
access-list 102 extended permit udp object-group kumo_product_labs-1 object-group amazon_ec2_apac-1 range 6644 6646 
access-list 102 extended permit udp object-group kumo_product_labs-1 host 204.246.160.140 range 6644 6646 
access-list 102 extended permit udp object-group kumo_product_labs-1 host 205.251.242.7 range 6644 6646 
access-list 102 extended permit udp object-group kumo_product_labs-1 host 72.21.215.33 range 6644 6646 
access-list 102 extended permit udp object-group kumo_product_labs-1 host 207.171.162.181 range 6644 6646 
access-list 102 extended permit udp object-group kumo_product_labs-1 object-group microsoft_azure_South_Central_US range 6644 6646 
access-list 102 extended permit udp object-group kumo_product_labs-1 object-group microsoft_azure_North_Central_US range 6644 6646 
access-list 102 extended permit udp object-group kumo_product_labs-1 object-group microsoft_azure_East_US range 6644 6646 
access-list 102 extended permit udp object-group kumo_product_labs-1 object-group microsoft_azure_West_US range 6644 6646 
access-list 102 extended permit udp any 173.36.216.0 255.255.255.0 eq 902 
access-list 102 extended permit udp any 173.36.217.0 255.255.255.128 eq 902 
access-list 102 extended permit udp host 64.103.35.61 host 196.192.9.242 eq isakmp 
access-list 102 extended permit gre any host 64.102.242.226 
access-list 102 extended permit udp any host 64.102.242.226 eq isakmp 
access-list 102 extended permit udp host 10.35.48.55 host 173.36.192.20 eq 902 
access-list 102 extended permit udp host 10.35.48.55 host 173.36.192.29 eq 902 
access-list 102 extended permit udp host 10.35.48.75 host 173.36.192.20 eq snmp 
access-list 102 extended permit udp host 10.35.48.75 host 173.36.192.29 eq snmp 
access-list 102 extended permit udp host 10.35.48.76 host 173.36.192.20 eq snmp 
access-list 102 extended permit udp host 10.35.48.76 host 173.36.192.29 eq snmp 
access-list 102 extended permit udp host 10.35.48.77 host 173.36.192.20 eq snmp 
access-list 102 extended permit udp host 10.35.48.77 host 173.36.192.29 eq snmp 
access-list 102 extended permit udp host 10.35.48.78 host 173.36.192.20 eq snmp 
access-list 102 extended permit udp host 10.35.48.78 host 173.36.192.29 eq snmp 
access-list 102 extended permit udp host 10.42.4.76 host 173.36.192.20 eq snmp 
access-list 102 extended permit udp host 10.42.4.76 host 173.36.192.29 eq snmp 
access-list 102 extended permit udp host 172.18.136.210 host 64.100.8.211 range 2776 2777 
access-list 102 extended permit udp any eq 1719 host 128.107.85.164 eq 6001 
access-list 102 extended permit udp any range 15000 15999 host 128.107.85.164 eq 2776 
access-list 102 extended permit udp any range 50000 54999 host 128.107.85.164 eq 2776 
access-list 102 extended permit udp any range 50000 54999 host 128.107.85.164 eq 2777 
access-list 102 extended permit udp host 172.19.236.172 host 128.107.85.164 eq 6006 
access-list 102 extended permit udp host 172.19.236.172 host 128.107.85.164 eq 1719 
access-list 102 extended permit udp host 172.19.236.172 host 128.107.85.164 range 50000 52399 
access-list 102 extended permit udp host 172.27.201.152 host 128.107.85.164 eq 6006 
access-list 102 extended permit udp host 172.27.201.152 host 128.107.85.164 eq 1719 
access-list 102 extended permit udp host 172.27.201.152 host 128.107.85.164 range 50000 52399 
access-list 102 extended permit udp object-group UCLAB319_OT2-VCSC-1_2 object-group DMZ_VCE-RTP-105_106 eq 2776 
access-list 102 extended permit tcp object-group UCLAB319_OT2-VCSC-1_2 object-group DMZ_VCE-RTP-105_106 eq 2776 
access-list 102 extended permit udp object-group UCLAB319_OT2-VCSC-1_2 object-group DMZ_VCE-RTP-105_106 eq 2777 
access-list 102 extended permit tcp object-group UCLAB319_OT2-VCSC-1_2 object-group DMZ_VCE-RTP-105_106 eq 2777 
access-list 102 extended permit udp object-group UCLAB319_OT2-VCSC-1_2 object-group DMZ_VCE-RTP-105_106 eq 6001 
access-list 102 extended permit tcp object-group UCLAB319_OT2-VCSC-1_2 object-group DMZ_VCE-RTP-105_106 eq 7001 
access-list 102 extended permit udp object-group UCLAB319_OT2-VCSC-1_2 object-group DMZ_VCE-RTP-105_106 range 50000 54999 
access-list 102 extended permit udp host 161.44.82.186 any object-group xboxlive_services_udp 
access-list 102 extended deny udp any any 
access-list 102 extended deny ip any any 
