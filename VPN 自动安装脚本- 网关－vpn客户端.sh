#!/bin/bash
#changelog
function set_ntp(){
	setenforce 0
	sed -i "s/SELINUX=enforcing/SELINUX=disabled/g" /etc/selinux/config
	yum -y install ntp
	service ntpd restart
	cp -rf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	cd /root
	echo '0-59/10 * * * * /usr/sbin/ntpdate -u cn.pool.ntp.org' >> /tmp/crontab.back
	crontab /tmp/crontab.back
	systemctl restart crond
}
function set_network(){
yum install rp-pppoe -y
pppoe-setup
yum install dhcp
echo '' > /etc/dhcp/dhcpd.conf
cat >>  /etc/dhcp/dhcpd.conf <<EOF
# dhcpd.conf
option domain-name "example.org";
log-facility local7;
subnet 192.168.10.0 netmask 255.255.255.0 {
  range 192.168.10.100 192.168.10.200;
  option domain-name-servers 8.8.8.8,8.8.4.4;
  option routers 192.168.10.1;
  option broadcast-address 192.168.10.255;
  default-lease-time 600;
  max-lease-time 7200;
}
host fantasia {
  hardware ethernet 08:00:07:26:c0:a5;
  fixed-address 192.168.10.103;
}
EOF
}

function set_strongswan6(){
	systemctl stop firewalld
	systemctl disable firewalld
	yum -y install epel-release
	yum -y install openssl-devel
    yum -y install strongswan strongswan-libipsec
echo '' > /etc/strongswan/ipsec.conf
cat >>  /etc/strongswan/ipsec.conf <<EOF
config setup
    uniqueids=never
conn centos
  keyexchange=ikev2
  ike=aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
  esp=aes256-sha256,aes256-sha1,3des-sha1!
  left=%any
  leftid=192.168.0.1
  leftsubnet=0.0.0.0/0
  leftsourceip=%any
  authby=secret
  right=2.2.2.2
  rightid=2.2.2.2
  rightsubnet=31.13.0.0/16,45.64.40.0/22,64.18.0.0/20,64.63.0.0/18,64.68.90.0/24,64.233.0.0/16,66.102.0.0/20,66.220.0.0/16,66.249.0.0/20,67.228.0.0/16,69.63.0.0/16,69.171.0.0/16,69.195.0.0/16,72.14.192.0/18,74.119.76.0/22,74.125.0.0/16,74.173.0.0/16,103.4.96.0/22,103.252.0.0/16,104.244.0.0/16,108.177.0.0/16,129.134.0.0/16,157.240.0.0/16,172.217.0.0/16,173.194.0.0/16,173.252.64.0/18,179.60.192.0/22,185.45.0.0/23,185.60.216.0/22,188.64.0.0/16,192.44.69.0/24,192.133.76.0/22,199.16.156.0/22,199.59.148.0/22,199.96.0.0/16,199.223.0.0/16,202.160.0.0/16,204.15.20.0/22,207.126.144.0/20,207.223.0.0/16,208.65.0.0/16,208.117.0.0/16,209.85.128.0/17,209.237.0.0/16,216.58.0.0/16,216.239.0.0/16,8.8.8.8/32,8.8.4.4/32
  #rightsubnet=0.0.0.0/0    #访问服务器的哪个网络
  type=tunnel
  auto=add
EOF
cat >>  /etc/strongswan/ipsec.secrets <<EOF
: PSK fastvpn #预设密钥,与服务器端保持一致
EOF
}
function set_iptables10(){
	echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
	sysctl -p
	yum -y install iptables-services
	systemctl start iptables.service
	chmod +x /etc/rc.local
cat >>  /etc/rc.local <<EOF
systemctl start strongswan
iptables -F
iptables -t nat -F
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 1723 -j ACCEPT
iptables -A INPUT -p gre -j ACCEPT
iptables -A INPUT -p udp -m policy --dir in --pol ipsec -m udp --dport 1701 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 1701 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 4500 -j ACCEPT
iptables -A INPUT -p esp -j ACCEPT
iptables -A INPUT -m policy --dir in --pol ipsec -j ACCEPT
iptables -A INPUT -j DROP
iptables -A FORWARD -i ppp+ -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
sleep 3
#使路由器可以访问本地
ip rule add from 192.168.10.0/24 table main prio 1
#启动连接
strongswan up centos
sleep 3
#增加本地其他网段到 table 220 中
ip rule add from 192.168.10.0/24 table 220
#地址转换
iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o ipsec0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o ppp+ -j MASQUERADE
EOF
}
function shell_install() {
	echo "初始化时间"
	set_ntp
	echo '安装配置strongswan'
	set_strongswan6
	echo "安装l2tp"
	echo '配置iptables'
	set_iptables10
	echo '配置daloradius'
}
shell_install
