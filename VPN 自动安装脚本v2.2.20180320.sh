#!/bin/bash
function set_ntp(){
	setenforce 0
	sed -i "s/SELINUX=enforcing/SELINUX=disabled/g" /etc/selinux/config
	yum -y install ntp
	service ntpd restart
	cp -rf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	cd /root
	crontab -l > /tmp/crontab.back
	echo '0-59/10 * * * * /usr/sbin/ntpdate -u cn.pool.ntp.org' >> /tmp/crontab.back
	crontab /tmp/crontab.back
	systemctl restart crond
}
#初始化密码设置
function set_shell_input1() {
	clear	
	sqladmin=0p0o0i0900
	read -p "请输入VPN外网IP地址！(默认为192.168.0.1):" public_ip
	if [ -z "$public_ip" ];then
	public_ip=192.168.0.1
	fi
	read -p "请输strongswan VPN 预共享密钥(默认为abc123):" ike_passwd
	if [ -z "$ike_passwd" ];then
	ike_passwd=abc123
	fi
}
function set_install_pro2(){
	alias cp='cp'
	yum groupinstall "Development tools" -y
	yum install wget vim expect telnet net-tools httpd mariadb-server php php-mysql php-gd php-ldap php-odbc php-pear php-xml php-xmlrpc php-mbstring php-snmp php-soap curl curl-devel -y
	yum install freeradius freeradius-mysql freeradius-utils -y
	systemctl restart mariadb
	systemctl restart httpd
	systemctl stop firewalld
	systemctl disable firewalld
}
#配置radius数据库并导入数据
function set_mysql3() {
	systemctl restart mariadb
	sleep 3
	mysqladmin -u root password ""${sqladmin}""
	mysql -uroot -p${sqladmin} -e "create database radius;"
	mysql -uroot -p${sqladmin} -e "grant all privileges on radius.* to radius@localhost identified by 'p0radius_0p';"
	mysql -uradius -p'p0radius_0p' radius < /etc/raddb/mods-config/sql/main/mysql/schema.sql  
	systemctl restart mariadb
}

function set_freeradius4(){
	ln -s /etc/raddb/mods-available/sql /etc/raddb/mods-enabled/
	sed -i "s/auth = no/auth = yes/g" /etc/raddb/radiusd.conf
	sed -i "s/auth_badpass = no/auth_badpass = yes/g" /etc/raddb/radiusd.conf
	sed -i "s/auth_goodpass = no/auth_goodpass = yes/g" /etc/raddb/radiusd.conf
	sed -i "s/\-sql/sql/g" /etc/raddb/sites-available/default
	#在查找到的session {字符串后面插入内容
	sed -i '/session {/a\        sql' /etc/raddb/sites-available/default
	sed -i 's/driver = "rlm_sql_null"/driver = "rlm_sql_mysql"/g' /etc/raddb/mods-available/sql	
	#查找到字符串，去掉首字母为的注释#
	sed -i '/read_clients = yes/s/^#//' /etc/raddb/mods-available/sql
	sed -i '/dialect = "sqlite"/s/^#//' /etc/raddb/mods-available/sql
	sed -i 's/dialect = "sqlite"/dialect = "mysql"/g' /etc/raddb/mods-available/sql	
	sed -i '/server = "localhost"/s/^#//' /etc/raddb/mods-available/sql
	sed -i '/port = 3306/s/^#//' /etc/raddb/mods-available/sql
	sed -i '/login = "radius"/s/^#//' /etc/raddb/mods-available/sql
	sed -i '/password = "radpass"/s/^#//' /etc/raddb/mods-available/sql
	sed -i 's/password = "radpass"/password = "p0radius_0p"/g' /etc/raddb/mods-available/sql	
	systemctl restart radiusd
	sleep 3
}
function set_daloradius5(){
	cd /var/www/html/
	wget http://www.beijinghuayu.com.cn/down/daloradius-0.9-9.tar.gz >/dev/null 2>&1
	tar xzvf daloradius-0.9-9.tar.gz
	mv daloradius-0.9-9 daloradius
	chown -R apache:apache /var/www/html/daloradius/
	chmod 664 /var/www/html/daloradius/library/daloradius.conf.php
	cd /var/www/html/daloradius/
	mysql -uradius -p'p0radius_0p' radius < contrib/db/fr2-mysql-daloradius-and-freeradius.sql
	mysql -uradius -p'p0radius_0p' radius < contrib/db/mysql-daloradius.sql
	sleep 3
	sed -i "s/\['CONFIG_DB_USER'\] = 'root'/\['CONFIG_DB_USER'\] = 'radius'/g"  /var/www/html/daloradius/library/daloradius.conf.php
	sed -i "s/\['CONFIG_DB_PASS'\] = ''/\['CONFIG_DB_PASS'\] = 'p0radius_0p'/g" /var/www/html/daloradius/library/daloradius.conf.php
	yum -y install epel-release
	yum -y install php-pear-DB
	systemctl restart mariadb.service 
	systemctl restart radiusd.service
	systemctl restart httpd
	chmod 644 /var/log/messages
	chmod 755 /var/log/radius/
	chmod 644 /var/log/radius/radius.log
	touch /tmp/daloradius.log
	chmod 644 /tmp/daloradius.log
	chown -R apache:apache /tmp/daloradius.log
}

function set_strongswan6(){
	yum -y install pam-devel openssl-devel make gcc curl
	cd /root/
	wget http://www.beijinghuayu.com.cn/down/strongswan-5.5.3.tar.gz
	tar xzvf strongswan-5.5.3.tar.gz 
	cd strongswan-5.5.3
	./configure  --sysconfdir=/etc --enable-eap-identity --enable-eap-md5 --enable-eap-mschapv2 --enable-eap-tls --enable-eap-ttls --enable-eap-peap  --enable-eap-tnc --enable-eap-dynamic --enable-eap-radius --enable-xauth-eap  --enable-xauth-pam  --enable-dhcp  --enable-openssl  --enable-addrblock --enable-unity  --enable-certexpire --enable-radattr --enable-swanctl --enable-openssl --disable-gmp
	make && make install
	cd /root/
	touch zhengshu.sh 
cat >> /root/zhengshu.sh <<EOF
ipsec pki --gen --outform pem > ca.key.pem
ipsec pki --self --in ca.key.pem --dn "C=CN, O=Huayu, CN=Huayu CA" --ca --lifetime 3650 --outform pem > ca.cert.pem
ipsec pki --gen --outform pem > server.key.pem
ipsec pki --pub --in server.key.pem --outform pem > server.pub.pem
ipsec pki --issue --lifetime 1200 --cacert ca.cert.pem --cakey ca.key.pem --in server.pub.pem --dn "C=CN, O=Huayu, CN=$public_ip" --san="$public_ip" --flag serverAuth --flag ikeIntermediate --outform pem > server.cert.pem
ipsec pki --gen --outform pem > client.key.pem
ipsec pki --pub --in client.key.pem --outform pem > client.pub.pem
ipsec pki --issue --lifetime 1200 --cacert ca.cert.pem --cakey ca.key.pem --in client.pub.pem --dn "C=CN, O=Huayu, CN=$public_ip" --outform pem > client.cert.pem
openssl pkcs12 -export -inkey client.key.pem -in client.cert.pem -name "Huayu Client Cert" -certfile ca.cert.pem -caname "Huayu CA" -out client.cert.p12 -password pass:
cp -r ca.key.pem /etc/ipsec.d/private/
cp -r ca.cert.pem /etc/ipsec.d/cacerts/
cp -r server.cert.pem /etc/ipsec.d/certs/
cp -r server.key.pem /etc/ipsec.d/private/
cp -r client.cert.pem /etc/ipsec.d/certs/
cp -r client.key.pem /etc/ipsec.d/private/
cat ca.cert.pem >> /etc/raddb/certs/ca.pem
cat server.cert.pem >> /etc/raddb/certs/server.pem
cat server.key.pem >> /etc/raddb/certs/server.key
cat /etc/raddb/certs/server.key >> /etc/raddb/certs/server.pem
EOF
chmod +x /root/zhengshu.sh
/root/zhengshu.sh
echo '' > /etc/ipsec.conf
cat >>  /etc/ipsec.conf <<EOF
config setup
    uniqueids=never              #允许多个客户端使用同一个证书
#所有项目共用的配置项
conn %default
    keyexchange=ike              #ikev1 或 ikev2 都用这个
    left=%any                    #服务器端标识,%any表示任意
    leftsubnet=0.0.0.0/0         #服务器端虚拟ip, 0.0.0.0/0表示通配.
    right=%any                   #客户端标识,%any表示任意
 
conn IKE-BASE
    leftca=ca.cert.pem           #服务器端 CA 证书
    leftcert=server.cert.pem     #服务器端证书
    rightsourceip=10.0.0.0/24    #分配给客户端的虚拟 ip 段，格式为：单个IP或1.1.1.1-1.1.1.5或1.1.1.0/24
 
#供 ios 使用, 使用客户端证书
conn IPSec-IKEv1
    also=IKE-BASE
    keyexchange=ikev1
    fragmentation=yes            #开启对 iOS 拆包的重组支持
    leftauth=pubkey
    rightauth=pubkey
    rightauth2=xauth-radius  #使用radius
    rightcert=client.cert.pem
    auto=add
 
#供 ios 使用, 使用 PSK 预设密钥
conn IPSec-IKEv1-PSK
    also=IKE-BASE
    keyexchange=ikev1
    fragmentation=yes
    leftauth=psk
    rightauth=psk
    rightauth2=xauth-radius #使用radius
    auto=add
 
#供 android, linux, os x 使用
conn IPSec-IKEv2
    also=IKE-BASE
    keyexchange=ikev2
    leftauth=pubkey
    rightauth=pubkey
    rightcert=client.cert.pem
    auto=add
 
#供 windows 7+ 使用, win7 以下版本需使用第三方 ipsec vpn 客户端连接
conn IPSec-IKEv2-EAP
    also=IKE-BASE
    keyexchange=ikev2
    #ike=aes256-sha1-modp1024!   #第一阶段加密方式
    rekey=no                     #服务器对 Windows 发出 rekey 请求会断开连接
    leftauth=pubkey
    rightauth=eap-radius
    rightsendcert=never          #服务器不要向客户端请求证书
    eap_identity=%any
    auto=add
conn L2TP-PSK
    keyexchange=ikev1
    authby=secret
    leftprotoport=17/1701 #l2tp端口
    leftfirewall=no
    rightprotoport=17/%any
    type=transport
    auto=add
#供linux客户端
conn ipke2vpn
    keyexchange=ikev2
    ike=aes256-sha1-modp1024!
    esp=aes256-sha1!
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%defaultroute
    leftsubnet=0.0.0.0/0
    leftauth=pubkey
    leftcert=server.Cert.pem
    leftid="$public_ip"
    right=%any
    rightsourceip=10.0.0.0/24
    rightauth=eap-radius  #使用radius
    rightsendcert=never
    eap_identity=%any
    auto=add
EOF
echo '' > /etc/strongswan.conf
cat >>  /etc/strongswan.conf <<EOF
# strongswan.conf - strongSwan configuration file
#
# Refer to the strongswan.conf(5) manpage for details
#
# Configuration changes should be made in the included files
charon {
        i_dont_care_about_security_and_use_aggressive_mode_psk = yes
        duplicheck.enable = no
        threads = 16
        compress = yes 
        load_modular = yes
        plugins {
                include strongswan.d/charon/*.conf    
               }
	dns1 = 8.8.8.8
	dns2 = 114.114.114.114
}
include strongswan.d/*.conf
EOF
sed -i "s/# accounting = no/accounting = yes/g" /etc/strongswan.d/charon/eap-radius.conf 
#\n是回车 \t tab
sed -i '/servers {/a\ \t radius{\n \t address = 127.0.0.1 \n \t secret = testing123 \n \t \t }' /etc/strongswan.d/charon/eap-radius.conf 
sed -i "s/# backend = radius/ backend = radius/g" /etc/strongswan.d/charon/xauth-eap.conf
cat >>  /etc/ipsec.secrets <<EOF
: RSA server.key.pem #使用证书验证时的服务器端私钥
: PSK "$ike_passwd" #使用预设密钥时, 8-63位ASCII字符
: XAUTH "$ike_passwd"
EOF
}


function set_xl2tp(){
yum -y install xl2tpd
echo '' > /etc/ppp/options.xl2tpd 
cat >>  /etc/ppp/options.xl2tpd  <<EOF
ipcp-accept-local
ipcp-accept-remote
ms-dns  8.8.8.8
ms-dns  8.8.4.4
noccp
auth
idle 1800
mtu 1410
mru 1410
nodefaultroute
debug
proxyarp
connect-delay 5000
EOF
echo '' > /etc/xl2tpd/xl2tpd.conf
cat >>  /etc/xl2tpd/xl2tpd.conf  <<EOF
[global]
[lns default]
ip range = 10.8.1.100-10.8.1.200
local ip = 10.8.1.1
require chap = yes
refuse pap = yes
require authentication = yes
name = LinuxVPNserver
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF
yum -y install radiusclient-ng
echo '127.0.0.1 testing123' >> /etc/radiusclient-ng/servers
cp -rf /usr/share/radiusclient-ng/dictionary /etc/radiusclient-ng/
echo 'INCLUDE /etc/radiusclient-ng/dictionary.microsoft' >> /etc/radiusclient-ng/dictionary
touch /etc/radiusclient-ng/dictionary.microsoft
cat >> /etc/radiusclient-ng/dictionary.microsoft <<EOF
#
#	Microsoft's VSA's, from RFC 2548
#
#	$Id: dictionary.microsoft,v 1.1 2004/11/14 07:26:26 paulus Exp $
#

VENDOR		Microsoft	311	Microsoft

ATTRIBUTE	MS-CHAP-Response	1	string	Microsoft
ATTRIBUTE	MS-CHAP-Error		2	string	Microsoft
ATTRIBUTE	MS-CHAP-CPW-1		3	string	Microsoft
ATTRIBUTE	MS-CHAP-CPW-2		4	string	Microsoft
ATTRIBUTE	MS-CHAP-LM-Enc-PW	5	string	Microsoft
ATTRIBUTE	MS-CHAP-NT-Enc-PW	6	string	Microsoft
ATTRIBUTE	MS-MPPE-Encryption-Policy 7	string	Microsoft
# This is referred to as both singular and plural in the RFC.
# Plural seems to make more sense.
ATTRIBUTE	MS-MPPE-Encryption-Type 8	string	Microsoft
ATTRIBUTE	MS-MPPE-Encryption-Types  8	string	Microsoft
ATTRIBUTE	MS-RAS-Vendor		9	integer	Microsoft
ATTRIBUTE	MS-CHAP-Domain		10	string	Microsoft
ATTRIBUTE	MS-CHAP-Challenge	11	string	Microsoft
ATTRIBUTE	MS-CHAP-MPPE-Keys	12	string	Microsoft
ATTRIBUTE	MS-BAP-Usage		13	integer	Microsoft
ATTRIBUTE	MS-Link-Utilization-Threshold 14 integer	Microsoft
ATTRIBUTE	MS-Link-Drop-Time-Limit	15	integer	Microsoft
ATTRIBUTE	MS-MPPE-Send-Key	16	string	Microsoft
ATTRIBUTE	MS-MPPE-Recv-Key	17	string	Microsoft
ATTRIBUTE	MS-RAS-Version		18	string	Microsoft
ATTRIBUTE	MS-Old-ARAP-Password	19	string	Microsoft
ATTRIBUTE	MS-New-ARAP-Password	20	string	Microsoft
ATTRIBUTE	MS-ARAP-PW-Change-Reason 21	integer	Microsoft

ATTRIBUTE	MS-Filter		22	string	Microsoft
ATTRIBUTE	MS-Acct-Auth-Type	23	integer	Microsoft
ATTRIBUTE	MS-Acct-EAP-Type	24	integer	Microsoft

ATTRIBUTE	MS-CHAP2-Response	25	string	Microsoft
ATTRIBUTE	MS-CHAP2-Success	26	string	Microsoft
ATTRIBUTE	MS-CHAP2-CPW		27	string	Microsoft

ATTRIBUTE	MS-Primary-DNS-Server	28	ipaddr	Microsoft
ATTRIBUTE	MS-Secondary-DNS-Server	29	ipaddr	Microsoft
ATTRIBUTE	MS-Primary-NBNS-Server	30	ipaddr	Microsoft
ATTRIBUTE	MS-Secondary-NBNS-Server 31	ipaddr	Microsoft

#ATTRIBUTE	MS-ARAP-Challenge	33	string	Microsoft


#
#	Integer Translations
#

#	MS-BAP-Usage Values

VALUE		MS-BAP-Usage		Not-Allowed	0
VALUE		MS-BAP-Usage		Allowed		1
VALUE		MS-BAP-Usage		Required	2

#	MS-ARAP-Password-Change-Reason Values

VALUE	MS-ARAP-PW-Change-Reason	Just-Change-Password		1
VALUE	MS-ARAP-PW-Change-Reason	Expired-Password		2
VALUE	MS-ARAP-PW-Change-Reason	Admin-Requires-Password-Change	3
VALUE	MS-ARAP-PW-Change-Reason	Password-Too-Short		4

#	MS-Acct-Auth-Type Values

VALUE		MS-Acct-Auth-Type	PAP		1
VALUE		MS-Acct-Auth-Type	CHAP		2
VALUE		MS-Acct-Auth-Type	MS-CHAP-1	3
VALUE		MS-Acct-Auth-Type	MS-CHAP-2	4
VALUE		MS-Acct-Auth-Type	EAP		5

#	MS-Acct-EAP-Type Values

VALUE		MS-Acct-EAP-Type	MD5		4
VALUE		MS-Acct-EAP-Type	OTP		5
VALUE		MS-Acct-EAP-Type	Generic-Token-Card	6
VALUE		MS-Acct-EAP-Type	TLS		13
EOF
echo 'plugin radius.so' >> /etc/ppp/options.xl2tpd
echo 'radius-config-file /etc/radiusclient-ng/radiusclient.conf' >> /etc/ppp/options.xl2tpd
service strongswan restart
service xl2tpd restart
}

function set_fix_radacct_table7(){
	cd /tmp
	sleep 3
	wget http://www.beijinghuayu.com.cn/down/radacct_new.sql.tar.gz
	tar xzvf radacct_new.sql.tar.gz
	mysql -uradius -p'p0radius_0p' radius < /tmp/radacct_new.sql
	systemctl restart strongswan
	systemctl restart radiusd

}


function set_openvpn8(){
	modprobe tun
	yum -y install openssl openssl-devel lzo openvpn easy-rsa
	yum -y install expect
cp -rf /usr/share/easy-rsa/ /etc/openvpn
cd /etc/openvpn/easy-rsa/3.0
./easyrsa init-pki 
expect<<-END
spawn ./easyrsa build-ca nopass
expect "CA]:"
send "\r"
expect eof
exit
END
expect<<-END
spawn ./easyrsa gen-req server nopass
expect "server]:"
send "\r"
expect eof
exit
END
expect<<-END
spawn ./easyrsa sign server server
expect "details:"
send "yes\r"
expect eof
exit
END
./easyrsa gen-dh 
touch /etc/openvpn/server.conf
cat >>  /etc/openvpn/server.conf <<EOF
port 1194 # default port
proto udp # default protocol
dev tun
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
reneg-sec 0
ca /etc/openvpn/easy-rsa/3.0/pki/ca.crt
cert /etc/openvpn/easy-rsa/3.0/pki/issued/server.crt
key /etc/openvpn/easy-rsa/3.0/pki/private/server.key
dh /etc/openvpn/easy-rsa/3.0/pki/dh.pem
#plugin /usr/share/openvpn/plugin/lib/openvpn-auth-pam.so /etc/pam.d/login # 如果使用freeradius，请注释这一行
plugin /etc/openvpn/radiusplugin.so /etc/openvpn/radiusplugin.cnf # 如果使用freeradius，请去掉这一行的注释
server 10.8.0.0 255.255.255.0 # 分配给VPN客户端的地址范围
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1"
push "route 192.168.0.0 255.255.255.0"    #指定VPN客户端访问你服务器的内网网段
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 2 20
comp-lzo
persist-key
persist-tun
status openvpn-status.log
log-append openvpn.log
verb 3
#script-security 3
#auth-user-pass-verify /etc/openvpn/checkpsw.sh via-env
client-cert-not-required            #启用后，就关闭证书认证，只通过账号密码认证
username-as-common-name
EOF
touch /etc/openvpn/easy-rsa/3.0/client.ovpn
cat >>  /etc/openvpn/easy-rsa/3.0/client.ovpn <<EOF
client
dev tun
proto udp
remote $public_ip 1194 # – Your server IP and OpenVPN Port
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
ca ca.crt
auth-user-pass
comp-lzo
reneg-sec 0
verb 3
EOF
}


function set_openvpn_freeradius9(){
	yum -y install libgcrypt libgcrypt-devel gcc-c++
	cd /tmp
	wget http://www.beijinghuayu.com.cn/down/radiusplugin_v2.1a_beta1.tar.gz
	tar xzvf radiusplugin_v2.1a_beta1.tar.gz
	cd radiusplugin_v2.1a_beta1
	make
	cp -rf radiusplugin.so /etc/openvpn/
	cp -rf radiusplugin.cnf /etc/openvpn/
	sed -i "s/name=192.168.0.153/name=127.0.0.1/g" /etc/openvpn/radiusplugin.cnf
	sed -i "s/sharedsecret=testpw/sharedsecret=testing123/g" /etc/openvpn/radiusplugin.cnf
	systemctl restart openvpn@server
}
function set_netdisco(){
yum -y install perl-core perl-DBD-Pg net-snmp-perl net-snmp-devel openssl-devel make automake gcc expect wget
yum -y install postgresql-server postgresql-contrib
useradd -m -p x -s /bin/bash netdisco
postgresql-setup initdb
systemctl start postgresql
systemctl enable postgresql
su - postgres <<!
expect<<-END
spawn createuser -DRSP netdisco
expect "role:"
send "netdisco\r"
expect "again:"
send "netdisco\r"
expect eof
exit
END
createdb -O netdisco netdisco
exit
!
sed -i "/#/b;s/peer/md5/g" /var/lib/pgsql/data/pg_hba.conf
sed -i "/#/b;s/ident/md5/g" /var/lib/pgsql/data/pg_hba.conf
systemctl restart postgresql
su - netdisco <<!
curl -L https://cpanmin.us/ | perl - --notest --local-lib ~/perl5 App::Netdisco
mkdir ~/bin
ln -s ~/perl5/bin/{localenv,netdisco-*} ~/bin/
mkdir ~/environments
cp ~/perl5/lib/perl5/auto/share/dist/App-Netdisco/environments/deployment.yml ~/environments
chmod 600 ~/environments/deployment.yml
sed -i '/user:/s/changeme/netdisco/g' ~/environments/deployment.yml
sed -i '/pass:/s/changeme/netdisco/g' ~/environments/deployment.yml
expect<<-END
spawn ~/bin/netdisco-deploy
expect "N]:"
send "y\r"
expect "N]:"
send "y\r"
expect "Username:  :"
send "netdisco\r"
expect "Password:  : "
send "netdisco\r"
expect "N]:"
send "y\r"
expect "N]:"
send "n\r"
expect eof
exit
END
wget http://www.beijinghuayu.com.cn/down/netdisco-mibs.tar.gz >/dev/null 2>&1
tar xzvf netdisco-mibs.tar.gz
rm -rf netdisco-mibs.tar.gz
chown -R netdisco:netdisco /home/netdisco/netdisco-mibs
~/bin/netdisco-web start
~/bin/netdisco-backend start
!
#sed -i '/xxx/s/aaa/fff/g' file    --表示针对文件，找出包含xxx的行，并将其中的aaa替换为ff
}
function set_iptables10(){
	echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
	sysctl -p
	yum -y install iptables-services
	systemctl start iptables.service
	chmod +x /etc/rc.local
cat >>  /etc/rc.local <<EOF
systemctl start mariadb
systemctl start httpd
systemctl start radiusd
systemctl start strongswan
systemctl start xl2tpd
systemctl start iptables
systemctl start openvpn@server
iptables -F
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 9090 -j ACCEPT
iptables -A INPUT -p tcp --dport 9091 -j ACCEPT
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT 
iptables -A INPUT -p tcp --dport 1723 -j ACCEPT
iptables -A INPUT -p gre -j ACCEPT
iptables -A INPUT -p udp -m policy --dir in --pol ipsec -m udp --dport 1701 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 1701 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 4500 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 1194 -j ACCEPT
iptables -A INPUT -p esp -j ACCEPT
iptables -A INPUT -m policy --dir in --pol ipsec -j ACCEPT
iptables -A INPUT -j DROP
iptables -A FORWARD -i ppp+ -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -d 10.0.0.0/24 -j ACCEPT
iptables -A FORWARD -s 10.0.0.0/24 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE
su - netdisco <<!
~/bin/netdisco-web start
~/bin/netdisco-backend start
!
EOF
/etc/rc.local
}

function set_web_config(){
echo  "
Listen 9090
Listen 9091
<VirtualHost *:9090>
 DocumentRoot "/var/www/html/daloradius"
 ServerName daloradius
 ErrorLog "logs/daloradius-error.log"
 CustomLog "logs/daloradius-access.log" common
</VirtualHost>
<VirtualHost *:9091>
 DocumentRoot "/var/www/html/user_reg_new"
 ServerName userReg
 ErrorLog "logs/test-error.log"
 CustomLog "logs/test-access.log" common
</VirtualHost>
" >> /etc/httpd/conf/httpd.conf
cd /var/www/html/
rm -rf *
wget http://www.beijinghuayu.com.cn/down/dbback.tar.gz
tar xzvf dbback.tar.gz
rm -rf dbback.tar.gz
wget http://www.beijinghuayu.com.cn/down/daloradius20180310.tar.gz 
tar xzvf daloradius20180310.tar.gz 
rm -rf daloradius20180310.tar.gz
wget http://www.beijinghuayu.com.cn/down/user_reg_new20180311.tar.gz
tar xzvf user_reg_new20180311.tar.gz
rm -rf user_reg_new20180311.tar.gz
chown -R apache:apache /var/www/html/daloradius
chown -R apache:apache /var/www/html/user_reg_new
#获取当前页面中的strongswanpsk
strongswanPSK_page=`cat /var/www/html/user_reg_new/class.user.php | grep 'strongswan' | awk -F "'" '{print $2}'`
#获取实际的strongswanpsk
strongswanPSK=`cat /etc/ipsec.secrets | grep PSK |awk -F '"' {'print $2'}`
sed -i "s/$strongswanPSK_page/$strongswanPSK/g" /var/www/html/user_reg_new/class.user.php
service httpd restart
}


function set_initvpn(){
echo "注意网卡地址必须为固定，如果网卡地址不固定，按Ctrl＋C 结束，请想修改网卡地址为固定地址"
#获取网卡接口
netcard_name=`ifconfig | head -1 | awk -F ":" '{print$1}'`
#获取当前公网IP地址
currPubIP=`grep '$pubIP' /var/www/html/user_reg_new/class.user.php | awk -F "'" '{print $2}'`
echo "设备当前的公网地址为：$currPubIP"
#获取当前内网IP地址、子网掩码、网关
currPriIP=`cat /etc/sysconfig/network-scripts/ifcfg-$netcard_name | grep 'IPADDR' | awk -F '"' '{print $2}'`
currPriSubnet=`cat /etc/sysconfig/network-scripts/ifcfg-$netcard_name | grep 'NETMASK' | awk -F '"' '{print $2}'`
currPriGateway=`cat /etc/sysconfig/network-scripts/ifcfg-$netcard_name | grep 'GATEWAY' | awk -F '"' '{print $2}'`
echo "设备当前的内网地址为：$currPriIP"
echo "设备当前的子网掩码为：$currPriSubnet"
echo "设备当前的网关地址为：$currPriGateway"
#读取用户设置的内网IP地址
read -p "是否要修改VPN的公网地址:［y/n］" changePubIP
if [ $changePubIP == "y" ];then
	read -p "当前公网地址为 $currPubIP,请输入新的VPN公网IP地址:" newPubIP
	sed -i "s/$currPubIP/$newPubIP/g" /var/www/html/user_reg_new/class.user.php
	sed -i "s/$currPubIP/$newPubIP/g" /var/www/html/daloradius/library/exten-welcome_page.php
	sed -i "s/$currPubIP/$newPubIP/g" /etc/ipsec.conf 
	sed -i "s/$currPubIP/$newPubIP/g" /etc/openvpn/easy-rsa/3.0/client.ovpn
	sed -i "s/$currPubIP/$newPubIP/g" /root/zhengshu.sh
	/root/zhengshu.sh
	zip -p -r /root/client.zip /root/client.cert.p12
	alias cp='cp'
	cp -rf /root/client.zip /var/www/html/user_reg_new/
	chown -R apache:apache /var/www/html/user_reg_new/
	service strongswan restart
	echo "公网IP地址修改成功"
fi
read -p "是否要修改VPN的-内网-地址:［y/n］" changePriIP
if [ $changePriIP == "y" ];then
	read -p "请输入VPN内网IP地址:" newPriIP
	read -p "请输入VPN内网－子网掩码:" newPriSubnet
	read -p "请输入VPN内网－网关:" newPriGateway
	sed -i "s/$currPriIP/$newPriIP/g" /etc/sysconfig/network-scripts/ifcfg-$netcard_name	
	sed -i "s/$currPriSubnet/$newPriSubnet/g" /etc/sysconfig/network-scripts/ifcfg-$netcard_name
	sed -i "s/$currPriGateway/$newPriGateway/g" /etc/sysconfig/network-scripts/ifcfg-$netcard_name
	echo "网地址修改成功"
	echo "请重新打开ssh窗口使用新地址登录"
	echo " VPN管理地址请访问http://$newPriIP:9090"
fi
echo "==========================================================================
                         Centos7 VPN 安装完成                            
										 
		以下信息将自动保存到/root/info.txt文件中			
                                                                         
                   openvpn 需要导出的客户端配置文件/etc/openvpn/easy-rsa/3.0/client.ovpn 

                   openvpn 需要导出客户端证书文件 /etc/openvpn/easy-rsa/3.0/pki/ca.crt 

                   openvpn 服务器配置文件/etc/openvpn/server.conf 

                   strongswan VPN 预共享密钥:$ike_passwd 

                   strongswan 证书生成文件/root/zhengshu.sh 

                   strongswan 服务器配置文件/etc/ipsec.conf 

                   strongSwan 共享密钥配置文件 /etc/ipsec.secrets 

                   strongSwan 客户端DNS配置文件 /etc/strongswan.conf

                   strongswan 连接radius密钥配置文件/etc/strongswan.d/charon/eap-radius.conf

                   开机启动配置文件/etc/rc.local  

                   mysql root用户密码:0p0o0i0900      

		   用户注册后台登录地址:http://$newPriIP:9091

		   VPN 账号管理后台地址：http://$newPriIP:9090
		                         账号：administrator 密码:radius

		   网管系统后台登录地址：http://$newPriIP:5000
					 账号：netdisco   密码:netdisco

==========================================================================" > /root/info.txt
	service network restart
	sleep 3
	cat /root/info.txt
	exit;
}

function shell_install() {
	echo '初始化设置，请按照下面提示设置您的密码等配置'
	set_shell_input1
	echo "初始化时间"
	set_ntp
	echo '安装freeradius、mariadb、php'
	set_install_pro2
	sleep 3
	echo '开始配置数据库'
	set_mysql3
	echo '配置freeradius'
	set_freeradius4
	echo '安装配置daloradius'
	set_daloradius5
	echo '安装配置strongswan'
	set_strongswan6
	echo "安装l2tp"
	set_xl2tp
	echo '修复radacct表'
	set_fix_radacct_table7
	echo '安装配置openvpn'
	set_openvpn8
	echo '配置openvpn与freeradius连动'
	set_openvpn_freeradius9
	echo '配置netdisco'
	set_netdisco
	echo '配置iptables'
	set_iptables10
	echo '配置daloradius'
	set_web_config
	echo 'vpn服务器初始化IP'
	set_initvpn
}
shell_install

#changelog
#v2.2 增加了xl2tpd 的配置，并修改了strongswan 的安装路径为/etc/ ，删除了升级php7的函数
