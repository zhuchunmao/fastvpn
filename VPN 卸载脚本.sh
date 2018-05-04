#!/bin/bash
	yum -y remove ntp
 	yum groupremove "Development tools" -y
	yum remove wget vim expect telnet net-tools httpd mariadb-server php php-mysql php-gd php-ldap php-odbc php-pear php-xml php-xmlrpc php-mbstring php-snmp php-soap curl curl-devel -y
	yum remove freeradius freeradius-mysql freeradius-utils -y
	rm -rf /var/www/html/
	yum -y remove php-pear-DB
    yum -y remove strongswan strongswan-libipsec strongswan-tnc-imcvs
	rm -rf /root/zhengshu.sh
	rm -rf /etc/strongswan/
	rm -rf /etc/raddb/
yum -y remove radiusclient-ng
rm -rf /etc/radiusclient-ng/
yum remove xl2tpd -y
	yum -y remove openssl openssl-devel lzo openvpn easy-rsa
	yum -y remove expect
   rm -rf /etc/openvpn/
   yum -y remove libgcrypt libgcrypt-devel gcc-c++
rm -rf /root/initvpn*.sh
rm -rf /root/info.txt