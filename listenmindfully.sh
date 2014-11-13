#!/bin/bash
#
# <UDF name="user_password" label="User password" />
# <UDF name="haproxy_password" label="HAProxy stats password" />

NOTIFY_EMAIL=eric.david.isakson@gmail.com
USER_NAME="eric"
USER_SSHKEY="ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAIEAgd1shp+Tvj1LYoW6r+UrvL/G1y1e25JW9mpnRcsxvllBlALAP5LxGfyZJDFg+HfmGszTABMrYRUxwPy+awDjNZrjl021YwY10JkWINvEXZjI7KKC5VppZx1E0VHGWdshlFxUQefNp2j5P1l08qKemtDJWeF0y4dVF0LqH+JvCQ0= rsa-key-20120530"
SSHD_PASSWORDAUTH="No"
SSHD_PERMITROOTLOGIN="No"
USER_SHELL="/bin/bash"
SYS_HOSTNAME="amber"
SETUP_MONGODB="Yes"
SETUP_MONIT="Yes"
USER_GROUPS=sudo

###########################################################
# System
###########################################################

function system_update {
    apt-get update
    apt-get -y install aptitude
    aptitude -y full-upgrade
}

function system_primary_ip {
    # returns the primary IP assigned to eth0
    echo $(ifconfig eth0 | awk -F: '/inet addr:/ {print $2}' | awk '{ print $1 }')
}

function get_rdns {
    # calls host on an IP address and returns its reverse dns

    if [ ! -e /usr/bin/host ]; then
        aptitude -y install dnsutils > /dev/null
    fi
    echo $(host $1 | awk '/pointer/ {print $5}' | sed 's/\.$//')
}

function get_rdns_primary_ip {
    # returns the reverse dns of the primary IP assigned to this system
    echo $(get_rdns $(system_primary_ip))
}

function system_set_hostname {
    # $1 - The hostname to define
    HOSTNAME="$1"

    if [ ! -n "$HOSTNAME" ]; then
        echo "Hostname undefined"
        return 1;
    fi

    echo "$HOSTNAME" > /etc/hostname
    hostname -F /etc/hostname
}

function system_add_host_entry {
    # $1 - The IP address to set a hosts entry for
    # $2 - The FQDN to set to the IP
    IPADDR="$1"
    FQDN="$2"

    if [ -z "$IPADDR" -o -z "$FQDN" ]; then
        echo "IP address and/or FQDN Undefined"
        return 1;
    fi

    echo $IPADDR $FQDN  >> /etc/hosts
}


###########################################################
# Users and Authentication
###########################################################

function user_add_sudo {
    # Installs sudo if needed and creates a user in the sudo group.
    #
    # $1 - Required - username
    # $2 - Required - password
    USERNAME="$1"
    USERPASS="$2"

    if [ ! -n "$USERNAME" ] || [ ! -n "$USERPASS" ]; then
        echo "No new username and/or password entered"
        return 1;
    fi

    aptitude -y install sudo
    adduser $USERNAME --disabled-password --gecos ""
    echo "$USERNAME:$USERPASS" | chpasswd
    usermod -aG sudo $USERNAME
}

function user_add_pubkey {
    # Adds the users public key to authorized_keys for the specified user. Make sure you wrap your input variables in double quotes, or the key may not load properly.
    #
    #
    # $1 - Required - username
    # $2 - Required - public key
    USERNAME="$1"
    USERPUBKEY="$2"

    if [ ! -n "$USERNAME" ] || [ ! -n "$USERPUBKEY" ]; then
        echo "Must provide a username and the location of a pubkey"
        return 1;
    fi

    if [ "$USERNAME" == "root" ]; then
        mkdir /root/.ssh
        echo "$USERPUBKEY" >> /root/.ssh/authorized_keys
        return 1;
    fi

    mkdir -p /home/$USERNAME/.ssh
    echo "$USERPUBKEY" >> /home/$USERNAME/.ssh/authorized_keys
    chown -R "$USERNAME":"$USERNAME" /home/$USERNAME/.ssh
}

function ssh_disable_root {
    # Disables root SSH access.
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    touch /tmp/restart-ssh

}


###########################################################
# Apache
###########################################################

function apache_install {
    # installs the system default apache2 MPM
    aptitude -y install apache2

    a2dissite default # disable the interfering default virtualhost

    # clean up, or add the NameVirtualHost line to ports.conf
    sed -i -e 's/^NameVirtualHost \*$/NameVirtualHost *:80/' /etc/apache2/ports.conf
    if ! grep -q NameVirtualHost /etc/apache2/ports.conf; then
        echo 'NameVirtualHost *:80' > /etc/apache2/ports.conf.tmp
        cat /etc/apache2/ports.conf >> /etc/apache2/ports.conf.tmp
        mv -f /etc/apache2/ports.conf.tmp /etc/apache2/ports.conf
    fi
}

function apache_tune {
    # Tunes Apache's memory to use the percentage of RAM you specify, defaulting to 40%

    # $1 - the percent of system memory to allocate towards Apache

    if [ ! -n "$1" ];
        then PERCENT=40
        else PERCENT="$1"
    fi

    aptitude -y install apache2-mpm-prefork
    PERPROCMEM=10 # the amount of memory in MB each apache process is likely to utilize
    MEM=$(grep MemTotal /proc/meminfo | awk '{ print int($2/1024) }') # how much memory in MB this system has
    MAXCLIENTS=$((MEM*PERCENT/100/PERPROCMEM)) # calculate MaxClients
    MAXCLIENTS=${MAXCLIENTS/.*} # cast to an integer
    sed -i -e "s/\(^[ \t]*MaxClients[ \t]*\)[0-9]*/\1$MAXCLIENTS/" /etc/apache2/apache2.conf

    touch /tmp/restart-apache2
}

function apache_virtualhost {
    # Configures a VirtualHost

    # $1 - required - the hostname of the virtualhost to create

    if [ ! -n "$1" ]; then
        echo "apache_virtualhost() requires the hostname as the first argument"
        return 1;
    fi

    if [ -e "/etc/apache2/sites-available/$1" ]; then
        echo /etc/apache2/sites-available/$1 already exists
        return;
    fi

    mkdir -p /srv/www/$1/public_html /srv/www/$1/logs

    echo "<VirtualHost *:80>" > /etc/apache2/sites-available/$1
    echo "    ServerName $1" >> /etc/apache2/sites-available/$1
    echo "    DocumentRoot /srv/www/$1/public_html/" >> /etc/apache2/sites-available/$1
    echo "    ErrorLog /srv/www/$1/logs/error.log" >> /etc/apache2/sites-available/$1
    echo "    CustomLog /srv/www/$1/logs/access.log combined" >> /etc/apache2/sites-available/$1
    echo "</VirtualHost>" >> /etc/apache2/sites-available/$1

    a2ensite $1

    touch /tmp/restart-apache2
}

function apache_virtualhost_from_rdns {
    # Configures a VirtualHost using the rdns of the first IP as the ServerName

    apache_virtualhost $(get_rdns_primary_ip)
}


function apache_virtualhost_get_docroot {
    if [ ! -n "$1" ]; then
        echo "apache_virtualhost_get_docroot() requires the hostname as the first argument"
        return 1;
    fi

    if [ -e /etc/apache2/sites-available/$1 ];
        then echo $(awk '/DocumentRoot/ {print $2}' /etc/apache2/sites-available/$1 )
    fi
}

###########################################################
# mysql-server
###########################################################

function mysql_install {
    # $1 - the mysql root password

    if [ ! -n "$1" ]; then
        echo "mysql_install() requires the root pass as its first argument"
        return 1;
    fi

    echo "mysql-server mysql-server/root_password password $1" | debconf-set-selections
    echo "mysql-server mysql-server/root_password_again password $1" | debconf-set-selections
    apt-get -y install mysql-server mysql-client

    echo "Sleeping while MySQL starts up for the first time..."
    sleep 5
}

function mysql_tune {
    # Tunes MySQL's memory usage to utilize the percentage of memory you specify, defaulting to 40%

    # $1 - the percent of system memory to allocate towards MySQL

    if [ ! -n "$1" ];
        then PERCENT=40
        else PERCENT="$1"
    fi

    sed -i -e 's/^#skip-innodb/skip-innodb/' /etc/mysql/my.cnf # disable innodb - saves about 100M

    MEM=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo) # how much memory in MB this system has
    MYMEM=$((MEM*PERCENT/100)) # how much memory we'd like to tune mysql with
    MYMEMCHUNKS=$((MYMEM/4)) # how many 4MB chunks we have to play with

    # mysql config options we want to set to the percentages in the second list, respectively
    OPTLIST=(key_buffer sort_buffer_size read_buffer_size read_rnd_buffer_size myisam_sort_buffer_size query_cache_size)
    DISTLIST=(75 1 1 1 5 15)

    for opt in ${OPTLIST[@]}; do
        sed -i -e "/\[mysqld\]/,/\[.*\]/s/^$opt/#$opt/" /etc/mysql/my.cnf
    done

    for i in ${!OPTLIST[*]}; do
        val=$(echo | awk "{print int((${DISTLIST[$i]} * $MYMEMCHUNKS/100))*4}")
        if [ $val -lt 4 ]
            then val=4
        fi
        config="${config}\n${OPTLIST[$i]} = ${val}M"
    done

    sed -i -e "s/\(\[mysqld\]\)/\1\n$config\n/" /etc/mysql/my.cnf

    touch /tmp/restart-mysql
}

function mysql_create_database {
    # $1 - the mysql root password
    # $2 - the db name to create

    if [ ! -n "$1" ]; then
        echo "mysql_create_database() requires the root pass as its first argument"
        return 1;
    fi
    if [ ! -n "$2" ]; then
        echo "mysql_create_database() requires the name of the database as the second argument"
        return 1;
    fi

    echo "CREATE DATABASE $2;" | mysql -u root -p$1
}

function mysql_create_user {
    # $1 - the mysql root password
    # $2 - the user to create
    # $3 - their password

    if [ ! -n "$1" ]; then
        echo "mysql_create_user() requires the root pass as its first argument"
        return 1;
    fi
    if [ ! -n "$2" ]; then
        echo "mysql_create_user() requires username as the second argument"
        return 1;
    fi
    if [ ! -n "$3" ]; then
        echo "mysql_create_user() requires a password as the third argument"
        return 1;
    fi

    echo "CREATE USER '$2'@'localhost' IDENTIFIED BY '$3';" | mysql -u root -p$1
}

function mysql_grant_user {
    # $1 - the mysql root password
    # $2 - the user to bestow privileges
    # $3 - the database

    if [ ! -n "$1" ]; then
        echo "mysql_create_user() requires the root pass as its first argument"
        return 1;
    fi
    if [ ! -n "$2" ]; then
        echo "mysql_create_user() requires username as the second argument"
        return 1;
    fi
    if [ ! -n "$3" ]; then
        echo "mysql_create_user() requires a database as the third argument"
        return 1;
    fi

    echo "GRANT ALL PRIVILEGES ON $3.* TO '$2'@'localhost';" | mysql -u root -p$1
    echo "FLUSH PRIVILEGES;" | mysql -u root -p$1

}

###########################################################
# PHP functions
###########################################################

function php_install_with_apache {
    aptitude -y install php5 php5-mysql libapache2-mod-php5
    touch /tmp/restart-apache2
}

function php_tune {
    # Tunes PHP to utilize up to 32M per process

    sed -i'-orig' 's/memory_limit = [0-9]\+M/memory_limit = 32M/' /etc/php5/apache2/php.ini
    touch /tmp/restart-apache2
}

###########################################################
# Wordpress functions
###########################################################

function wordpress_install {
    # installs the latest wordpress tarball from wordpress.org

    # $1 - required - The existing virtualhost to install into

    if [ ! -n "$1" ]; then
        echo "wordpress_install() requires the vitualhost as its first argument"
        return 1;
    fi

    if [ ! -e /usr/bin/wget ]; then
        aptitude -y install wget
    fi

    VPATH=$(apache_virtualhost_get_docroot $1)

    if [ ! -n "$VPATH" ]; then
        echo "Could not determine DocumentRoot for $1"
        return 1;
    fi

    # download, extract, chown, and get our config file started
    cd $VPATH
    wget http://wordpress.org/latest.tar.gz
    tar xfz latest.tar.gz
    chown -R www-data: wordpress/
    cd $VPATH/wordpress
    cp wp-config-sample.php wp-config.php
    chown www-data wp-config.php
    chmod 640 wp-config.php

    # database configuration
    WPPASS=$(randomString 20)
    mysql_create_database "$DB_PASSWORD" wordpress
    mysql_create_user "$DB_PASSWORD" wordpress "$WPPASS"
    mysql_grant_user "$DB_PASSWORD" wordpress wordpress

    # configuration file updates
    for i in {1..4}
        do sed -i "0,/put your unique phrase here/s/put your unique phrase here/$(randomString 50)/" wp-config.php
    done

    sed -i 's/database_name_here/wordpress/' wp-config.php
    sed -i 's/username_here/wordpress/' wp-config.php
    sed -i "s/password_here/$WPPASS/" wp-config.php

    # http://downloads.wordpress.org/plugin/wp-super-cache.0.9.8.zip
}

###########################################################
# Other niceties!
###########################################################

function goodstuff {
    # Installs the REAL vim, wget, less, and enables color root prompt and the "ll" list long alias

    aptitude -y install wget vim less
    sed -i -e 's/^#PS1=/PS1=/' /root/.bashrc # enable the colorful root bash prompt
    sed -i -e "s/^#alias ll='ls -l'/alias ll='ls -al'/" /root/.bashrc # enable ll list long alias <3
}


###########################################################
# utility functions
###########################################################

function restartServices {
    # restarts services that have a file in /tmp/needs-restart/

    for service in $(ls /tmp/restart-* | cut -d- -f2-10); do
        /etc/init.d/$service restart
        rm -f /tmp/restart-$service
    done
}

function randomString {
    if [ ! -n "$1" ];
        then LEN=20
        else LEN="$1"
    fi

    echo $(</dev/urandom tr -dc A-Za-z0-9 | head -c $LEN) # generate a random string
}

function lower {
    # helper function
    echo $1 | tr '[:upper:]' '[:lower:]'
}

function system_add_user {
    # system_add_user(username, password, groups, shell=/bin/bash)
    USERNAME=`lower $1`
    PASSWORD=$2
    SUDO_GROUP=$3
    SHELL=$4
    if [ -z "$4" ]; then
        SHELL="/bin/bash"
    fi
    useradd --create-home --shell "$SHELL" --user-group --groups "$SUDO_GROUP" "$USERNAME"
    echo "$USERNAME:$PASSWORD" | chpasswd
}

function system_add_system_user {
    # system_add_system_user(username, home, shell=/bin/bash)
    USERNAME=`lower $1`
    HOME_DIR=$2
    SHELL=$3
    if [ -z "$3" ]; then
        SHELL="/bin/bash"
    fi
    useradd --system --create-home --home-dir "$HOME_DIR" --shell "$SHELL" --user-group $USERNAME
}

function system_lock_user {
    # system_lock_user(username)
    passwd -l "$1"
}

function system_get_user_home {
    # system_get_user_home(username)
    cat /etc/passwd | grep "^$1:" | cut --delimiter=":" -f6
}

function system_user_add_ssh_key {
    # system_user_add_ssh_key(username, ssh_key)
    USERNAME=`lower $1`
    USER_HOME=`system_get_user_home "$USERNAME"`
    sudo -u "$USERNAME" mkdir "$USER_HOME/.ssh"
    sudo -u "$USERNAME" touch "$USER_HOME/.ssh/authorized_keys"
    sudo -u "$USERNAME" echo "$2" >> "$USER_HOME/.ssh/authorized_keys"
    chmod 0600 "$USER_HOME/.ssh/authorized_keys"
}

function system_sshd_edit_bool {
    # system_sshd_edit_bool (param_name, "Yes"|"No")
    VALUE=`lower $2`
    if [ "$VALUE" == "yes" ] || [ "$VALUE" == "no" ]; then
        sed -i "s/^#*\($1\).*/\1 $VALUE/" /etc/ssh/sshd_config
    fi
}

function system_sshd_permitrootlogin {
    system_sshd_edit_bool "PermitRootLogin" "$1"
}

function system_sshd_passwordauthentication {
    system_sshd_edit_bool "PasswordAuthentication" "$1"
}

function system_update_hostname {
    # system_update_hostname(system hostname)
    if [ -z "$1" ]; then
        echo "system_update_hostname() requires the system hostname as its first argument"
        return 1;
    fi
    echo $1 > /etc/hostname
    hostname -F /etc/hostname
    echo -e "\n127.0.0.1 $1 $1.local\n" >> /etc/hosts
}

function system_security_logcheck {
    aptitude -y install logcheck logcheck-database
    # configure email
    # start after setup
}

function system_security_fail2ban {
    aptitude -y install fail2ban
}

function system_security_ufw_configure_basic {
    # see https://help.ubuntu.com/community/UFW
    ufw logging on

    ufw default deny

    ufw allow ssh/tcp
    ufw limit ssh/tcp

    ufw allow http/tcp
    # TODO setup https ufw allow https/tcp

    ufw allow smtp/tcp

    # monit port
    ufw allow 2812/tcp

    ufw enable
}

function system_configure_private_network {
    # system_configure_private_network(private_ip)
    PRIVATE_IP=$1
    NETMASK="255.255.128.0"
    cat >>/etc/network/interfaces <<EOF
auto eth0:0
iface eth0:0 inet static
 address $PRIVATE_IP
 netmask $NETMASK
EOF
    touch /tmp/restart_initd-networking
}

function restart_services {
    # restarts upstart services that have a file in /tmp/needs-restart/
    for service_name in $(ls /tmp/ | grep restart-* | cut -d- -f2-10); do
        service $service_name restart
        rm -f /tmp/restart-$service_name
    done
}

function restart_initd_services {
    # restarts upstart services that have a file in /tmp/needs-restart/
    for service_name in $(ls /tmp/ | grep restart_initd-* | cut -d- -f2-10); do
        /etc/init.d/$service_name restart
        rm -f /tmp/restart_initd-$service_name
    done
}

# Maintain for compatibility with scripts using this library for Ubuntu 10.04

function system_get_codename {
    echo `lsb_release -sc`
}

function system_get_release {
    echo `lsb_release -sr`
}

function system_sshd_pubkeyauthentication {
    system_sshd_edit_bool "PubkeyAuthentication" "$1"
}

function system_update_locale_en_US_UTF_8 {
    # locale-gen en_US.UTF-8
    dpkg-reconfigure locales
    update-locale LANG=en_US.UTF-8
}

function system_enable_universe {
    sed -i 's/^#\(.*deb.*\) universe/\1 universe/' /etc/apt/sources.list
    aptitude update
}

function system_security_ufw_install {
    aptitude -y install ufw
}

function python_install {
    aptitude -y install python python-dev python-setuptools
    easy_install pip
    pip install virtualenv virtualenvwrapper
}

function ansible_install {
    aptitude -y install software-properties-common
    apt-add-repository -y ppa:ansible/ansible
    aptitude -y update
    aptitude -y install ansible
}

function git_install {
    aptitude -y install git
}

function node_install {
    aptitude -y install nodejs npm
    npm install -g n
    n stable
}

function mongodb_install {
    aptitude -y install mongodb
}

function system_install_utils {
    aptitude -y install htop iotop bsd-mailx python-software-properties zsh
}

function system_install_build {
    aptitude -y install build-essential gcc
}

function node_init_script {
    NAME=$1

    groupadd -r $NAME
    useradd -r -g $NAME -G syslog $NAME

cat <<EOT >/etc/init.d/$NAME
#! /bin/sh
### BEGIN INIT INFO
# Provides:          $NAME
# Required-Start:    \$remote_fs \$syslog
# Required-Stop:     \$remote_fs \$syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: NodeJS $NAME app
# Description:       This file should be used to start and stop the $NAME service.
### END INIT INFO

# Author: Eric Isakson <eric@listenmindfully.org>
#

# Do NOT "set -e"

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/bin
NAME=$NAME
DESC="NodeJS \$NAME app"
DAEMON=/usr/local/bin/\$NAME
DAEMON_DIR=/var/\$NAME
DAEMON_ARGS=\$DAEMON_DIR/boot.js
DAEMONUSER=\$NAME
DAEMONGROUP=\$NAME
PIDFILE=/var/run/\$NAME.pid
SCRIPTNAME=/etc/init.d/\$NAME

[ -x /usr/local/bin/node ] && [ ! -e "\$DAEMON" ] && ln -s /usr/local/bin/node "\$DAEMON"

# Exit if the package is not installed
[ -x "\$DAEMON" ] || exit 0

# Read configuration variable file if it is present
[ -r /etc/default/\$NAME ] && . /etc/default/\$NAME

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.2-14) to ensure that this file is present
# and status_of_proc is working.
. /lib/lsb/init-functions

#
# Function that starts the daemon/service
#
do_start()
{
	# Return
	#   0 if daemon has been started
	#   1 if daemon was already running
	#   2 if daemon could not be started
	start-stop-daemon --start --chuid \${DAEMONUSER}:\${DAEMONGROUP} --quiet --pidfile \$PIDFILE --exec \$DAEMON --test > /dev/null \
		|| return 1
	start-stop-daemon --start --chuid \${DAEMONUSER}:\${DAEMONGROUP} --make-pidfile --quiet --pidfile \$PIDFILE --background --chdir \$DAEMON_DIR\
                      --startas /bin/bash -- -c "exec \$DAEMON \$DAEMON_ARGS > /var/log/\$NAME.log 2>&1" \
		|| return 2
	# Add code here, if necessary, that waits for the process to be ready
	# to handle requests from services started subsequently which depend
	# on this one.  As a last resort, sleep for some time.
}

#
# Function that stops the daemon/service
#
do_stop()
{
	# Return
	#   0 if daemon has been stopped
	#   1 if daemon was already stopped
	#   2 if daemon could not be stopped
	#   other if a failure occurred
	start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 --pidfile \$PIDFILE --name \$NAME
	RETVAL="\$?"
	[ "\$RETVAL" = 2 ] && return 2
	# Wait for children to finish too if this is a daemon that forks
	# and if the daemon is only ever run from this initscript.
	# If the above conditions are not satisfied then add some other code
	# that waits for the process to drop all resources that could be
	# needed by services started subsequently.  A last resort is to
	# sleep for some time.
	start-stop-daemon --stop --quiet --oknodo --retry=0/30/KILL/5 --exec \$DAEMON
	[ "\$?" = 2 ] && return 2
	# Many daemons don't delete their pidfiles when they exit.
	rm -f \$PIDFILE
	return "\$RETVAL"
}

#
# Function that sends a SIGHUP to the daemon/service
#
do_reload() {
	#
	# If the daemon can reload its configuration without
	# restarting (for example, when it is sent a SIGHUP),
	# then implement that here.
	#
	start-stop-daemon --stop --signal 1 --quiet --pidfile \$PIDFILE --name \$NAME
	return 0
}

case "\$1" in
  start)
	[ "\$VERBOSE" != no ] && log_daemon_msg "Starting \$DESC" "\$NAME"
	do_start
	case "\$?" in
		0|1) [ "\$VERBOSE" != no ] && log_end_msg 0 ;;
		2) [ "\$VERBOSE" != no ] && log_end_msg 1 ;;
	esac
	;;
  stop)
	[ "\$VERBOSE" != no ] && log_daemon_msg "Stopping \$DESC" "\$NAME"
	do_stop
	case "\$?" in
		0|1) [ "\$VERBOSE" != no ] && log_end_msg 0 ;;
		2) [ "\$VERBOSE" != no ] && log_end_msg 1 ;;
	esac
	;;
  status)
	status_of_proc "\$DAEMON" "\$NAME" && exit 0 || exit \$?
	;;
  #reload|force-reload)
	#
	# If do_reload() is not implemented then leave this commented out
	# and leave 'force-reload' as an alias for 'restart'.
	#
	#log_daemon_msg "Reloading \$DESC" "\$NAME"
	#do_reload
	#log_end_msg \$?
	#;;
  restart|force-reload)
	#
	# If the "reload" option is implemented then remove the
	# 'force-reload' alias
	#
	log_daemon_msg "Restarting \$DESC" "\$NAME"
	do_stop
	case "\$?" in
	  0|1)
		do_start
		case "\$?" in
			0) log_end_msg 0 ;;
			1) log_end_msg 1 ;; # Old process is still running
			*) log_end_msg 1 ;; # Failed to start
		esac
		;;
	  *)
		# Failed to stop
		log_end_msg 1
		;;
	esac
	;;
  *)
	#echo "Usage: \$SCRIPTNAME {start|stop|restart|reload|force-reload}" >&2
	echo "Usage: \$SCRIPTNAME {start|stop|status|restart|force-reload}" >&2
	exit 3
	;;
esac

:

EOT
    chown root:root /etc/init.d/$NAME
    chmod 755 /etc/init.d/$NAME

    chown root:root /etc/default/$NAME
    chmod 644 /etc/default/$NAME

    update-rc.d $NAME defaults
    touch /tmp/restart_initd-$NAME
}

function www_install {
    git clone https://github.com/eric-isakson/listenmindfully.org.git /var/www
    chmod 755 /var/www

cat <<EOT >/etc/default/www
NODE_ENV="production"
PORT="3000"
EOT

    node_init_script www
}

function haproxy_install {
    aptitude -y install haproxy
    sed -i 's/^ENABLED=.*/ENABLED=1/' /etc/default/haproxy
    touch /tmp/restart_initd-haproxy

cat <<EOT >/etc/haproxy/haproxy.cfg
global
    log         127.0.0.1 local2
    chroot      /var/lib/haproxy
    pidfile     /var/run/haproxy.pid
    maxconn     4000
    user        haproxy
    group       haproxy
    daemon

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    option  http-server-close
    option  forwardfor
    option  redispatch
    retries 3
    timeout http-request    10s
    timeout queue           1m
    timeout connect         10s
    timeout client          1m
    timeout server          1m
    timeout http-keep-alive 10s
    timeout check           10s

frontend  main *:80
    stats enable
    stats uri /haproxy?stats
    stats auth eric:${HAPROXY_PASSWORD}
    default_backend app

backend app
    balance     roundrobin
    server localhost localhost:3000 cookie localhost check
EOT
}

function monit_install {
    aptitude -y install monit
}

function monit_configure_email {
    # system_monit_configure_email(email)
cat <<EOT >/etc/monit/conf.d/email-interface
  set mailserver localhost
  set alert $1
EOT
}

function monit_configure_web {
    # system_monit_configure_web(domain)
cat <<EOT >/etc/monit/conf.d/web-interface
  set httpd port 2812 and
    use address $1
    allow $(randomString 10):$(randomString 30)
    allow @sudo readonly
    signature disable
EOT
}

function monit_def_system {
    # monit_def_system(hostname)
cat <<EOT >/etc/monit/conf.d/system.cfg
  check system $1
    if loadavg (1min) > 10 then alert
    if loadavg (5min) > 7 then alert
    if memory usage > 85% then alert
    if swap usage > 25% then alert
    if cpu usage (user) > 90% then alert
    if cpu usage (system) > 60% then alert
    if cpu usage (wait) > 50% then alert
    group system
EOT
}

function monit_def_rootfs {
cat <<EOT >/etc/monit/conf.d/rootfs.cfg
  check filesystem rootfs with path /
    if space usage > 80% for 5 times within 15 cycles then alert
    if inode usage > 85% then alert
    group system
EOT
}

function monit_def_cron {
cat <<EOT >/etc/monit/conf.d/cron.cfg
  check process cron with pidfile /var/run/crond.pid
    start program = "/sbin/start cron"
    stop  program = "/sbin/stop cron"
    if 5 restarts within 5 cycles then timeout
    depends on cron_rc
    group system

  check file cron_rc with path /etc/init.d/cron
    if failed checksum then unmonitor
    if failed permission 755 then unmonitor
    if failed uid root then unmonitor
    if failed gid root then unmonitor
    group system
EOT
}

function monit_def_sshd {
cat <<EOT >/etc/monit/conf.d/sshd.cfg
  check process sshd with pidfile /var/run/sshd.pid
    start program "/etc/init.d/ssh start"
    stop program "/etc/init.d/ssh stop"
    # if failed port 22 protocol ssh then restart
    # if 3 restarts within 3 cycles then timeout
EOT
}

function monit_def_ping_google {
cat <<EOT >/etc/monit/conf.d/ping_google.cfg
  check host google-ping with address google.com
    if failed port 80 proto http then alert
    group server
EOT
}

function monit_def_postfix {
cat <<EOT >/etc/monit/conf.d/postfix.cfg
  check process postfix with pidfile /var/spool/postfix/pid/master.pid
    start program = "/etc/init.d/postfix start"
    stop  program = "/etc/init.d/postfix stop"
    if cpu > 60% for 2 cycles then alert
    if cpu > 80% for 5 cycles then restart
    if totalmem > 200.0 MB for 5 cycles then restart
    if children > 250 then restart
    if loadavg(5min) greater than 10 for 8 cycles then stop
    if failed host localhost port 25 protocol smtp with timeout 15 seconds then alert
    if failed host localhost port 25 protocol smtp for 3 cycles then restart
    if 3 restarts within 5 cycles then timeout
    group mail

  check file postfix_rc with path /etc/init.d/postfix
    if failed checksum then unmonitor
    if failed permission 755 then unmonitor
    if failed uid root then unmonitor
    if failed gid root then unmonitor
    group mail
EOT
}


function monit_def_postgresql {
cat <<EOT >/etc/monit/conf.d/postgresql.cfg
  check process postgres with pidfile /var/run/postgresql/9.1-main.pid
    start program = "/etc/init.d/postgresql start"
    stop program = "/etc/init.d/postgresql stop"
    if failed unixsocket /var/run/postgresql/.s.PGSQL.5432 protocol pgsql then restart
    if failed host localhost port 5432 protocol pgsql then restart
    if 5 restarts within 5 cycles then timeout
    depends on postgresql_bin
    depends on postgresql_rc
    group database

  check file postgresql_bin with path /usr/lib/postgresql/9.1/bin/postgres
    if failed checksum then unmonitor
    if failed permission 755 then unmonitor
    if failed uid root then unmonitor
    if failed gid root then unmonitor
    group database

  check file postgresql_rc with path /etc/init.d/postgresql
    if failed checksum then unmonitor
    if failed permission 755 then unmonitor
    if failed uid root then unmonitor
    if failed gid root then unmonitor
    group database

  check file postgresql_log with path /var/log/postgresql/postgresql-9.1-main.log
    if size > 100 MB then alert
    group database
EOT
}

function monit_def_mysql {
cat <<EOT > /etc/monit/conf.d/mysql.cfg
  check process mysqld with pidfile /var/run/mysqld/mysqld.pid
    start program = "/sbin/start mysql" with timeout 20 seconds
    stop program = "/sbin/stop mysql"
    if failed host localhost port 3306 protocol mysql then restart
    if failed unixsocket /var/run/mysqld/mysqld.sock protocol mysql then restart
    if 5 restarts within 5 cycles then timeout
    depends on mysql_bin
    depends on mysql_rc
    group database

  check file mysql_bin with path /usr/sbin/mysqld
    if failed checksum then unmonitor
    if failed permission 755 then unmonitor
    if failed uid root then unmonitor
    if failed gid root then unmonitor
    group database

  check file mysql_rc with path /etc/init.d/mysql
    if failed checksum then unmonitor
    if failed permission 755 then unmonitor
    if failed uid root then unmonitor
    if failed gid root then unmonitor
    group database
EOT
}

function monit_def_mongodb {
cat <<EOT >/etc/monit/conf.d/mongodb.cfg
  check process mongodb with pidfile /var/lib/mongodb/mongod.lock
    start program = "/sbin/start mongodb"
    stop  program = "/sbin/stop mongodb"
    if failed host localhost port 28017 protocol http
      and request "/" with timeout 10 seconds then restart
    if 5 restarts within 5 cycles then timeout
    group database
EOT
}

function monit_def_memcached {
cat <<EOT >/etc/monit/conf.d/memcached.cfg
  check process memcached with pidfile /var/run/memcached.pid
    start program = "/etc/init.d/memcached start"
    stop program = "/etc/init.d/memcached stop"
    if 5 restarts within 5 cycles then timeout
    group database
EOT
}

function monit_def_apache {
cat <<EOT >/etc/monit/conf.d/apache2.cfg
  check process apache with pidfile /var/run/apache2.pid
    start program = "/etc/init.d/apache2 start"
    stop  program = "/etc/init.d/apache2 stop"
    if cpu > 60% for 2 cycles then alert
    if cpu > 80% for 5 cycles then alert
    if totalmem > 200.0 MB for 5 cycles then alert
    if children > 250 then alert
    if loadavg(5min) greater than 10 for 8 cycles then stop
    if failed host localhost port 80 protocol HTTP request / within 2 cycles then alert
    if failed host localhost port 80 protocol apache-status
        dnslimit > 25% or  loglimit > 80% or waitlimit < 20% retry 2 within 2 cycles then alert
    #if 5 restarts within 5 cycles then timeout
    depends on apache_bin
    depends on apache_rc
    group www

  check file apache_bin with path /usr/sbin/apache2
    if failed checksum then unmonitor
    if failed permission 755 then unmonitor
    if failed uid root then unmonitor
    if failed gid root then unmonitor
    group www

  check file apache_rc with path /etc/init.d/apache2
    if failed checksum then unmonitor
    if failed permission 755 then unmonitor
    if failed uid root then unmonitor
    if failed gid root then unmonitor
    group www
EOT
}

function monit_def_www {
cat <<EOT >/etc/monit/conf.d/www.cfg
  check process www with pidfile /var/run/www.pid
    start program = "/etc/init.d/www start"
    stop  program = "/etc/init.d/www stop"
    if cpu > 60% for 2 cycles then alert
    if cpu > 80% for 5 cycles then alert
    if totalmem > 200.0 MB for 5 cycles then alert
    if children > 250 then alert
    if loadavg(5min) greater than 10 for 8 cycles then stop
    if failed host localhost port 80 protocol HTTP request / within 2 cycles then alert
#    if failed host localhost port 80 protocol apache-status
#        dnslimit > 25% or  loglimit > 80% or waitlimit < 20% retry 2 within 2 cycles then alert
    if 5 restarts within 5 cycles then timeout
    depends on www_bin
    depends on www_rc
    group www

  check file www_bin with path /usr/local/bin/www
    if failed checksum then unmonitor
    if failed permission 755 then unmonitor
    if failed uid root then unmonitor
    if failed gid root then unmonitor
    group www

  check file www_rc with path /etc/init.d/www
    if failed checksum then unmonitor
    if failed permission 755 then unmonitor
    if failed uid root then unmonitor
    if failed gid root then unmonitor
    group www

  check host listenmindfully-org-ping with address listenmindfully.org
    if failed port 80 proto http then alert
    group server

  check host www-listenmindfully-com-ping with address www.listenmindfully.com
    if failed port 80 proto http then alert
    group server

  check host www-personal-integrity-org-ping with address www.personal-integrity.org
    if failed port 80 proto http then alert
    group server

EOT
}

function monit_def_haproxy {
cat <<EOT >/etc/monit/conf.d/haproxy.cfg
  check process haproxy with pidfile /var/run/haproxy.pid
    start program = "/etc/init.d/haproxy start"
    stop  program = "/etc/init.d/haproxy stop"
    if cpu > 60% for 2 cycles then alert
    if cpu > 80% for 5 cycles then alert
    if totalmem > 200.0 MB for 5 cycles then alert
    if children > 250 then alert
    if loadavg(5min) greater than 10 for 8 cycles then stop
#    if failed host localhost port 80 protocol HTTP request / within 2 cycles then alert
#    if failed host localhost port 80 protocol apache-status
#        dnslimit > 25% or  loglimit > 80% or waitlimit < 20% retry 2 within 2 cycles then alert
    if 5 restarts within 5 cycles then timeout
    depends on haproxy_bin
    depends on haproxy_rc
    depends on haproxy_cfg
    group haproxy

  check file haproxy_bin with path /usr/sbin/haproxy
    if failed checksum then unmonitor
    if failed permission 755 then unmonitor
    if failed uid root then unmonitor
    if failed gid root then unmonitor
    group haproxy

  check file haproxy_rc with path /etc/init.d/haproxy
    if failed checksum then unmonitor
    if failed permission 755 then unmonitor
    if failed uid root then unmonitor
    if failed gid root then unmonitor
    group haproxy

  check file haproxy_cfg with path /etc/haproxy/haproxy.cfg
    if failed checksum then unmonitor
    if failed permission 755 then unmonitor
    if failed uid root then unmonitor
    if failed gid root then unmonitor
    group haproxy
EOT
}

###########################################################
# Postfix
###########################################################

function postfix_install {

    echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
    echo "postfix postfix/mailname string localhost" | debconf-set-selections
    echo "postfix postfix/destinations string localhost.localdomain, localhost" | debconf-set-selections
    aptitude -y install postfix

    # http://askubuntu.com/questions/418340/how-to-secure-postfix-on-ubuntu-server
    chmod 755 /etc/postfix
    chmod 644 /etc/postfix/*.cf
    chmod 755 /etc/postfix/postfix-script*
    chmod 755 /var/spool/postfix
    chown root:root /var/log/mail*
    chmod 600 /var/log/mail*

    /usr/sbin/postconf -e "smtpd_banner = mail.listenmindfully.org"
    /usr/sbin/postconf -e "myhostname = mail"
    /usr/sbin/postconf -e "mydomain = listenmindfully.org"
    /usr/sbin/postconf -e "myorigin = listenmindfully.org"
    /usr/sbin/postconf -e "inet_interfaces = $(system_primary_ip) 127.0.0.1"
    /usr/sbin/postconf -e "mydestination = mail"
    /usr/sbin/postconf -e "mynetworks = 127.0.0.1"
    /usr/sbin/postconf -e "virtual_alias_maps = hash:/etc/postfix/virtual/addresses"
    /usr/sbin/postconf -e "relay_domains ="
    /usr/sbin/postconf -e "default_process_limit = 100"
    /usr/sbin/postconf -e "smtpd_client_connection_count_limit = 10"
    /usr/sbin/postconf -e "smtpd_client_connection_rate_limit = 30"
    /usr/sbin/postconf -e "queue_minfree = 20971520"
    /usr/sbin/postconf -e "header_size_limit = 51200"
    /usr/sbin/postconf -e "message_size_limit = 10485760"
    /usr/sbin/postconf -e "smtpd_recipient_limit = 100"

    mkdir /etc/postfix/virtual
    chmod 755 /etc/postfix/virtual

# forward everything
cat > /etc/postfix/virtual/addresses <<EOD
listenmindfully.org DOMAIN
@listenmindfully.org ${NOTIFY_EMAIL}
listenmindfully.com DOMAIN
@listenmindfully.com ${NOTIFY_EMAIL}
personal-integrity.org DOMAIN
mary.cobb@personal-integrity.org mary.bernice.cobb@gmail.com
@personal-integrity.org ${NOTIFY_EMAIL}
EOD
    chmod 644 /etc/postfix/virtual/addresses
    postmap /etc/postfix/virtual/addresses

    touch /tmp/restart-postfix
}


set -e
set -u
#set -x

exec &> /root/stackscript.log

system_update

# Configure system
system_update_hostname "$SYS_HOSTNAME"

# Create user account
system_add_user "$USER_NAME" "$USER_PASSWORD" "$USER_GROUPS" "$USER_SHELL"
if [ "$USER_SSHKEY" ]; then
    system_user_add_ssh_key "$USER_NAME" "$USER_SSHKEY"
fi

# Configure sshd
system_sshd_permitrootlogin "$SSHD_PERMITROOTLOGIN"
system_sshd_passwordauthentication "$SSHD_PASSWORDAUTH"
touch /tmp/restart-ssh

# Lock user account if not used for login
if [ "SSHD_PERMITROOTLOGIN" == "No" ]; then
    system_lock_user "root"
fi

# Install Postfix
postfix_install

# Setup logcheck
system_security_logcheck

# Setup fail2ban
system_security_fail2ban

# Setup firewall
system_security_ufw_configure_basic

system_install_utils

system_install_build

#python_install

#ansible_install

git_install

node_install

www_install

haproxy_install

# Install MongoDB
if [ "$SETUP_MONGODB" == "Yes" ]; then
    mongodb_install
fi

restart_services
restart_initd_services

if [ "$SETUP_MONIT" == "Yes" ]; then
    monit_install

    monit_configure_email "$NOTIFY_EMAIL"
    monit_configure_web $(system_primary_ip)

    monit_def_system "$SYS_HOSTNAME"
    monit_def_rootfs
    monit_def_cron
    monit_def_postfix
    monit_def_ping_google
    monit_def_www
    monit_def_haproxy
    if [ "$SETUP_MONGODB" == "Yes" ]; then monit_def_mongodb; fi
    monit reload
fi

# Send info message
RDNS=$(system_primary_ip)
cat > ~/setup_message <<EOD
Hi,

Your Linode VPS configuration is completed.

EOD

if [ "$SETUP_MONIT" == "Yes" ]; then
    cat >> ~/setup_message <<EOD
Monit web interface is at http://${RDNS}:2812/ (use your system username/password).

EOD
fi

cat >> ~/setup_message <<EOD
To access your server ssh to $USER_NAME@$RDNS

EOD

mail -s "Your Linode VPS is ready" "$NOTIFY_EMAIL" < ~/setup_message