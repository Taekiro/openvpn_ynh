#!/bin/bash

#=================================================
# COMMON VARIABLES
#=================================================

# dependencies used by the app
pkg_dependencies="php7.0-fpm openvpn openvpn-auth-ldap netmask"

service_name="openvpn"

#============================================================
# Specific to openvpn
#============================================================

check_iptables () {
    # Check if iptables is working
    if !  iptables -L > /dev/null 2>&1; then
        ynh_die "iptables is not available in your environment, aborting..."
    fi
}

check_tun_available () {
    # Ensure tun device is available
    #if [[ ! -c /dev/net/tun ]]; then
    #    err "OpenVPN requires tun support, aborting..."
    #    exit 1
    #fi
    return 0
}

check_ip4ranges () {
    _255='(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)'
    ip4regex=(${_255}\.){3}${_255}
    rangeip4regex="${ip4regex}(/(3[0-2]|[1-2][0-9]|[1-9]))?"
    regex="${rangeip4regex}([[:space:]]+${rangeip4regex})*"
    if [[ $1 =~ ^${regex}$ ]]; then
        return 0
    else
        ynh_die "Bad Ipv4 ranges format, aborting..."
    fi
}


configure_firewall () {
    ip4ranges=$(ynh_app_setting_get $app ip4ranges | tr " " "\n")
    iface=$(ynh_app_setting_get $app iface)
    iptables -t filter -$1 FORWARD -i "${iface}" -o tun0 -m state --state ESTABLISHED,RELATED -j ACCEPT
    for ip4range in $ip4ranges
    do
        if [[ "$1" = "A" ]];then
            if ! ( /sbin/iptables -L -t nat | grep $ip4range | grep MASQUERADE > /dev/null 2>&1); then
                iptables -t nat -$1 POSTROUTING -s $ip4range -o "${iface}" -j MASQUERADE
                iptables -t filter -$1 FORWARD -s $ip4range -o "${iface}" -j ACCEPT
            fi
        elif [[ "$1" = "D" ]]; then
            if (/sbin/iptables -L -t nat | grep $ip4range | grep MASQUERADE > /dev/null 2>&1); then
                iptables -t nat -$1 POSTROUTING -s $ip4range -o "${iface}" -j MASQUERADE
                iptables -t filter -$1 FORWARD -s $ip4range -o "${iface}" -j ACCEPT
            fi
        fi
    done
}

add_firewall_rules () {
    configure_firewall A
}

rm_firewall_rules () {
    configure_firewall D
}

deduce_gateway () {

    first_ip4_range=$(echo $ip4ranges | cut -f1 -d" ")
    first_ip=$(netmask -r $first_ip4_range | cut -f1 -d"-" )
    first_ip=$( netmask -x $first_ip )
    first_ip=$(( $first_ip + 1 ))
    export first_ip4=$( netmask $first_ip )
    export last_ip4=$(netmask -r $first_ip4_range | cut -f2 -d"-" )
    first_ip4_range=$(netmask -s $first_ip4_range)
    export gateway_ip4=$(echo $first_ip4_range | cut -f1 -d"/")
    export gateway_mask=$(echo $first_ip4_range | cut -f2 -d"/")
}

install_files () {
    # Make directories and set rights
    mkdir -p /etc/openvpn/auth \
        /etc/openvpn/users \
        "${final_path}" \
        /var/log/openvpn
    touch /var/log/openvpn/status.log
    touch /var/log/openvpn/server.log
    touch /etc/openvpn/users_settings.csv

    # Copy web files
    cp -a ../sources/. $final_path

    # Configurations
    set +x
    export ca_yunohost=$(cat /etc/ssl/certs/ca-yunohost_crt.pem)
    export ta_key=$(cat /etc/openvpn/ta.key)
    export domain=$domain
    export port=$port
    export dedicated_ip=$dedicated_ip
    set -x
    install -b -o root -g root -m 0644 ../conf/server.conf.j2 /etc/openvpn/
    install -b -o root -g root -m 0644 ../conf/client.conf.j2 /etc/openvpn/
    install -b -o root -g root -m 0644 ../conf/client.ovpn.j2 /etc/openvpn/
    install -b -o root -g root -m 0644 ../conf/ldap.conf /etc/openvpn/auth/
    ln -s /etc/ssl/certs/ca-yunohost_crt.pem "${final_path}/ca.crt"
    cp ../conf/handler.sh /etc/openvpn/handler.sh
    touch /etc/openvpn/crl.pem
    echo "$ip4ranges" | tee /etc/openvpn/ip4ranges

    # IP forwarding
    install -b -o root -g root -m 0644 ../conf/sysctl /etc/sysctl.d/openvpn.conf
}

setup_and_restart () {
    # Find gateway ip and mask and save it
    deduce_gateway
    ynh_app_setting_set "$app" gateway_ip4 $gateway_ip4
    ynh_app_setting_set "$app" gateway_mask $gateway_mask

    # Open port in firewall
    if [ -z $dedicated_ip ]; then
        yunohost firewall allow Both $port > /dev/null 2>&1
    fi

    # Create user
    if ! ynh_system_user_exists ${user}; then
        ynh_system_user_create "$user" "/etc/openvpn/"
    fi
    if ! ynh_system_user_exists ${webuser}; then
        ynh_system_user_create "$webuser" "$final_path"
    fi

    # Ensure the system user has enough permissions
    install -b -o root -g root -m 0440 ../conf/sudoers.conf /etc/sudoers.d/${app}_ynh
    ynh_replace_string "__VPNCLIENT_SYSUSER__" "${user}" /etc/sudoers.d/${app}_ynh

    # Copy files
    install_files
    sysctl -p /etc/sysctl.d/openvpn.conf

    # Modify openvpn config files
    ynh_render_template /etc/openvpn/server.conf.j2 /etc/openvpn/server.conf
    ynh_render_template /etc/openvpn/client.conf.j2 "${final_path}/${domain}.conf"
    ynh_render_template /etc/openvpn/client.ovpn.j2 "${final_path}/${domain}.ovpn"

    # Permissions
    ynh_set_default_perm "${final_path}" $webuser
    chown -R $webuser:www-data "${final_path}"
    chown -R $user: /var/log/openvpn
    chown -R $user: /etc/openvpn
    chmod 640 /etc/openvpn/users_settings.csv
    chmod u+x /etc/openvpn/handler.sh
    # Add OpenVPN to YunoHost's monitored services
    yunohost service add openvpn --log /var/log/openvpn/status.log

    # Ensure that tun device is still available, otherwise try to create it manually
    if [[ ! -c /dev/net/tun ]]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 666 /dev/net/tun
    fi

    # Add masquerade rules
    add_firewall_rules

    # Let's go !
    yunohost service enable openvpn
    yunohost service start openvpn
}


#============================================================
# Common helpers
#============================================================

ynh_check_var () {
    test -n "$1" || ynh_die "$2"
}

# Create a database, an user and its password. Then store the password in the app's config
#
# User of database will be store in db_user's variable.
# Name of database will be store in db_name's variable.
# And password in db_pwd's variable.
#
# usage: ynh_mysql_generate_db user name
# | arg: user - Proprietary of the database
# | arg: name - Name of the database
ynh_mysql_generate_db () {
    export db_user=${1//[-.]/_}    # Mariadb doesn't support - and . in the name of databases. It will be replace by _
    export db_name=${2//[-.]/_}

    export db_pwd=$(ynh_string_random) # Generate a random password
    ynh_check_var "$db_pwd" "db_pwd empty"

    ynh_mysql_create_db "$db_name" "$db_user" "$db_pwd" # Create the database

    ynh_app_setting_set $app mysqlpwd $db_pwd   # Store the password in the app's config
}

# Execute a command as another user
# usage: ynh_exec_as USER COMMAND [ARG ...]
ynh_exec_as() {
  local USER=$1
  shift 1

  if [[ $USER = $(whoami) ]]; then
    eval "$@"
  else
    # use sudo twice to be root and be allowed to use another user
    sudo sudo -u "$USER" "$@"
  fi
}

# Get sources, setup it into dest directory and deploy patches
# Try to find locally the sources and download it if missing.
# Check the integrity with an hash program (default: sha256sum)
# Source hash and location are get from a "SOURCE_ID.src" file,
# by default the SOURCE_ID is "app".
# Patches should be located in a "patches" dir, they should be
# named like "SOURCE_ID-*.patch".
#
# example: ynh_setup_source "/var/www/limesurvey/" "limesurvey"
#
# usage: ynh_setup_source DEST_DIR [USER [SOURCE_ID]]

ynh_setup_source () {
    local DEST=$1
    local AS_USER=${2:-admin}
    local SOURCE_ID=${3:-app}
    local SOURCE_FILE="$YNH_APP_ID.tar.gz"
    local SUM_PRG="sha256sum"
    source ../$SOURCE_ID.src
    local LOCAL_SOURCE="/opt/yunohost-apps-src/$YNH_APP_ID/$SOURCE_FILE"

    if test -e $LOCAL_SOURCE; then
        cp $LOCAL_SOURCE $SOURCE_FILE
    else
        wget -nv $SOURCE_URL -O $SOURCE_FILE
    fi
    echo "$SOURCE_SUM $SOURCE_FILE" |$SUM_PRG -c --status \
        || ynh_die "Corrupt source"

    mkdir -p "$DEST"
    chown $AS_USER: "$DEST"
    if [ "$(echo ${SOURCE_FILE##*.})" == "gz" ]; then
        ynh_exec_as "$AS_USER" tar xf $SOURCE_FILE -C "$DEST" --strip-components 1
    elif [ "$(echo ${SOURCE_FILE##*.})" == "bz2" ]; then
        ynh_exec_as "$AS_USER" tar xjf $SOURCE_FILE -C "$DEST" --strip-components 1
    elif [ "$(echo ${SOURCE_FILE##*.})" == "zip" ]; then
        mkdir -p "/tmp/$SOURCE_FILE"
        ynh_exec_as "$AS_USER" unzip -q $SOURCE_FILE -d "/tmp/$SOURCE_FILE"
        ynh_exec_as "$AS_USER" mv "/tmp/$SOURCE_FILE"/./. "$DEST"
        rmdir "$/tmp/$SOURCE_FILE"
    else
        false
    fi

    # Apply patches
    if [ -f patches/$SOURCE_ID-*.patch  ]; then
        (cd "$DEST" \
        && for p in patches/$SOURCE_ID-*.patch; do \
            ynh_exec_as "$AS_USER" patch -p1 < $p; done) \
            || ynh_die "Unable to apply patches"

    fi

    # Apply persistent modules (upgrade only)
    ynh_restore_persistent modules

    # Apply persistent data (upgrade only)
    ynh_restore_persistent data

}

# TODO support SOURCE_ID
ynh_save_persistent () {
    local TYPE=$1
    local DIR=/tmp/ynh-persistent/$TYPE/$app/app
    mkdir -p $DIR
    touch $DIR/dir_names
    shift
    i=1
    for PERSISTENT_DIR in $@;
    do
        if [ -e $final_path/$PERSISTENT_DIR  ]; then
            mv $final_path/$PERSISTENT_DIR $DIR/$i
            su -c "echo -n '$PERSISTENT_DIR ' >> $DIR/dir_names"
            ((i++))
        fi
    done
}

# TODO support SOURCE_ID
ynh_restore_persistent () {
    local TYPE=$1
    local DIR=/tmp/ynh-persistent/$TYPE/$app/app
    shift
    if [ -d $DIR  ]; then
        i=1
        for PERSISTENT_DIR in $(cat $DIR/dir_names);
        do
            if [ "$TYPE" = "modules" ]; then
                for updated_subdir in $(ls $final_path/$PERSISTENT_DIR);
                do
                    rm -Rf $DIR/$i/$updated_subdir
                done
            fi
            if [ -d $DIR/$i ]; then
                mv $DIR/$i/* $final_path/$PERSISTENT_DIR/ 2> /dev/null || true
            else
                mv $DIR/$i $final_path/$PERSISTENT_DIR 2> /dev/null || true
            fi
            ((i++))
        done
        rm -Rf $DIR
    fi

}
ynh_mv_to_home () {
    local APP_PATH="/home/yunohost.app/$app/"
    local DATA_PATH="$1"
    mkdir -p "$APP_PATH"
    chown $app: "$APP_PATH"
    ynh_exec_as "$app" mv "$DATA_PATH" "$APP_PATH"
    ynh_exec_as "$app" ln -s "$APP_PATH$DATA_PATH" "$DATA_PATH"

}

ynh_set_default_perm () {
    local DIRECTORY=$1
    local USER=$2
    # Set permissions
    chown -R $USER:$USER $DIRECTORY
    chmod -R 664 $DIRECTORY
    find $DIRECTORY -type d -print0 | xargs -0 chmod 775 \
        || echo "No file to modify"

}
ynh_sso_access () {
    ynh_app_setting_set $app unprotected_uris "/"

    if [[ $is_public -eq 0 ]]; then
        ynh_app_setting_set $app protected_uris "$1"
    fi
    yunohost app ssowatconf
}

ynh_exit_if_up_to_date () {
    if [ "${version}" = "${last_version}" ]; then
        info "Up-to-date, nothing to do"
        exit 0
    fi
}

to_logs() {

  # When yunohost --verbose or bash -x
  if $_ISVERBOSE; then
    cat
  else
    cat > /dev/null
  fi
}

ynh_read_json () {
    python3 -c "import sys, json;print(json.load(open('$1'))['$2'])"
}
