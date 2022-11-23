#!/bin/bash
#curl --cacert /usr/share/arkime/config/certs/certificates/ca/ca.crt "https://elastic:123qweASD@localhost:9200"
# echo "Initializing db on ES..."
# echo INIT | /opt/arkime/db/ 


#perl db.pl --clientcert /usr/share/arkime/config/certs/certificates/ca/ca.crt --esuser 'elastic':'123qweASD' "https://elastic:123qweASD@localhost:9200" init

# perl db.pl --clientcert /usr/share/arkime/config/certs/certificates/arkime/arkime.crt --clientkey /usr/share/arkime/config/certs/certificates/arkime/arkime.key -vvv --insecure --esuser elastic:123qweASD https://localhost:9200 init

#$ARKIMEDIR/db/db.pl https://elastic:123qweASD@127.0.0.1:9200 init --clientcert /usr/share/arkime/config/certs/certificates/ca/ca.crt


echo "Giving OS time to start..."
until curl --cacert /usr/share/arkime/config/certs/certificates/ca/ca.crt -sS "https://elastic:123qweASD@127.0.0.1:9200/_cluster/health?wait_for_status=yellow" > /dev/null 2>&1
do
    echo "Waiting for OS to start"
    sleep 1
done
echo
echo "OS started..."


# set runtime environment variables
export ARKIME_PASSWORD=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w32 | head -n1)  # random password
export ARKIME_LOCALELASTICSEARCH=no
export ARKIME_ELASTICSEARCH="https://"$OS_HOST":"$OS_PORT
export ARKIME_INET=no

if [ ! -f $ARKIMEDIR/etc/.initialized ]; then
    echo "Configuring......."
    echo -e "$ARKIME_LOCALELASTICSEARCH\n$ARKIME_INET" | $ARKIMEDIR/bin/Configure
    echo INIT | $ARKIMEDIR/db/db.pl --clientcert /usr/share/arkime/config/certs/certificates/arkime/arkime.crt --clientkey /usr/share/arkime/config/certs/certificates/arkime/arkime.key --insecure --esuser elastic:123qweASD https://localhost:9200 init
    $ARKIMEDIR/bin/arkime_add_user.sh admin "Admin User" $ARKIME_ADMIN_PASSWORD --admin
    echo $ARKIME_VERSION > $ARKIMEDIR/etc/.initialized
else
    # possible update
    read old_ver < $ARKIMEDIR/etc/.initialized
    # detect the newer version
    newer_ver=`echo -e "$old_ver\n$ARKIME_VERSION" | sort -rV | head -n 1`
    # the old version should not be the same as the newer version
    # otherwise -> upgrade
    if [ "$old_ver" != "$newer_ver" ]; then
        echo "Upgrading OS database..."
        echo -e "$ARKIME_LOCALELASTICSEARCH\n$ARKIME_INET" | $ARKIMEDIR/bin/Configure
        $ARKIMEDIR/db/db.pl --clientcert /usr/share/arkime/config/certs/certificates/arkime/arkime.crt --clientkey /usr/share/arkime/config/certs/certificates/arkime/arkime.key --insecure --esuser elastic:123qweASD https://localhost:9200 init upgradenoprompt
        echo $ARKIME_VERSION > $ARKIMEDIR/etc/.initialized
    fi
fi
#echo INIT | $ARKIMEDIR/db/db.pl https://$OS_HOST:$OS_PORT init
#exec $ARKIMEDIR/db/db.pl http://$OS_HOST:$OS_PORT upgrade


# start cron daemon for logrotate
service cron start

if [ "$CAPTURE" = "on" ]
then
    echo "Launch capture..."
    if [ "$VIEWER" = "on" ]
    then
        # Background execution
        exec $ARKIMEDIR/bin/capture --config $ARKIMEDIR/etc/config.ini --host $ARKIME_HOSTNAME >> $ARKIMEDIR/logs/capture.log 2>&1 &
    else
        # If only capture, foreground execution
        exec $ARKIMEDIR/bin/capture --config $ARKIMEDIR/etc/config.ini --host $ARKIME_HOSTNAME >> $ARKIMEDIR/logs/capture.log 2>&1
    fi
fi

echo "Look at log files for errors"
echo "  /data/logs/viewer.log"
echo "  /data/logs/capture.log"
echo "Visit http://127.0.0.1:8005 with your favorite browser."
echo "  user: admin"
echo "  password: $ARKIME_ADMIN_PASSWORD"

if [ "$VIEWER" = "on" ]
then
    echo "Launch viewer..."
    pushd $ARKIMEDIR/viewer
    exec $ARKIMEDIR/bin/node viewer.js -c $ARKIMEDIR/etc/config.ini --host $ARKIME_HOSTNAME >> $ARKIMEDIR/logs/viewer.log 2>&1
    popd
fi

# /opt/arkime/bin/node viewer.js -c /opt/arkime/etc/config.ini --host http://127.0.0.1:8006