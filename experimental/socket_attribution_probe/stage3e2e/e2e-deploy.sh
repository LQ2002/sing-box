#!/system/bin/sh
# Install the pushed build into the test directory and restart the test instance.
sh /data/local/tmp/sbe2/e2e-ctl.sh stop
cp /data/local/tmp/sbe2/sing-box-new /data/local/tmp/sbe2/e2e/sing-box
chmod 755 /data/local/tmp/sbe2/e2e/sing-box
/data/local/tmp/sbe2/e2e/sing-box version | head -1
sh /data/local/tmp/sbe2/e2e-ctl.sh start | grep -E "pid=|started|FATAL"
