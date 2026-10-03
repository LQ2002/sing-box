#!/system/bin/sh
# Cold-start check for creator_v2_probe: capture while two apps that are not
# running are launched, then return to the home screen. Nothing is killed.
DIR=/data/local/tmp/sbo-creator-v2-probe
sh $DIR/run-device.sh capture ${1:-75} > $DIR/coldstart.log 2>&1 &
runner=$!
sleep 8
for package in com.xiaomi.market com.android.browser; do
  echo "LAUNCH $package before_pid=$(pidof $package || echo none)" >> $DIR/coldstart-launch.log
  monkey -p $package -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
  sleep 20
  input keyevent KEYCODE_HOME
  echo "LAUNCHED $package pids=$(pidof $package) all=$(ps -A -o PID,NAME | grep $package | tr '\n' ' ')" >> $DIR/coldstart-launch.log
done
wait $runner
cat $DIR/coldstart-launch.log $DIR/coldstart.log
rm -f $DIR/coldstart-launch.log
