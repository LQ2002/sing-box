#!/system/bin/sh
set -eu
# Called by run-device.sh after unshare -n. All network writes stay here.
DIR=/data/local/tmp/sbo-identity-carrier-20261003
[ "$#" -ge 1 ]
main_netns=$1
shift
current_netns=$(readlink /proc/self/ns/net)
[ "$current_netns" != "$main_netns" ] || {
  echo "refusing to configure the original network namespace" >&2
  exit 1
}
ip link set lo up
echo "PRIVATE_NETNS=$current_netns"
ip -o address show dev lo
exec "$DIR/identity-carrier-probe" "$@"
