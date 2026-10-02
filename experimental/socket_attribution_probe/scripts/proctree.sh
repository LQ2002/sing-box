z=$(pidof zygote64); z32=$(pidof zygote); w=$(pidof webview_zygote)
for d in /proc/[0-9]*; do
  p=${d#/proc/}
  e=$(readlink $d/exe 2>/dev/null); [ -z "$e" ] && continue
  pp=$(sed 's/.*) //' $d/stat | cut -d' ' -f2)
  u=$(grep '^Uid:' $d/status | cut -f2)
  c=other
  if [ "$pp" = "$z" ] || [ "$pp" = "$z32" ]; then c=zygote_child
  elif [ -n "$w" ] && [ "$pp" = "$w" ]; then c=webview_zygote_child
  elif [ "$pp" = 1 ]; then c=init_child
  else
    pe=$(readlink /proc/$pp/exe 2>/dev/null)
    case "$pe" in *app_process*) c=child_of_app_process ;; esac
  fi
  echo "$c $u ${e##*/}"
done
