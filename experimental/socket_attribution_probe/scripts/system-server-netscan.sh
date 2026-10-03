# All jars/apks whose dex system_server has mapped, then the same static
# scan for network API call sites, plus HandlerThread names in those classes.
P=$(pidof system_server)
JARS=$(grep -oE '/[^ ]+\.(jar|apk)$' /proc/$P/maps | sort -u)
echo "MAPPED $(echo "$JARS" | wc -l)"
PAT='Ljava/net/URL;\.openConnection|Ljava/net/URL;\.openStream|Lcom/android/okhttp/OkHttpClient|Lokhttp3/OkHttpClient;\.newCall|Ljava/net/DatagramSocket;\.<init>|Ljava/net/Socket;\.connect|Landroid/net/Network;\.openConnection|Lorg/apache/http/impl/client/DefaultHttpClient;\.<init>'
for jar in $JARS; do
  out=$(/apex/com.android.art/bin/dexdump -d "$jar" 2>/dev/null | awk -v pat="$PAT" '
    /^  Class descriptor/ { cls=$4; gsub(/\x27/,"",cls) }
    /^    #[0-9]+ +: \(in / { inm=1; next }
    inm && /^      name/ { m=$3; gsub(/\x27/,"",m); inm=0 }
    /invoke-/ && $0 ~ pat { api=$0; sub(/.*, L/,"L",api); sub(/:.*/,"",api); key=cls"->"m"  calls  "api; if (!(key in seen)) { seen[key]=1; print key } }
  ' | grep -vE "mockito|Lkotlin/|apache/commons|InlineDexmaker|jarjar/kotlin")
  [ -n "$out" ] && { echo "##### $jar"; echo "$out"; }
done
