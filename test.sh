for file in pcap/*; do
	out="$(./nward -f $file $@)"
	if [ -z "$out" ]; then
		echo "NO SCANS FOUND IN $file"
	else
		echo "$(echo "$out" | sed -n '/- warning -/!p' | wc -l) SCAN PACKETS DETECTED IN $file"
	fi
done
