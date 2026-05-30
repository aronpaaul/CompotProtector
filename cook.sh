#!/bin/bash
# usage: cook.sh <infile> <outfile> <language>
infile="$1"; outfile="$2"; lang="${3:-rust}"
esc=$(perl -e 'local $/; my $s=<STDIN>; $s=~s/\\/\\\\/g; $s=~s/"/\\"/g; $s=~s/\n/\\n/g; $s=~s/\t/\\t/g; print $s' < "$infile")
cat > /tmp/body.json <<EOF
{"code":"$esc","settings":{"language":"$lang","theme":"night-owl","fontFamily":"JetBrains Mono","fontSize":"15px","lineNumbers":false,"windowControls":true,"paddingHorizontal":"44px","paddingVertical":"44px"}}
EOF
curl -s -m 60 -X POST "https://sourcecodeshots.com/api/image" -H "Content-Type: application/json" --data @/tmp/body.json -o "$outfile" -w "  -> $outfile http=%{http_code} size=%{size_download}\n"
