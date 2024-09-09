#!/bin/sh

# Test script for placer-source-http
#
# Here is how it should work:
# - Read list of URLs to fetch from STDIN, separated by newlines, until a single
#   blank line is observed (with "\n" as the newline indicator) which indicates
#   the end of the URL list
# - Fetch URLs on a regular interval (e.g. 30s). Ideally use ETags to avoid
#   repeat fetches of the same file
# - If file is new (or fetched for the first time), print the following:
#   1. A line with "[LENGTH] [URI]" where [LENGTH] is the length of the file
#      in bytes as a decimal (e.g. 1048576 for a 1MB file) and [URI] is the
#      location the file was fetched from
#   2. The entirety of the fetched file, followed by a "\n" newline
# - If any errors occur, print a one-liner error message to STDERR
#

IFS='\n' read -r -d '' EXAMPLE_URLS <<EOD
https://gist.githubusercontent.com/tarcieri/d76f89429f9324e05a10465b835bcb77/raw/4f7a4ba600966ce52a57cceda30ace59563650e1/gistfile1.txt
https://gist.githubusercontent.com/tarcieri/d76f89429f9324e05a10465b835bcb77/raw/4f7a4ba600966ce52a57cceda30ace59563650e1/gistfile2.txt
https://www.random.org/integers/?num=1&min=0&max=1000000000&col=1&base=10&format=plain&rnd=new

derp derp derp
nothing to see here
EOD

echo "$EXAMPLE_URLS" | cargo run
