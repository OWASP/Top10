#!/bin/bash
# Sum up how many "interactions" each user has had with the issues. 
# An interaction is either creation of or commenting on an issue.
# To use for future releases, some functionality will need to be added to
# filter by release or timeframe or something.

if [ $# -ne 2 ]; then
    echo 1>&2 "usage: $0 <username> <password>"
    echo 1>&2 "   You may wish to pass a personal access token instead of your password. See https://github.com/settings/tokens for details."
    exit 1
fi
USERNAME="$1"
PASSWORD="$2"
APIROOT="https://api.github.com"
OWNER="OWASP"
REPO="Top10"
CURL="curl"

case "$OS" in
    Win*) 
        JQ="./jq-win64.exe"
        ;;
    SOMETHING)
         JQ="./jq-osx-amd64"
        ;;
    SOMETHING) 
        JQ="./jq-linux64"
        ;;
    *)
        echo 1>&2 "What OS are we on?"
        exit 1
        ;;
esac

doit() {
    "$CURL" --silent -u "$USERNAME:$PASSWORD" "$APIROOT/repos/$OWNER/$REPO/$1"
}

# get the highest issue number
MAXISSUE=$(doit "issues?state=all" | grep '"number":'  | head -1 | sed -e 's/^.*: //' -e 's/,.*$//')
if [ -z "$MAXISSUE" ]; then
    echo 1>&2 "Couldn't calculate MAXISSUE"
    exit 1;
fi
# echo 1>&2 "MAXISSUE=$MAXISSUE"

users=""
# To simplify the code, we're just going to run through all issues, 1..$MAXISSUE.
# We'll deal with any deleted issues as we run into them.
issue=1
while [ $issue -le $MAXISSUE ]; do
    # Get issue author
    echo 1>&2 "Processing issue $issue."
    author=$(doit "issues/$issue" | "$JQ" '{user} | {data: .user.login}' | grep 'data' | sed -e 's/^.*data": "//' -e 's/"//')
    # make sure issue exists before proceeding to parse it - see comment above
    if [ -n "$author" ]; then 
        # echo 1>&2 "author ($issue)=$author"
        commentors=$(doit "issues/$issue/comments" | ./jq-win64.exe '.[] | {user: .user.login}' | sed 's/"user": //g' | tr '{}\n\r"' '     ')
        users="$author $commentors $users"
    else
        echo 1>&2 "Skipping deleted issue $issue."
    fi
    let issue+=1
done

echo "$users" |  sed --regexp-extended -e 's/\s+/ /g' -e 's/^ *//' | tr ' ' '\n' | sort | uniq -c | sort -r
