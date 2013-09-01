wsh
===

execute command in a Linux Container through unix socket
wsh is copied from cloudfoundry/warden 

usage:

1. create a Linux Container use your favirate way, for example: docker. The import thing is you need binding mount a
directory inside container, assume /tmp/hostdir --> /tmp/guestdir 

1. inside containr:

wshd --run /tmp/guestdir -d

this command will create a unix socket file:  /tmp/guestdir/wshd.sock 

2. on the host, now you can execute command inside container like this:

wsh --socket /tmp/hostdir/wshd.sock  ps auxf

wsh --socket /tmp/hostdir/wshd.sock  echo "hello"

wsh --socket /tmp/hostdir/wshd.sock  /bin/bash

