wsh
===

execute command in a Linux Container through unix socket

The orig wsh is copied from cloudfoundry/warden 

usage:

### 1. get wsh

mkdir $HOME/github

cd $HOME/github

git clone https://github.com/chenyf/wsh.git

### 2. build wsh
cd wsh

make

### 3. run container with wshd
mkdir share

cp wshd share/

sudo docker run -d -v $HOME/github/wsh/share:/share -t ubuntu:12.04 /share/wshd  --run /share

### 4. now you can execute command inside container from thie host

sudo ./wsh --socket $HOME/github/wsh/share/wshd.sock hostname
sudo ./wsh --socket $HOME/github/wsh/share/wshd.sock ls /

Have funs!






