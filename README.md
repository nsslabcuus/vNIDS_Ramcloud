
# vNIDS_Ramcloud Project

This is the project for the paper: vNIDS: Towards Elastic Security with Safe and Efficient Virtualization of Network Intrusion Detection System.

This project based on the Click System.

> Click is a modular router toolkit. To use it you'll need to know how to compile and install the software, how to write router configurations, and how to write new elements. This is the Click system office repo link: [Click System](https://github.com/kohler/click)

**Hint**: Please use Ubuntu 16.04 or Ubuntu 14.04 because we have tested this project in these two Ubuntu versions.

## Installing the RAMCloud client

We have changed some code based on the Ramcloud project. So you need to install the Ramcloud from our repo if you want to get an easy way to use our project. You can access this repo's page: [Ramcloud](https://bitbucket.org/guozetang/ramcloud/src/master/)

```bash
git clone https://guozetang@bitbucket.org/guozetang/ramcloud.git
cd ramcloud
sudo su
./install.sh
```

If it doesn't finish the installing of RAMCloud, please input the command as follow.

```bash
source /etc/profile
./install_ramcloud.sh
```

Update the PATH

```bash
source /etc/profile
ldconfig
ldconfig -p | grep ramcloud
```

If you can find the dynamic link library  `libramcloud.so`, then it means that you have installed the RAMCloud client on your instance. And you can continue the next steps.

## Build vNIDS_Ramcloud with RAMCloud client

Then configure and build the vNIDS_Ramcloud project with Ramcloud in the project base folder.

```bash
./configure LIBS="-lramcloud -L/usr/local/lib/ramcloud" --disable-linuxmodule
make -j $(getconf _NPROCESSORS_ONLN) userlevel
```

## Get Documentation

`cd doc; make doxygen O=html; cd ..`

This will generate HTML documentation in  `html`  folder. You can open the index.html in a browser.

## Test the Click using the click config file

After you build the click, you can change the click file to run it. There is an example of how to test the click system. In the `ramcloud_test.click` file, you just need to change the mac addresses and ip addresses which depended on your experimental environment.

```bash
define($src_mac 90:e2:ba:ac:18:bc)
define($dst_mac 90:e2:ba:b3:20:e0)
define($IN_device ovs-lan)

define($RAMSERVER "tcp:host=10.10.1.4,port=11100")
define($RAMNAME "__unnamed__")
```

So, please change the `$src_mac`, `$dst_mac`, `$IN_device`, `$RAMSERVER` and `$RAMNAME` by yourself.

After you changed this file, you can run click as follow.

```bash
./bin/click ramcloud_test.click
```

## Bugs, Questions, etc

We welcome bug reports, questions, comments, code, whatever you'd like to give us. GitHub issues are the best way to stay in touch.

<!-- 
## vids scripts

Before setting the nic, you should have a bridge named ovs-lan in your ovs. Run  `ovs-vsctl show`  to figure out.

If ovs-lan bridge is showing in the previous results, setup nic

`exps/userlevel/vids/bin/set_nics.sh 2`

This script will add 2 pairs of network interfaces, and change their mac addresses.

### Run lw

`ip netns exec click_ns_1 bin/click exps/userlevel/vids/conf/lw.click`

### Run hw

`ip netns exec click_ns_2 bin/click exps/userlevel/vids/conf/hw.click`

## FAQ -->