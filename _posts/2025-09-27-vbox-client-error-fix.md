Written by [Deesick](https://hackwithdeesick.com/about/)
## Introduction

If you use Linux on VirtualBox as much as I do, you may encounter an issue when you boot into your machine at some point and you get an error “VBoxClient: the VirtualBox Kernel service is not running. Exiting”

![[001.jpg]]

When you get this issue, your clipboard, terminal and a few other features may stop functioning normally. There are a few ways to resolve this. One way is to simply navigate to the mounted .iso location on your linux machine, and run the VBoxAdditions script with:

```
cd /media/cdrom0
sudo ./VBoxLinuxAdditions.run
```

That should fix the issue automatically but in case this doesn’t work and you get a “permission denied” error, you might want to check permissions and add execute permissions rights:

```
ls -la
chmod +x VBoxLinuxAdditions.run
```

If you run this and you still get “permission denied” error, it may be because of your shell type. If your default shell is zsh, try explicitly invoking the shell to run the script with:

```
sudo sh ./VBoxLinuxAdditions.run
```

That should run the script. If for some reason, this does not work for you, it might be best to uninstall VBoxAdditions, update your virtual box, restart then run the ./VBoxLinuxAdditions.run script again.  
  
Run the following command to uninstall VBoxAdditions:

```
sudo /media/cdrom0/VBoxGuestAdditions*/uninstall.sh
```

The wildcard `*` will match the version of VBoxGuestAdditions installed. If this fails, manually remove the files:

```
sudo rm -rf /opt/VBoxGuestAdditions-* 
sudo rm -rf /usr/src/vboxguest* 
sudo rm -rf /lib/modules/$(uname -r)/misc/vbox*
```

This will remove all the files recursively. Once done, run the following to unload the VirtualBox kernel modules:

```
sudo modprobe -r vboxguest vboxsf vboxvideo
```

Sometimes, the vboxguest might still be running in the background so you might encounter errors when trying to run the above command. You can confirm this with :

```
lsmod | grep vboxguest
```

If you find the process running with a PID, do not kill forcefully with kill -9 , kill -0 or kill - As this could cause fatal errors. Instead, run:

```
sudo systemctl stop vboxadd.service

sudo systemctl stop vboxservice.service

reboot

sudo modprobe -r vboxguest vboxsf vboxvideosudo systemctl stop vboxadd.service

shutdown -h now
```

Once done, go ahead to update your virtual box to the latest version. Then go to the storage section in your settings as seen below and mount the latest version of VBoxGuestAdditions.iso file:  ![[002.png]]

Alternatively, VBoxGuestAdditions.iso can be also found from file explorer at C:\Program Files\Oracle\VirtualBox:

![[003.png]]

Once done, start your linux virtual m,achine, go to terminal and run:

```
sudo apt update
sudo apt upgrade
sudo apt install build-essential dkms linux-headers-$(uname -r)
```

Mount and execute the VBoxGuestAdditions `.iso`:  

```
sudo mount /dev/cdrom /media/cdrom
cd /media/cdrom
sudo sh ./VBoxLinuxAdditions.run
```

Your problem should be fixed. In case you see errors like “failure to build kernel modules”, use the following command to rebuild the kernel module and run the process again.

```
sudo /sbin/rcvboxadd quicksetup all
```

![[004.jpg]]

Remember to reboot the machine to make sure changes have propagated properly before resuming normal use. If for some reason, the issue persists, refer to the other troubleshooting commands in the error logs. With these steps, your problem should be resolved, and you can return to using your Linux VM smoothly!