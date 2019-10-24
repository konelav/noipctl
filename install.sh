#!/bin/sh

cp noipctl.py /usr/sbin/noipctl.py
chmod +x /usr/sbin/noipctl.py
mkdir /etc/noipctl
cp noipctl.cfg /etc/noipctl/user.cfg
cp noipctl@.service /lib/systemd/system/
ln -s /lib/systemd/system/noipctl@.service /etc/systemd/system/multi-user.target.wants/noipctl@user.service
systemctl daemon-reload
systemctl enable noipctl@user.service
systemctl start noipctl@user.service

# now credentials must be set in /etc/noipctl/user.cfg
#nano /etc/noipctl/user.cfg
