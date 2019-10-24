No-IP control
-------------

Simple script for updating DNS record for dynamic IP address.


Main source of knowledge: Dynamic-Update-Client (DUC) by NoIP:
  - https://my.noip.com/#!/dynamic-dns/duc
  - https://www.noip.com/client/linux/noip-duc-linux.tar.gz


Example usage:

    $ ./noipctl.py get-ip
    2019-10-24 06:44:20,893 [INFO] get-ip: 193.181.111.1
    $ ./noipctl.py -u user@mail.com -p passw0rd get-hosts
    2019-10-24 06:44:31,961 [INFO] get-hosts: [
      {
        "domain": "ddns.net", 
        "fqdn": "user.ddns.net", 
        "group": "", 
        "host": "user"
      }, 
      {
        "domain": "myddns.me", 
        "fqdn": "user.myddns.me", 
        "group": "", 
        "host": "user"
      }
    ]
    $ ./noipctl.py -c noip.cfg update
    2019-10-24 06:44:39,392 [INFO] Autodetected FQDNs for updating: ['user.ddns.net', 'user.myddns.me']
    2019-10-24 06:44:41,129 [INFO] Autodetected IP: 193.181.111.1
    2019-10-24 06:44:43,833 [INFO] update: {
      "user.ddns.net": true, 
      "user.myddns.me": true
    }
    $ 

Utility can be scheduled for regular updates using cron or like.
Alternatively it can be started as daemon via systemd or like.

Example configuration is in `noipctl.cfg`.

Example systemd service is in `noipctl.service`.
