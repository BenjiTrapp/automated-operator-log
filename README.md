# automated-operator-log


## Install as Service

Create the file `audit2json-daemon.service` with the content below and adjust the path: 
```bash
[Unit]
Description=Audit2Json Converter Daemon
After=network.target

[Service]
Type=simple
User=Benji
WorkingDirectory=/path/to/your/script
ExecStart=/usr/bin/python3 /path/to/your/script/auditd_json_converter.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
Now start the daemon with `systemctl start audit2json-daemon`. One word of awareness: make sure that `/usr/bin/python3` fits and adjust it to your environment.
