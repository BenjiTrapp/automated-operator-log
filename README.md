# automated-operator-log

Lorem ipsum dolores ...

## Install as Service

1. Make sure that AuditD and Python3 is installed 
2. Create the file `audit2json-daemon.service` with the content below: 
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
3. Adjust the path settings according to the location of your script
4. Now start the daemon with `systemctl start audit2json-daemon`.
5. One word of awareness: make sure that `/usr/bin/python3` fits and adjust it to your environment. In most of the caeses a "simple" python3 is enough :) 
