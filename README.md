# Certbot2IIS
Certbot2IIS is a tool to programmatically update IIS certificate generated 
by Certbot.

# Usage
```
Certbot2IIS 1.0.0
Copyright (C) 2023 Brayns.it

ERROR(S):
  Required option 'c, certfile' is missing.
  Required option 'k, keyfile' is missing.
  Required option 'n, friendlyname' is missing.
  Required option 's, sitename' is missing.

  -c, --certfile        Required. PEM certificate file

  -k, --keyfile         Required. PEM private key file

  -n, --friendlyname    Required. Certificate friendly name

  -s, --sitename        Required. IIS site name

  -h, --hostname        IIS site binding site name

  --help                Display this help screen.

  --version             Display version information.
```

Example:
```
Certbot2IIS.exe 
    -c C:\Certbot\live\mysite.mydomain.it\fullchain.pem 
    -k C:\Certbot\live\mysite.mydomain.it\privkey.pem 
    -n "Cert for mysite" 
    -s "MYSITE" 
    -h "mysite.mydomain.it"
```

# License
Experience is an Open Source project, use it for free.

# Credits
Built with love :heart: in Italy by Brayns, an idea of Simone Giordano 
[sg@simonegiordano.it](mailto:sg@simonegiordano.it)