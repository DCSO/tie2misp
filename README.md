# DEPRECATED 
*tie2misp*  was replaced by [tiffy](https://github.com/DCSO/tiffy) and is therefore no longer supported. 

--- 

# tie2misp
Import DCSO TIE IOCs as MISP events

# Requirements
## Base
- Python 3.5
- TIE API Key http://tie.dcso.de
- MISP API Key

The MISP user should be able to create events and to tag them. For this we suggest to create a separate role with the 
permission `Tagger` enabled.  

## Packages
- Requests http://python-requests.org
- PyYAML http://pyyaml.org
- Click http://click.pocoo.org/
- PyMISP https://github.com/MISP/PyMISP

# Install
```bash
$ git clone https://github.com/DCSO/tie2misp.git
$ pip3 install -r requirements.txt
```

## Configuration
The command line client expects a configuration and tag file in the `tie2misp/settings` directory where you have to
define the required API keys and URLs. To create the config and tag file, just copy the `config.sample.yml` and
`tags.sample.yml` file to `config.yml` and `tags.yml` and edit it.

```bash
$ cp settings/config.sample.yml settings/config.yml
$ cp settings/tags.sample.yml settings/tags.yml

$ vim settings/config.yml

$ vim settings/tags.yml
```

# HowTo
To start the parser just run:
```bash
$ ./tie2misp c2server
```
The parser will now process all IOCs as attributes beginning from the actual system date.

To process attributes from a specific date you can use the `--date YYYY-MM-DD` option
```bash
$ ./tie2misp c2server --date 2017-03-13
```

If you don't want to upload attributes directly, you could use the `--noupload` and `--file` flag. The parser will then
create a local file named `c2server_031609be-0d88-11e7-9c31-784f437ac6ae.json` in the tie2misp directory
```bash
$ ./tie2misp c2server --date 2017-03-13 --noupload --file
````

Additionally, you can set only the `--file` flag. The parser will now create and upload attributes for MISP and
additionally create a local JSON MISP file.
```bash
$ ./tie2misp c2server --date 2017-03-13 --file
```

If you run the tie2misp parser with cron and want to process all IOCs from the last day, you could use the `--delay INT` option. As
example:
```bash
$ ./tie2misp c2server --delay 1
```
the parser will process with the system date 2017-03-14 all IOCs from 2017-03-13. You could define a delay greater 1
but keep in mind that you could get a lot of IOCs...

## Using the actor or family parameter
Sometimes it's necessary to get all IOC's from a specific attacker group or tool family. In most cases these are known 
under more than one name. Because of this, TIE2MISP offers the capability to search for this values with the actor or 
family parameter.

To do this, you must create a simple file that contains the values that you want to search (the file can contain 1-n values).
```bash
vim crazypanda_families.txt
```
The file itself might looks like this
```
$ cat crazypanda_families.txt
pythus
agentblob
hydra
foo
bar
```

Query family based IOC's
```bash
$ ./tie2misp family --searchfile crazypanda_families.txt
```

Query actor based IOC's
```bash
$ ./tie2misp actor --searchfile crazypanda_actor_names.txt
```

## Using a proxy
TIE2MISP offers various ways for the use of a proxy. First, if the system variable `HTTP_PROXY` or `HTTPS_PROXY` is 
set, tie2misp will automatically use the given information's.

If no system variable is used, tie2misp will check if the parameter `--proxy_http` or `--proxy_https` is set. If so, TIE2MISP will use the parameter for pulling and pushing informations. 

You can use only `--proxy_http` or `--proxy_https` or both
```bash
$ ./tie2misp c2server --date 2017-03-13 --proxy_http "http://10.8.0.1:8000"
$ ./tie2misp c2server --date 2017-03-13 --proxy_http "http://10.8.0.1:8000 --proxy_https "http://10.8.0.1:8443"
```
With HTTP Basic Auth
```bash
$ ./tie2misp c2server --date 2017-03-13 --proxy_http "http://user:pass@10.8.0.1:8000"
```

In some special case's, it's useful to only set a proxy for the connection to MISP or TIE. If the proxy parameter for TIE or MISP is
used, TIE2MISP will ignore the `--proxy_http` or `--proxy_https` parameter as whole as the system variable `HTTP_PROXY` or `HTTPS_PROXY`.
```bash
$ ./tie2misp c2server --date 2017-03-13 --proxy_misp_http "http://10.8.0.1:8000"
$ ./tie2misp c2server --date 2017-03-13 --proxy_tie_https "http://10.8.0.1:8443"
```
It's also possible to use a different Proxy for TIE and MISP together:
```bash
$ ./tie2misp c2server --date 2017-03-13 --proxy_misp_http "http://10.8.0.1:8000" --proxy_tie_https "http://10.8.0.1:8443
```

# License

This software is released under a BSD 3-Clause license.
Please have a look at the LICENSE file included in the repository.

Copyright (c) 2016, DCSO Deutsche Cyber-Sicherheitsorganisation GmbH
