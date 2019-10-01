# Akamai SSL Expiration Audit
## What is this?
 Audit Akamai Property Manager Configurations and DNS Listo for Expiration dates.


## Features
* Audit Akamai Property Configuration: 
    * Offline JSON Document
    * Current Production version (download latest)
* Audit List of domains
    * List can be provided on a document (comma separeted)
    * List can be provived as argument (see "How to use")
* Account wide Audit
* Switch Key Integration (for multi account management) 
##Prerequisites/Requirements
## Limitations
Currently for version 0.1 this script will not look at variables since this adds a lot of complexity. This is because as an example: a variable (origin) can be made from other variables that are only available in execution time.

    python3 ssl-audit.py --audit file --file list.txt --file-type list --verbose

## How to use?
### Arguments:


```bash
    python3 ssl-audit.py --audit config --config-name www.art.com_pm --section allswitch --switch-key 1-42BYG
```
## Contribute
## Licensing
I am providing code and resources in this repository to you under an open source license. Because this is my personal repository, the license you receive to my code and resources is from me and not my employer (Akamai).

```
Copyright 2019 Roy Martinez

Creative Commons Attribution 4.0 International License (CC BY 4.0)

http://creativecommons.org/licenses/by/4.0/
```
