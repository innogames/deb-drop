[![Build Status](https://travis-ci.org/innogames/deb-drop.svg?branch=master)](https://travis-ci.org/innogames/deb-drop)

# Description

Http fastCGI web server for provide simple and secure access for managing Debian packages in repositories Edit

## Restrictions
There are certain rules for package and config which need to be respected:

* Nginx/Other web server must support FastCGI interface to interact with daemon. I highly recommend you to use https in front
* Name of package-file must satisfy next schema: \<name_of_package\>\_\<version\>\_\<architecture\>.deb. For example grafsy_1.3_amd64.deb
* Name of repository must satisfy next schema: \<name_of_repository\>-\<section\>-\<architecture\>. For example oleg-stable-amd64

## Parameters
* token: secret token to authenticate on server. If you perform actions on multiple repositories - token must work for all of them
* package: may mean package name for `Get` and `Copy` functions or file location for `Deploy`
* repos: one or multiple comma-separated repositories, on which you want to perform actions
* versions: in case of usage `Get` means how many package entries to return. In case of `Copy` and `Deploy` - how many packages to keep. Default is 5  

## Usage

There are 3 main use cases right now:  

### Get
Get one or multiple entries of latest versions of given package (names with version)  
```bash
curl "https://<server>/?token=someToken&repos=someRepo-stable-amd64&package=test&versions=2"
test_0.100_all.deb
test_0.68_all.deb
```

### Copy
Copy package from one repository to another  
This might be useful for testing package on staging and then copy in to stable  
```bash
curl https://<server> -F "token=someToken" -F "repos=someRepo-stable-amd64,someRepo-jessie-amd64" -F "package=igcollect_0.100_all.deb"
```

### Deploy
Deploy package to repository  
```bash
curl https://<server> -F "token=someToken" -F "repos=someRepo-stable-amd64,someRepo-jessie-amd64" -F "package=@/root/test_1234_amd64.deb"
```

## Config
The server reads `deb-drop.toml` during every request so no need to restart the server after a change here
Structure:
```toml
# Listen on
host = "localhost"
port = 9000
# Amount of MB which will be allocated for caching purposes
requestCacheSize = 10
logfile = "/var/log/deb-drop/deb-drop.log"
# Root of repository structure. Files will be copied by deb-drop to <repoLocation>/<repo>/<package>
repoLocation = "/ftp/pool"
# Directory for temporary saved packages
tmpDir = "/tmp/deb-drop"
# Command to regenerate apt cache. We assume user of deb-drop knows how to regenerate Release files
# after the command " " repository + " " will be appended. For example "regenerate_repo.sh -r someRepo-stable-amd64"
repoRebuildCommand = "regenerate_repo.sh -r"

[[token]]
value = "someToken"
owner = "somebody"
[[token.repo]]
name = "someRepo-stable-amd64"
[[token.repo]]
name = "someRepo-jessie-amd64"

[[token]]
token = "anotherToken"
owner = "someoneElse"
[[token.repo]]
name = "someRepo-stable-amd64"
[[token.repo]]
name = "someRepo-jessie-amd64"
```
