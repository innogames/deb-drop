# Description

Provides a FastCGI interface Server which accepts over POST Packages which should be added to one or more repositories with token based access  

## Restrictions
There are certain rules for package and config which need to be respected:  
* Nginx/Other web server must support FastCGI interface to interact with daemon. I highly recommend you to use https in front   
* Name of package-file must satisfy next schema: <name_of_package>_<version>_<architecture>.deb. For example grafsy_1.3_amd64.deb  
* Name of repository must satisfy next schema: <name_of_repository>-<section>-<architecture>. For example oleg-stable-amd64  

#### Usage

Packages can be upload with the following curl command:

`curl -F "token=<your token>" -F "repos=<first repos>,<second repo (optional)>" -F "package=@<debian package>" -X POST https://<server>`

Example:

`curl -F "token=dsklsksgsdkdk" -F "repos=analytics-stable-amd64,analytics-jessie-amd64" -F "package=@test_1234_amd64.deb" -X POST https://yourServerName.com`

Additionally the paramater "max_versions" can be used to specify the amount of versions one package should have on the update server.
If more than the specified amount of versions are found the oldest get removed (String comparision, not real version parsing).
Default is to not remove any packages.

#### Config
The server reads `deb-drop.toml` during every request so no need to restart the server after a change here
Structure:
```toml
host = "localhost"
port = 9000
requestCacheSize = 10
logfile = "/var/log/deb-drop/deb-drop.log"
repoLocation = "/ftp/pool"
tmpDir = "/tmp/deb-drop"
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