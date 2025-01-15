# Command Line Utility to publish go artifacts on jfrog

## Usage Steps:
1. Clone the repository
2. Install
```shell
go install   
```
3. Navigate to the root folder of the module you want to publish.
4. Run the following command to publish artifacts.
```
Usage:
  jfrog-cli publish [flags]

Flags:
  -k, --apikey string      Api Key
  -h, --help               help for publish
  -i, --increment string   Increment level: pre, patch, minor, or major
  -s, --server string      Artifactory Server Host
  -u, --username string    User name
```

### Example: Publishing a patch upgrade
If current version of the module is 0.0.1. The following command will upgrade it to 0.0.2
```shell
jfrog-cli publish -i patch -s <artifactory-url> -u <artifactory-username> -k <artifactory-api-key>
```

Similarly, minor and major upgrades can be done using the corresponding increment level flag.