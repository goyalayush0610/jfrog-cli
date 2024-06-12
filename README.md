# Command Line Utility to publish go artifacts on jfrog

## Usage Steps:
1. Clone the repository
2. Install
    ```shell
    go install   
    ```
3. Navigate to the root folder of the module you want to publish.
4. Run the following command to get latest artifact version.
    ```
    Usage:
      jfrog-cli get-version [flags]
    
    Flags:
      -k, --apikey string      Api Key
      -h, --help               help for get-version
      -i, --increment string   Increment level: release, pre, patch, minor, or major
      -s, --server string      Artifactory Server Host
      -u, --username string    User name
    ```

5. Run the following command to publish artifact version.
    ```
    Usage:
      jfrog-cli publish [flags]
    
    Flags:
      -k, --apikey string     Api Key
      -h, --help              help for publish
      -s, --server string     Artifactory Server Host
      -u, --username string   User name
      -v, --version string    Version number
    ```

### Example: Getting a patch upgrade version
If current version of the module is 0.0.1. The following command will return 0.0.2
```shell
jfrog-cli get-version -i patch -s <artifactory-url> -u <artifactory-username> -k <artifactory-api-key>
```
Similarly, minor and major upgrade versions can be fetched using the corresponding increment level flag.


### Example: Publishing new version
```shell
jfrog-cli publish -v <new-version> -s <artifactory-url> -u <artifactory-username> -k <artifactory-api-key>
```