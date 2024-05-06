# PAM module for OAuth 2.0 Device Authorization Grant 
This PAM module authenticates users using [OAuth 2.0 Device Authorization Grant](https://oauth.net/2/device-flow/). It doesn't have built-in LDAP integration, so **users must be present** in the system before they can log in via this module. The module communicates with the Authorization Server to obtain user prompt data, attempt to retrieve a user `access_token`, and introspect the obtained token. Since the client module needs to introspect the access token via the Authorization Server introspection endpoint, it must be implemented on the server side. If the token is valid, the user is authenticated. The module validates the following fields in the Token Information Response:
- `active`: Must be true.
- `username`: The username from the `access_token` must match the requested PAM username. The use of "root" as a remote username is prohibited and and will consistently result in failure.
- `scope`: The scopes must match those requested in the module configuration file. The order of scopes doesn't matter.
- `exp`: The expiration date is compared to the current system date.

Only the `auth` PAM module type is implemented in this repo. The `account` type will consistently return success for testing purposes.

This code relies heavily on two libraries:
- [pam-bindings](https://docs.rs/pam-bindings/0.1.1/pam/) - A Rust interface to the PAM framework
- [oauth2](https://docs.rs/oauth2/latest/oauth2/) - A dedicated, strongly-typed Rust OAuth2 client library

**Tested only with AlmaLinux 9 and Keycloak.**

##  Requirements
- rustc
- cargo
- gcc
- libpam-dev

```shell
#RPMs
dnf install rustc cargo gcc pam-devel

#Debian
apt install rustc cargo build-essential libpam-dev
```
## Installation
You can use the provided Makefile:
```shell
make all
```
This command will test, build, and install the module. Installation primarily involves copying the compiled `libpam_oauth2_device.so` to the PAM modules path and creating example configurations.

Alternatively, you can test and build it manually:

```shell
cargo test [--release]
cargo build [--release]
```
The module file should then be located at either `target/debug/libpam_oauth2_device.so` or `target/release/libpam_oauth2_device.so`, and it can be copy to the PAM modules path (`lib64/security/`).

## Configuration
Module requires only one argument, which is a configuration path. You must specify this path using the `config` keyword because that's how the parser works. Please refer to the example below:
```conf
auth       sufficient   pam_oauth2_device.so config=/etc/pam_oauth2_device/config.json
```
Module also parses two optional arguments:
- `logs`: Specifies the logging path (default: `/tmp/pam_oauth2_device`),
- `log_level`: Specifies the logging level filter (default: `info`).

Example: 
```conf
auth       sufficient   pam_oauth2_device.so config=/etc/pam_oauth2_device/config.json logs=/var/log/pam_oauth2_device/log log_level=warn
```

The configuration file (`config.json`) must be a valid JSON file with all required fields properly set:
| Field                        | Description                                 | Required | Default Value        |
| ---------------------------- | ------------------------------------------- | ---------| ---------------------|
| `client_id`                  | OAuth 2.0 client_id                         | Yes      | -                    |
| `client_secret`              | OAuth 2.0 client_secret                     | Yes      | -                    |
| `oauth_auth_url`             | OAuth 2.0 Authorization endpoint URL        | Yes      | -                    |
| `oauth_device_url`           | OAuth 2.0 Device Authorization endpoint URL | Yes      | -                    |
| `oauth_token_url`            | OAuth 2.0 Token endpoint URL                | Yes      | -                    |
| `oauth_token_introspect_url` | OAuth 2.0 Token Introspection endpoint URL  | Yes      | -                    |
| `scope`                      | OAuth 2.0 Access Scopes (optional)          | No       | `openid profile`     |
| `qr_enabled`                 | If set to true, a QR code will be generated from either verification_uri_complete or verification_uri (optional) | No       | `true`               |

Look at [example-config.json](./config.json).

### Redirect URI
The redirect URI is hardcoded as a `urn:ietf:wg:oauth:2.0:oob` value because the PAM module is Out of Band. You need to configure this redirect URI in your OAuth client settings.

## Testing
If you installed the module using the Makefile, you should find a testing utility at `target/pam_test` and an example PAM configuration at `/etc/pam.d/device-flow-auth`. Ensure you create the configuration file at `/etc/pam_oauth2_device/config.json`. You can use the following command to test the module:
```shell
                                 # Just the name of PAM config under /etc/pam.d/. Not a path!
./target/pam_test <pam-username> device-flow-auth 
```
Make sure to replace <pam-username> with the actual username configured in your system.

## SElinux config
Setting one of this booleans should be sufficient: `authlogin_yubikey` or `nis_enabled`.
```shell
setsebool -P authlogin_yubikey 1
# OR
setsebool -P nis_enabled 1
```

## SSHD example
This `sshd_config`  params are required:
```conf
ChallengeResponseAuthentication yes
UsePAM yes
```
An example of `/etc/pam.d/sshd`:
```conf
#%PAM-1.0
auth       sufficient   pam_oauth2_device.so config=/etc/pam_oauth2_device/config.json logs=/var/log/pam_oauth2_device/log log_level=info
auth       include      postlogin

#the rest of the file...
```
