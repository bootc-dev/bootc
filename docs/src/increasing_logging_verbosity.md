# Increasing Logging Verbosity

When troubleshooting issues with **bootc**, it is often helpful to enable **verbose logging** to gain additional insights into its execution flow.

## Using the `--verbose` Flag
Most **bootc** commands support the `--verbose` flag, which enables detailed logging output. The verbosity level determines how much information is logged.

### **Verbosity Levels**
The `--verbose` flag can be used multiple times (`-v`, `-vv`, `-vvv`) to increase the verbosity of logging:

| Verbosity Level | Flag Used | Logs Enabled |
|---------------|-----------|--------------|
| **WARN** (default) | *(no flag)* | Only warnings and errors |
| **INFO** | `-v` | Warnings, errors, and general information |
| **DEBUG** | `-vv` | Info, warnings, errors, and debug logs |
| **TRACE** | `-vvv` or more | All logs, including low-level tracing |

### Example Usage
To switch to a new container image with verbose logging enabled:
```sh
bootc switch --apply -vv quay.io/centos-bootc/centos-bootc:stream9
```
This command will print **INFO, DEBUG, and WARN logs**, helping diagnose issues during the `switch` process.

### Example Output (Verbose Mode Enabled with `-vv`)
```sh
$ bootc switch --apply -vvv quay.io/centos-bootc/centos-bootc:stream9
TRACE Verified uid 0 with CAP_SYS_ADMIN
DEBUG Re-executing current process for _ostree_unshared
DEBUG Already in a mount namespace
DEBUG Current security context is unconfined_u:system_r:install_t:s0:c1023
INFO We have install_t
INFO Staged: None
DEBUG Rollback queued=false
DEBUG Wrote merge commit b8761b75924d7f21e7f92abc8fd8b3c645d289fc91555
DEBUG new_with_config: Spawned skopeo pid=1023
TRACE new_with_config: impl_request: sending request Initialize
TRACE new_with_config: impl_request: completed request Config=ImageProxy
```
With `-vvv`, the output includes **INFO, DEBUG, WARN, and TRACE** level messages.

## Using the `RUST_LOG` Environment Variable
For even more detailed logging, use the `RUST_LOG` environment variable (if applicable for Rust-based components):

```sh
RUST_LOG=debug bootc switch --apply -vvv quay.io/centos-bootc/centos-bootc:stream9
```
The environment variable will override the `-vvv` and enable **DEBUG** level logs for Rust-based sub-components within **bootc**.
