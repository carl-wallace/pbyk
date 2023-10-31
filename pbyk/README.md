# pbyk

The `pbyk` utility is a provides a command line interface to enroll YubiKeys with a Purebred instance. Purebred is a derived
credential issuance system used by the U.S. Department of Defense. 

As with all Purebred apps and libraries, enrollment requires the participation of a Purebred Agent. Specifically, when enrolling
the device, you will need a Purebred Agent's EDIPI and a pair of one-time password values generated by that agent and
provided in a timely manner. When provisioning user certificates to the device, user key management (UKM) one-time
passwords (OTPs) are required. These can be obtained by authenticating to the target Purebred instance using the
(simulated) CAC credentials from which derived credentials will be created.

The `pbyk` utility uses support provided by the [pbyklib](../pbyklib/index.html) crate.

## Usage
```text
Usage: pbyk [OPTIONS]

Options:
  -h, --help     Print help (see more with '--help')
  -V, --version  Print version

Arguments:
  -a, --agent-edipi <AGENT_EDIPI>  EDIPI of Purebred Agent who provided the pre_enroll_otp or enroll_otp value
  -s, --serial <SERIAL>            Serial number of YubiKey to provision (available YubiKeys can be listed using list_yubikeys); this is not required if only one YubiKey is present
  -e, --environment <ENVIRONMENT>  Environment to target [possible values: dev, om-sipr, sipr]

Actions:
  -1, --pre-enroll-otp <PRE_ENROLL_OTP>
          Pre-enrollment OTP provided by Purebred Agent identified by agent_edipi
  -2, --enroll-otp <ENROLL_OTP>
          Enrollment OTP provided by Purebred Agent identified by agent_edipi
  -3, --ukm-otp <UKM_OTP>
          OTP generated by user associated with the device on the Purebred portal
  -4, --recover-otp <RECOVER_OTP>
          OTP generated by user associated with the device on the Purebred portal

Diagnostics:
  -p, --portal-status-check  Connect to status interface on portal to affirm network connectivity
  -k, --scep-check           Connect to status interface on CA to affirm network connectivity

Utilities:
  -y, --list-yubikeys  Lists available YubiKey devices, if any
  -r, --reset-yubikey  Resets the indicated YubiKey to a default state using a management key expected by Purebred applications

Logging:
  -l, --logging-config <LOGGING_CONFIG>
          Full path and filename of YAML-formatted configuration file for log4rs logging mechanism. See <https://docs.rs/log4rs/latest/log4rs/> for details
  -c, --log-to-console
          Log output to the console
```
## Purebred Workflow

The Purebred workflow consists of four steps: [pre-enroll](#pre-enroll), [enroll](#enroll), [user key management](#user-key-management)
and [recovery](#recover). When enrolling a YubiKey, these steps are preceded by a device [reset](#reset) operation.

The following sections demonstrate enrolling a YubiKey device with the serial number 15995762 with the cooperation of a
Purebred Agent whose EDIPI is 5533442211. 

### Reset

The first step is to list available YubiKeys. If you already know your device's  serial number or if only one YubiKey 
is present, this can be skipped.

```bash
$ pbyk -l
Name: Yubico YubiKey OTP+FIDO+CCID; Serial: 15995762
```

Next, reset the YubiKey so that it uses the expected management key.

```bash
$ pbyk -s 15995762 -r
```

### Pre-enroll

The next two steps require Purebred Agent participation. The agent should provide their EDIPI and a 
Pre-enrollment OTP. Pre-enrollment must be completed within three minutes of generating the Pre-enrollment OTP.

```bash
$ pbyk -s 15995762 -a 5533442211 -1 74517780
Enter PIN: 
Pre-enroll completed successfully: 07E7730D014D55AFA800609C962E9FF40B61A5AD70E07AAC95E9F6911C4B48E1
```

### Enroll

Next, the Purebred Agent will affirm the hash value displayed during pre-enrollment to establish trust in the device and will provide an Enrollment OTP.
As with Pre-enrollment, the Enrollment operation must be completed within three minutes of generating the Enrollment OTP.

```bash
$ pbyk -s 15995762 -a 5533442211 -2 63999319
Enter PIN: 
Enroll completed successfully
```

### User key management

Provisioning user keys does not require Purebred Agent co-operation but does require a UKM OTP. To generate a UKM OTP, 
browse to the My Devices tab on the Purebred portal and click the `Generate OTP` link for the target device to obtain a 
UKM OTP for your device. Provide the value to `pbyk` as shown below. The UKM process must be completed within three minutes of
generating the OTP value.

```bash
$ pbyk -s 15995762 -3 38979363
Enter PIN: 
UKM completed successfully
```

### Recover

The Recover operation is optional and follows the same steps as described for UKM. After obtaining a UKM OTP complete
the Recover operation as shown below. The recovery process must be completed within three minutes of
generating the OTP value.

```bash
$ pbyk -s 15995762 -4 30468894
Enter PIN: 
Recover completed successfully
```

## Features

As with other Purebred apps, information is incorporated into the app for a target environment, i.e., NIPR, SIPR, NIPR test, SIPR test, development.
Unlike other apps, a single `pbyk` build can target multiple environments. Target environments are represented as features
when `pbyk` is built. The following environment-related features are available:

| Feature  | Description                 |
|----------|-----------------------------|
| dev      | Development environment     |
| om_nipr* | Test environment for NIPR   |
| nipr*    | NIPR production environment |
| om_sipr  | Test environment for SIPR   |
| sipr     | SIPR production environment |

The `dev` feature is the default. At least one environment-related feature must be elected when `pbyk` is built, else compilation fails.
Features are additive. For example, either of the following commands can be used to build a `pbyk` app that targets dev, om_sipr and sipr.
```bash
cargo build --features om_sipr,sipr --release
cargo build --no-default-features --features dev,om_sipr,sipr --release
```
When more than one environment is available, the `environment` option must be specified. The `help` text for `environment` indicates available options, for example:
```text
  -e, --environment <ENVIRONMENT>  Environment to target [possible values: dev, om-sipr, sipr]
```

\* The pbyk application does not support processing BER encoded data. NIPR CAs presently return BER-encoded data. The NIPR features have been temporarily disabled until the NIPR CAs have been updated and return DER-encoded data. 

## Status

This is a work-in-progress implementation which is at an early stage of development.

## Minimum Supported Rust Version

This crate requires **Rust 1.70** at a minimum.

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.