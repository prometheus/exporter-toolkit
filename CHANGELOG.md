## 0.8.1 / 2022-10-21

* [BUGFIX] Fix systemd activation flag when using a custom kingpin app. #118

## 0.8.0 / 2022-10-10

* [CHANGE] Change some structs suffix from `Struct` to `Config`. #114
* [FEATURE] Add multiple listeners and systemd socket support. #95
* [FEATURE] Allow TLS parameters to be set in code. #110

## 0.7.1 / 2021-12-02

* [BUGFIX] Effectively enable HTTP/2 support. #72

## 0.7.0 / 2021-10-19

* [FEATURE] Add support for security-related HTTP headers. #41

## 0.6.1 / 2021-06-30

* [BUGFIX] Allow RequireAnyClientCert as client_auth_type. #58

## 0.6.0 / 2021-06-30

* [CHANGE] Move from github.com/go-kit/kit/log to github.com/go-kit/log #55

## 0.5.1 / 2021-01-15

This release includes a bugfix for a side-channel security issue that would
allow an attacker to verify if a user is defined in the configuration by timing
request. #39

* [ENHANCEMENT] Cache basic authentication results to significantly improve
  performance. #32
* [BUGFIX] Prevent user enumeration by timing requests. #39

## 0.5.0 / 2021-01-13

* [CHANGE] rename `https` package to `web`. #29
* [CHANGE] `web`: Rename Listen() to ListenAndServe(). #28

## 0.4.0 / 2020-12-26

This release now correctly resolves relative paths with regards to the
configuration file, instead of the current working directory.

* [FEATURE] `https`: Add a Validate() function. #22
* [ENHANCEMENT] `https`: Mark kingpin flag as experimental. #20
* [BUGFIX] `https`: Make certificate paths relative to configuration file. #21

## 0.3.0 / 2020-12-25

* [FEATURE] `https`: Add Serve to use an existing listener. #16
* [BUGFIX] Return 401 Unauthorized when a bad password is used. Previously we
  returned 403 Forbidden in that case. #17

## 0.2.0 / 2020-12-16

* [FEATURE] `https/kingpinflags` package for adding kingpin support for TLS. #12

## 0.1.0 / 2020-12-10

Initial release.

* [FEATURE] `https` package for adding TLS to exporters. #8
