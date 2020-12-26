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
