mindplay/blowfish
-----------------

[![Build Status](https://travis-ci.org/mindplay-dk/blowfish.svg?branch=master)](https://travis-ci.org/mindplay-dk/blowfish)

I want Blowfish password encryption, which is currently the best available.

I also want:

 * Strong, fast entropy: mcrypt when available, fall back to dev/urandom or `mt_rand()`
 * Variable cost: prioritize speed vs cipher strength depending on your needs
 * Ease of use and a small, simple dependency

I do not want a large, complicated password encryption framework - I feel quite
comfortable having a hard dependency on a public API consisting of two methods:

    public function hash($value): string;
    public function check($value, $hash): bool;

Replacing this with something else in the future would be trivial.

You need php version **5.3.7** or newer for working Blowfish implementation - prior
versions had a [broken Blowfish implementation](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2483).


Usage
-----

Trivial:

```PHP
    $service = new BlowfishService();

    $password = '$up3rS3c3tp@55w0rD';

    $hash = $service->hash($password); // encrypt the password

    $is_valid = $service->check($password, $hash); // check the password
```
