# SPF (Sender Policy Framework) Flattening/Splitting Library

# No tests yet - Use at your own risk!

Extension of the wonderful SPF-LIB library by mlocati (https://github.com/mlocati/spf-lib)

This PHP library allows you to:

- flatten a spf record into ips addresses
- split a flattened spf record into primary and child spf records
- get the SPF record from a domain name (parent lib mlocati/spf-lib)
- decode and validate the SPF record (parent lib mlocati/spf-lib)
- create the value of a TXT record (parent lib mlocati/spf-lib)
- check if domains and IP addresses satisfy the SPF records (parent lib mlocati/spf-lib)
- all the rest of what SPF-LIB library by mlocati (https://github.com/mlocati/spf-lib) can do

## Short introduction about SPF Flattener/Splitter

This library is meant to address the issue where more than 10 lookups are present in a SPF record.

There are two parts:

- RecordFlattener - this class will flatten an spf record into an aggregated list of ips addresses
- RecordSplitter - takes a flattened record and split the ip addresses of into child records like spf1.domain.com spf2.domain.com

Because this is an extension to the wonderful SPF-LIB library by mlocati (https://github.com/mlocati/spf-lib), you can use this PHP library to build, validate, flatten, split, and check the SPF records.

## Installation

You can install this library with Composer:

```sh
composer require midweste/spf-lib-flattener
```

## Usage

### Flattening an spf record from a domain name

```php
namespace SpfLibFlattener;

require __DIR__ . '/../vendor/autoload.php';

$domain = 'example.com';
$spf = new SpfFlattener($domain);

$flatArray = $spf->toFlatArray();
$flatString = $spf->toFlatString();
$flatRecord = $spf->toFlatRecord();

```

### Flattening an spf record from an existing string record

```php
// TODO
```

### Splitting an spf record from an existing string record

```php
namespace SpfLibFlattener;

require __DIR__ . '/../vendor/autoload.php';

$domain = 'example.com';
$spf = new SpfFlattener($domain);

$splitter = RecordSplitter::createFromTxt($spf->toFlatString());
$split = $splitter->split(512, 'spf#.' . $domain);

foreach ($split as $name => $r) {
    echo "name:$name record:$r<br/>" . PHP_EOL;
}
```

## Do you want to really say thank you?

You can offer nlocati a [monthly coffee](https://github.com/sponsors/mlocati) or a [one-time coffee](https://paypal.me/mlocati) :wink:
