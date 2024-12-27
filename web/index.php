<?php

namespace SpfLibFlattener;

require __DIR__ . '/../vendor/autoload.php';

$domain = 'example.com';

// Flatten a record by retrieving the SPF record for a domain
$spf = new SpfFlattener($domain);
$flatArray = $spf->toFlatArray();
$flatString = $spf->toFlatString();
$flatRecord = $spf->toFlatRecord();

// Flatten a record by passing the record as a string
$record = 'v=spf1 include:example.com include:google.com -all';
$spf = SpfFlattener::createFromText($domain, $record);
$flatArray = $spf->toFlatArray();
$flatString = $spf->toFlatString();
$flatRecord = $spf->toFlatRecord();

// Split a record using a flat spf string
$splitter = RecordSplitter::createFromTxt($flatString);
$split = $splitter->split(512, 'spf#.' . $domain);

foreach ($split as $name => $r) {
    echo "name:$name record:$r<br/>" . PHP_EOL;
}
