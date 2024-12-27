<?php

namespace SpfLibFlattener;

require __DIR__ . '/../vendor/autoload.php';

$domain = 'example.com';
$spf = new SpfFlattener($domain);

$flatArray = $spf->toFlatArray();
$flatString = $spf->toFlatString();
$flatRecord = $spf->toFlatRecord();

$splitter = RecordSplitter::createFromTxt($flatString);
$split = $splitter->split(512, 'spf#.' . $domain);

foreach ($split as $name => $r) {
    echo "name:$name record:$r<br/>" . PHP_EOL;
}
