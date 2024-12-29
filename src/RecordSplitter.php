<?php

declare(strict_types=1);

namespace SpfLibFlattener;

use SPFLib\Decoder;
use SPFLib\Record;
use SPFLib\Term\Mechanism\AllMechanism;
use SPFLib\Term\Mechanism\Ip4Mechanism;
use SPFLib\Term\Mechanism\Ip6Mechanism;

class RecordSplitter
{
    protected $spf;
    protected $record;

    public function __construct(Record $record)
    {
        $this->record = $record;
    }

    public static function createFromTxt(string $txtRecord): self
    {
        $decoder = new Decoder();
        $record = $decoder->getRecordFromTXT($txtRecord);
        return new self($record);
    }

    protected function parse(): array
    {
        $parts = [
            'version' => $this->record::PREFIX,
            'mechanisms' => [],
            'ips' => [],
            'all' => [],
        ];
        foreach ($this->record->getTerms() as $term) {
            switch (true) {
                case $term instanceof Ip4Mechanism:
                    $parts['ips'] = array_merge($parts['ips'], [(string) $term]);
                    break;
                case $term instanceof Ip6Mechanism:
                    $parts['ips'] = array_merge($parts['ips'], [(string) $term]);
                    break;
                case $term instanceof AllMechanism:
                    $parts['all'] = array_merge($parts['all'], [(string) $term]);
                    break;
                default:
                    $parts['mechanisms'] = array_merge($parts['mechanisms'], [(string) $term]);
                    break;
            }
        }
        return $parts;
    }

    protected function validateSpf(string $spf): void
    {
        $record = (new \SPFLib\Decoder())->getRecordFromTXT($spf);
        $issues = (new \SPFLib\SemanticValidator())->validate($record);
        if (!empty($issues)) {
            $errors = [];
            foreach ($issues as $issue) {
                $errors[] = (string) $issue;
            }
            throw new \Exception(implode(', ', $errors));
        }
    }

    protected function chunk(array $ips, int $characterLimit = 2048): array
    {
        if (empty($ips)) {
            return [];
        }

        $chunks = [];
        $chunk = [$this->record::PREFIX];
        $length = strlen($this->record::PREFIX) + 1;

        foreach ($ips as $ip) {
            $ipLength = strlen($ip) + 1; // +1 for the space or separator
            if ($length + $ipLength > $characterLimit) {
                $chunks[] = $chunk;
                $chunk = [$this->record::PREFIX];
                $length = strlen($this->record::PREFIX) + 1;
            }
            $chunk[] = $ip;
            $length += $ipLength;
        }

        if (!empty($chunk)) {
            $chunks[] = $chunk;
        }
        return $chunks;
    }

    // Take a spf record and split ip addresses on param limit, split into spf1.domain.com, spf2.domain.com, etc.
    // v=spf1 a mx ip4:88.198.17.124 ip4:188.40.111.227 ip6:2607:13c0:0001:0000:0000:0000:0000:7000/116 ~all becomes
    // v=spf1 a mx include:spf1.domain.com ~all
    // and spf1.domain.com becomes v=spf1 ip4:88.198.17.124 ip4:188.40.111.227 ip6:2607:13c0:0001:0000:0000:0000:0000:7000/116 ~all
    public function split(int $characterLimit = 2048, string $pattern = 'spf#'): array
    {
        $records = [];

        $parts = $this->parse();
        $chunk = $this->chunk($parts['ips'], $characterLimit);

        // assemble the parent spf string
        $primary = [$parts['version']];
        $primary = array_merge($primary, $parts['mechanisms']);
        foreach ($chunk as $index => $ips) {
            $primary[] = sprintf('include:%s', str_replace('#', (string) ($index + 1), $pattern));
        }
        $primary = array_merge($primary, $parts['all']);
        $records['primary'] = implode(' ', $primary);

        // assemble the child spf strings
        foreach ($chunk as $index => $ips) {
            $spf = [];
            $spf = array_merge($spf, $ips);
            $records[str_replace('#', (string) ($index + 1), $pattern)] = implode(' ', $spf);
        }

        // validate all
        foreach ($records as $txt) {
            $this->validateSpf($txt);
            $txtLength = strlen($txt);
            if ($txtLength > $characterLimit) {
                throw new \Exception(sprintf('SPF record length: %d - %s exceeds character limit %d', $txtLength, $txt, $characterLimit));
            }
        }

        // check number of lookups in main record
        $lookups = array_filter($parts['mechanisms'], function ($mechanism) {
            return in_array($mechanism, ['include', 'a', 'mx', 'ptr']);
        });
        if (count($lookups) > 10) {
            throw new \Exception(sprintf('SPF record contains %d lookups, maximum is 10', count($lookups)));
        }

        return $records;
    }
}
