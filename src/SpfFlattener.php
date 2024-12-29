<?php

declare(strict_types=1);

namespace SpfLibFlattener;

use SPFLib\Decoder;
use SPFLib\Record;

/**
 * Spf flattener
 * Takes a domain name
 * Fetches the SPF record for the domain
 * Parses and recurses into all include: values
 * Split function for TXT record limit best practices
 */

class SpfFlattener
{
    protected $decoder;
    protected $domain;
    protected $record;
    protected $spf;
    protected $flattener;

    /**
     * Constructor to initialize the SPF record for a domain.
     */
    public function __construct(string $domain, string $spfRecord = '')
    {
        $this->domain = $domain;
        $this->decoder = new Decoder();

        if (!empty($spfRecord)) {
            $this->setSpfRecord($spfRecord);
        } else {
            $domainSpf = $this->decoder->getRecordFromDomain($domain);
            $this->setSpfRecord((string) $domainSpf);
        }

        $this->flattener = new RecordFlattener($domain, $this->record);
    }

    /**
     * Static method to create an Spf instance from a domain name.
     *
     * @param string $domain The domain name.
     * @return self
     */
    public static function createFromDomain(string $domain): self
    {
        $spf = self::fetchSpfRecord($domain);
        if (empty($spf)) {
            throw new \RuntimeException(sprintf('No SPF record found for domain: %s', $domain));
        }
        $instance = new self($domain, $spf);
        return $instance;
    }

    /**
     * Static method to create an Spf instance from a domain name.
     */
    public static function createFromText(string $domain, string $spf): self
    {
        return new self($domain, $spf);
    }


    /**
     * Fetch the SPF record for a domain.
     *
     * @param string $domain The domain to fetch the SPF record for.
     * @return string The SPF record of the domain.
     */
    public static function fetchSpfRecord(string $domain): string
    {
        return self::fetchTxtRecordStartsWith($domain, 'v=spf1');
    }

    /**
     * Fetch the TXT record for a domain that start with string.
     *
     * @param string $domain The domain to fetch the SPF record for.
     * @return string The SPF record of the domain.
     */
    public static function fetchTxtRecordStartsWith(string $domain, string $startsWith): string
    {
        static $cache = [];

        $parsedUrl = parse_url('http://' . $domain);
        if ($parsedUrl === false || !isset($parsedUrl['host']) || $parsedUrl['host'] !== $domain) {
            throw new \InvalidArgumentException(sprintf('Invalid domain name: %s', $domain));
        }

        if (isset($cache[$domain])) {
            return $cache[$domain];
        }

        $dnsRecords = dns_get_record($domain, DNS_TXT);
        if ($dnsRecords === false) {
            throw new \RuntimeException(sprintf('Failed to fetch DNS records for domain: %s', $domain));
        }

        $results = [];
        foreach ($dnsRecords as $record) {
            if (isset($record['txt']) && strpos($record['txt'], $startsWith) === 0) {
                $results[] = $record['txt'];
            }
        }
        if (count($results) > 1) {
            throw new \RuntimeException(sprintf('Multiple TXT records starting with "%s" found for domain: %s', $startsWith, $domain));
        }

        $cache[$domain] = $results[0] ?? '';
        return $cache[$domain];
    }

    public function getRecord(): Record
    {
        return $this->record;
    }

    /**
     * Get the SPF record.
     *
     * @return string The SPF record.
     */
    public function getSpf(): string
    {
        return $this->spf;
    }

    public function validateSpf(string $spfRecord): void
    {
        try {
            $record = $this->decoder->getRecordFromTXT($spfRecord);
            $issues = (new \SPFLib\SemanticValidator())->validate($record);
            if (!empty($issues)) {
                $errors = [];
                foreach ($issues as $issue) {
                    $errors[] = (string) $issue;
                }
                throw new \RuntimeException(sprintf('Invalid SPF record: %s', implode(', ', $errors)));
            }
        } catch (\Throwable $e) {
            throw new \RuntimeException($e->getMessage());
        }
    }

    /**
     * Set the SPF record.
     *
     * @param string $record The SPF record.
     * @return self
     */
    public function setSpfRecord(string $record): self
    {
        $this->validateSpf($record);
        $this->spf = $record;
        $this->record = $this->decoder->getRecordFromTXT($record);
        return $this;
    }

    public function getAddresses(): array
    {
        $ips = $this->flattener->flattenMechanisms();
        return $ips;
    }

    public function toFlatRecord(bool $includesOnly = true): Record
    {
        return $this->decoder->getRecordFromTXT($this->toFlatString($includesOnly));
    }

    public function toFlatArray(bool $includesOnly = true): array
    {
        return $this->flattener->setIncludesOnly($includesOnly)->toFlatArray();
    }

    public function toFlatString(bool $includesOnly = true): string
    {
        return $this->flattener->setIncludesOnly($includesOnly)->toFlatString();
    }

    public function jsonSerialize(): array
    {
        return $this->toFlatArray();
    }

    public function __toString(): string
    {
        return $this->toFlatString();
    }
}
