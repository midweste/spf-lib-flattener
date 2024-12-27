<?php

declare(strict_types=1);

namespace SpfLibFlattener;

use JsonSerializable;
use SPFLib\Record;
use SPFLib\Term\Mechanism\AllMechanism;
use SPFLib\Term\Mechanism\AMechanism;
use SPFLib\Term\Mechanism\IncludeMechanism;
use SPFLib\Term\Mechanism\MxMechanism;
use SPFLib\Term\Mechanism\PtrMechanism;
use SPFLib\Term\Modifier\ExpModifier;
use SPFLib\Term\Modifier\RedirectModifier;

/**
 * Interface for SPF record flattening
 */

class RecordFlattener implements JsonSerializable
{
    protected $domain;
    protected $record;
    protected $includesOnly = true;

    public function __construct(string $domain, Record $record)
    {
        $this->domain = $domain;
        $this->record = $record;
    }

    public function getRecord(): Record
    {
        return $this->record;
    }

    public function setIncludesOnly(bool $includeOnly): self
    {
        $this->includesOnly = $includeOnly;
        return $this;
    }

    protected function flattenA(AMechanism $mechanism): array
    {
        try {
            $hostname = $this->domain;
            $records = dns_get_record($hostname, DNS_A + DNS_AAAA);
            if ($records === false) {
                return [];
            }
            $ipAddresses = [];
            foreach ($records as $record) {
                if (isset($record['ip'])) {
                    $ipAddress = $record['ip'];
                    if (filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $ipAddresses[] = $mechanism->getQualifier(true) . 'ip4:' . $ipAddress;
                    } else {
                        throw new \Exception('Error in AMechanism::flatten(): Invalid IPv4 address: ' . $ipAddress);
                    }
                } elseif (isset($record['ipv6'])) {
                    $ipAddress = $record['ipv6'];
                    if (filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                        $ipAddresses[] = $mechanism->getQualifier(true) . 'ip6:' . $ipAddress;
                    } else {
                        throw new \Exception('Error in AMechanism::flatten(): Invalid IPv6 address: ' . $ipAddress);
                    }
                }
            }
            return $ipAddresses;
        } catch (\Throwable $e) {
            throw new \Exception('Error in AMechanism::flatten(): ' . $e->getMessage());
        }
    }

    protected function flattenMx(MxMechanism $mechanism): array
    {
        try {
            $hostname = $this->domain;
            $records = dns_get_record($hostname, DNS_MX);
            if ($records === false) {
                return [];
            }
            $ipAddresses = [];
            foreach ($records as $record) {
                if (!isset($record['target'])) {
                    continue;
                }
                $mxHostname = $record['target'];
                $aRecords = dns_get_record($mxHostname, DNS_A | DNS_AAAA);
                foreach ($aRecords as $aRecord) {
                    if (isset($aRecord['ip'])) {
                        $ipAddress = $aRecord['ip'];
                        if (!filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                            throw new \Exception('Error in MxMechanism::flatten(): Invalid IPv4 address: ' . $ipAddress);
                        }
                        $ipAddresses[] = $mechanism->getQualifier(true) . 'ip4:' . $ipAddress;
                    } elseif (isset($aRecord['ipv6'])) {
                        $ipAddress = $aRecord['ipv6'];
                        if (!filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                            throw new \Exception('Error in MxMechanism::flatten(): Invalid IPv6 address: ' . $ipAddress);
                        }
                        $ipAddresses[] = $mechanism->getQualifier(true) . 'ip6:' . $ipAddress;
                    }
                }
            }
            return $ipAddresses;
        } catch (\Throwable $e) {
            throw new \Exception('Error in MxMechanism::flatten(): ' . $e->getMessage());
        }
    }

    protected function flattenInclude(IncludeMechanism $mechanism): array
    {
        $spf = new SpfFlattener((string) $mechanism->getDomainSpec());
        return $spf->getAddresses();
    }

    protected function flattenPtr(PtrMechanism $mechanism): array
    {
        $hostname = $this->domain;
        $validHostnames = [];
        $ptrRecords = dns_get_record($hostname, DNS_PTR);

        foreach ($ptrRecords as $ptrRecord) {
            $ptrHostname = $ptrRecord['target'];
            $aRecords = dns_get_record($ptrHostname, DNS_A | DNS_AAAA);

            foreach ($aRecords as $record) {
                if ((isset($record['ip']) && $record['ip'] === $hostname) ||
                    (isset($record['ipv6']) && $record['ipv6'] === $hostname)
                ) {
                    $validHostnames[] = $ptrHostname;
                    break;
                }
            }
        }

        return $validHostnames;
    }

    /**
     * Flatten all available mechanisms from the SPF record
     *
     * @return array
     */
    public function flattenMechanisms(): array
    {
        $ips = [];
        foreach ($this->getRecord()->getTerms() as $term) {
            switch (true) {
                case $term instanceof \SPFLib\Term\Mechanism\AMechanism:
                    $ips = array_merge($ips, $this->includesOnly ? [(string) $term] : $this->flattenA($term));
                    break;
                case $term instanceof \SPFLib\Term\Mechanism\ExistsMechanism:
                    $ips = array_merge($ips, [(string) $term]);
                    break;
                case $term instanceof \SPFLib\Term\Mechanism\IncludeMechanism:
                    $ips = array_merge($ips, $this->flattenInclude($term));
                    break;
                case $term instanceof \SPFLib\Term\Mechanism\Ip4Mechanism:
                    $ips = array_merge($ips, [(string) $term]);
                    break;
                case $term instanceof \SPFLib\Term\Mechanism\Ip6Mechanism:
                    $ips = array_merge($ips, [(string) $term]);
                    break;
                case $term instanceof \SPFLib\Term\Mechanism\MxMechanism:
                    $ips = array_merge($ips, $this->includesOnly ? [(string) $term] : $this->flattenMx($term));
                    break;
                case $term instanceof \SPFLib\Term\Mechanism\PtrMechanism:
                    $ips = array_merge($ips, $this->includesOnly ? [(string) $term] : $this->flattenPtr($term));
                    break;
            }
        }
        return array_unique($ips);
    }

    /**
     * Get the redirect domain
     *
     * @return string
     */
    public function getRedirect(): string
    {
        foreach ($this->getRecord()->getModifiers() as $modifier) {
            if ($modifier instanceof RedirectModifier) {
                return (string) $modifier->getDomainSpec();
            }
        }
        return '';
    }

    /**
     * Get the other modifiers that are not "redirect"
     *
     * @return array
     */
    public function getOtherModifiers(): array
    {
        $modifiers = [];
        foreach ($this->getRecord()->getModifiers() as $modifier) {
            if (!$modifier instanceof RedirectModifier) {
                $modifiers[] = (string) $modifier;
            }
        }
        return $modifiers;
    }

    /**
     * Get the "all" mechanism
     *
     * @return string
     */
    public function getAll(): string
    {
        foreach ($this->getRecord()->getMechanisms() as $mechanism) {
            if ($mechanism instanceof AllMechanism) {
                return (string) $mechanism;
            }
        }
        return '';
    }

    /**
     * Convert the SPF record to a flat array
     *
     * @return array
     */
    public function toFlatArray(): array
    {
        // check for redirect, short circuit if found
        $redirect = $this->getRedirect();
        if ($redirect !== '') {
            $flattener = new SpfFlattener($redirect);
            return $flattener->toFlatArray();
        }

        // process mechanisms
        $spf = [
            'version' => $this->getRecord()::PREFIX,
            'mechanisms' => $this->flattenMechanisms(),
            'modifiers' => $this->getOtherModifiers(),
            'all' => $this->getAll(),
        ];

        // process modifiers
        foreach ($this->getRecord()->getModifiers() as $modifier) {
            if ($modifier instanceof ExpModifier) {
                $spf['exp'] = (string) $modifier;
            }
        }

        return $spf;
    }

    /**
     * Convert the SPF record to a flat string
     *
     * @return string
     */
    public function toFlatString(): string
    {
        $flattened = $this->toFlatArray();
        $flatParts = array_merge([$flattened['version']], $flattened['mechanisms'], $flattened['modifiers'], [$flattened['all'] ?? '']);
        $spf = implode(' ', $flatParts);

        // validate
        $record = (new \SPFLib\Decoder())->getRecordFromTXT($spf);
        $issues = (new \SPFLib\SemanticValidator())->validate($record);
        if (!empty($issues)) {
            $errors = [];
            foreach ($issues as $issue) {
                $errors[] = (string) $issue;
            }
            throw new \RuntimeException(sprintf('Invalid SPF record: %s', implode(', ', $errors)));
        }
        return $spf;
    }

    /**
     * Convert the SPF record to a flat string
     *
     * @return string
     */
    public function toString(): string
    {
        return $this->toFlatString();
    }

    public function jsonSerialize(): mixed
    {
        return $this->toFlatArray();
    }

    public function __toString(): string
    {
        return $this->toString();
    }
}
