<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Tests;

use Jonathanleist\Dmarcation\DmarcLookup;
use Jonathanleist\Dmarcation\PolicySource;
use Jonathanleist\Dmarcation\Resolver\ResolverException;
use Jonathanleist\Dmarcation\Tests\Doubles\FakeDnsResolver;
use Jonathanleist\Dmarcation\Tests\Doubles\FakeOrganizationalDomainResolver;
use PHPUnit\Framework\TestCase;

final class DmarcLookupTest extends TestCase
{
    public function testDirectRecord(): void
    {
        $lookup = new DmarcLookup(
            new FakeDnsResolver(['_dmarc.example.com' => ['v=DMARC1; p=reject']]),
            new FakeOrganizationalDomainResolver(),
        );

        $result = $lookup->forDomain('example.com');

        $this->assertSame(PolicySource::Direct, $result->source);
        $this->assertTrue($result->found());
        $this->assertFalse($result->isInherited());
        $this->assertSame('example.com', $result->policyDomain);
        $this->assertSame('v=DMARC1; p=reject', $result->record);
        $this->assertCount(1, $result->queries);
    }

    public function testInheritedFromOrganizationalDomain(): void
    {
        $lookup = new DmarcLookup(
            new FakeDnsResolver([
                '_dmarc.sub.example.com' => [],
                '_dmarc.example.com' => ['v=DMARC1; p=reject; sp=quarantine'],
            ]),
            new FakeOrganizationalDomainResolver(['sub.example.com' => 'example.com']),
        );

        $result = $lookup->forDomain('sub.example.com');

        $this->assertSame(PolicySource::Organizational, $result->source);
        $this->assertTrue($result->found());
        $this->assertTrue($result->isInherited());
        $this->assertSame('example.com', $result->policyDomain);
        $this->assertCount(2, $result->queries);
    }

    public function testNoRecordAnywhere(): void
    {
        $lookup = new DmarcLookup(
            new FakeDnsResolver(),
            new FakeOrganizationalDomainResolver(['sub.example.com' => 'example.com']),
        );

        $result = $lookup->forDomain('sub.example.com');

        $this->assertSame(PolicySource::None, $result->source);
        $this->assertFalse($result->found());
        $this->assertNull($result->record);
        $this->assertCount(2, $result->queries);
    }

    public function testNoFallbackWhenDomainIsItsOwnOrganizationalDomain(): void
    {
        $lookup = new DmarcLookup(
            new FakeDnsResolver(),
            new FakeOrganizationalDomainResolver(['example.com' => 'example.com']),
        );

        $result = $lookup->forDomain('example.com');

        $this->assertSame(PolicySource::None, $result->source);
        $this->assertCount(1, $result->queries, 'should not re-query the same domain');
    }

    public function testMultipleRecordsIsFlaggedAndNotResolved(): void
    {
        $lookup = new DmarcLookup(
            new FakeDnsResolver([
                '_dmarc.example.com' => ['v=DMARC1; p=reject', 'v=DMARC1; p=none'],
            ]),
            new FakeOrganizationalDomainResolver(),
        );

        $result = $lookup->forDomain('example.com');

        $this->assertTrue($result->hasMultiple());
        $this->assertFalse($result->found());
        $this->assertSame('_dmarc.example.com', $result->multipleQuery()?->name);
    }

    public function testNonDmarcTxtRecordsAreIgnored(): void
    {
        $lookup = new DmarcLookup(
            new FakeDnsResolver([
                '_dmarc.example.com' => ['v=spf1 include:_spf.example.com ~all', 'v=DMARC1; p=none'],
            ]),
            new FakeOrganizationalDomainResolver(),
        );

        $result = $lookup->forDomain('example.com');

        $this->assertSame(PolicySource::Direct, $result->source);
        $this->assertSame('v=DMARC1; p=none', $result->record);
    }

    public function testDomainIsNormalized(): void
    {
        $lookup = new DmarcLookup(
            new FakeDnsResolver(['_dmarc.example.com' => ['v=DMARC1; p=none']]),
            new FakeOrganizationalDomainResolver(),
        );

        $result = $lookup->forDomain('_dmarc.EXAMPLE.com.');

        $this->assertSame('example.com', $result->domain);
        $this->assertTrue($result->found());
    }

    public function testResolverExceptionPropagates(): void
    {
        $lookup = new DmarcLookup(
            new FakeDnsResolver(records: [], failsFor: '_dmarc.example.com'),
            new FakeOrganizationalDomainResolver(),
        );

        $this->expectException(ResolverException::class);
        $lookup->forDomain('example.com');
    }
}
