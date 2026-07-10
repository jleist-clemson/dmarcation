<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Tests;

use Jonathanleist\Dmarcation\Resolver\ResolverException;
use Jonathanleist\Dmarcation\Spf\SpfLookup;
use Jonathanleist\Dmarcation\Tests\Doubles\FakeDnsResolver;
use PHPUnit\Framework\TestCase;

final class SpfLookupTest extends TestCase
{
    public function testFindsAndEvaluatesRecord(): void
    {
        $lookup = new SpfLookup(new FakeDnsResolver([
            'example.com' => ['v=spf1 include:_spf.example.com -all'],
            '_spf.example.com' => ['v=spf1 ip4:192.0.2.0/24 -all'],
        ]));

        $result = $lookup->forDomain('example.com');

        $this->assertTrue($result->found());
        $this->assertFalse($result->multiple);
        $this->assertSame('v=spf1 include:_spf.example.com -all', $result->record);
        $this->assertNotNull($result->evaluation);
        $this->assertSame(1, $result->evaluation->lookupCount);
    }

    public function testNoRecord(): void
    {
        $lookup = new SpfLookup(new FakeDnsResolver());

        $result = $lookup->forDomain('example.com');

        $this->assertFalse($result->found());
        $this->assertFalse($result->multiple);
        $this->assertNull($result->record);
        $this->assertNull($result->evaluation);
    }

    public function testMultipleRecordsIsFlaggedAndNotEvaluated(): void
    {
        $lookup = new SpfLookup(new FakeDnsResolver([
            'example.com' => ['v=spf1 -all', 'v=spf1 a -all'],
        ]));

        $result = $lookup->forDomain('example.com');

        $this->assertTrue($result->multiple);
        $this->assertFalse($result->found());
        $this->assertNull($result->evaluation);
        $this->assertCount(2, $result->multipleRecords());
    }

    public function testNonSpfTxtRecordsAreIgnored(): void
    {
        $lookup = new SpfLookup(new FakeDnsResolver([
            'example.com' => ['some verification token', 'v=spf1 -all'],
        ]));

        $result = $lookup->forDomain('example.com');

        $this->assertTrue($result->found());
        $this->assertSame('v=spf1 -all', $result->record);
    }

    public function testDomainIsNormalized(): void
    {
        $lookup = new SpfLookup(new FakeDnsResolver([
            'example.com' => ['v=spf1 -all'],
        ]));

        $result = $lookup->forDomain('  EXAMPLE.com.  ');

        $this->assertSame('example.com', $result->domain);
        $this->assertTrue($result->found());
    }

    public function testResolverExceptionPropagates(): void
    {
        $lookup = new SpfLookup(new FakeDnsResolver(records: [], failsFor: 'example.com'));

        $this->expectException(ResolverException::class);
        $lookup->forDomain('example.com');
    }
}
