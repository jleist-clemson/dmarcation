<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Tests;

use Jonathanleist\Dmarcation\Severity;
use Jonathanleist\Dmarcation\Spf\SpfEvaluationResult;
use Jonathanleist\Dmarcation\Spf\SpfEvaluator;
use Jonathanleist\Dmarcation\Tests\Doubles\FakeDnsResolver;
use PHPUnit\Framework\TestCase;

final class SpfEvaluatorTest extends TestCase
{
    public function testCountsLookupsAcrossNestedIncludes(): void
    {
        $result = $this->evaluate('example.com', [
            'example.com' => ['v=spf1 include:_spf.example.com a ~all'],
            '_spf.example.com' => ['v=spf1 include:c.example.org mx -all'],
            'c.example.org' => ['v=spf1 ip4:192.0.2.0/24 -all'],
        ]);

        // example.com: include + a = 2; _spf: include + mx = 2; c: ip4 = 0.
        $this->assertSame(4, $result->lookupCount);
        $this->assertTrue($result->withinLookupLimit());
        $this->assertSame([], $result->issues);
    }

    public function testIpAndAllMechanismsDoNotCount(): void
    {
        $result = $this->evaluate('example.com', [
            'example.com' => ['v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all'],
        ]);

        $this->assertSame(0, $result->lookupCount);
    }

    public function testRedirectIsFollowedAndCounted(): void
    {
        $result = $this->evaluate('r.example.com', [
            'r.example.com' => ['v=spf1 redirect=t.example.com'],
            't.example.com' => ['v=spf1 ip4:192.0.2.1 -all'],
        ]);

        $this->assertSame(1, $result->lookupCount);
        $this->assertSame('redirect', $result->root->children[0]->via);
        $this->assertSame('t.example.com', $result->root->children[0]->domain);
    }

    public function testRedirectIsIgnoredWhenAllIsPresent(): void
    {
        $result = $this->evaluate('ra.example.com', [
            'ra.example.com' => ['v=spf1 -all redirect=t.example.com'],
            't.example.com' => ['v=spf1 ip4:192.0.2.1 -all'],
        ]);

        $this->assertSame(0, $result->lookupCount);
        $this->assertSame([], $result->root->children);
    }

    public function testIncludeLoopIsDetected(): void
    {
        $result = $this->evaluate('loop1.com', [
            'loop1.com' => ['v=spf1 include:loop2.com -all'],
            'loop2.com' => ['v=spf1 include:loop1.com -all'],
        ]);

        $this->assertNotSame([], $result->issues);
        $this->assertContainsError($result);
    }

    public function testIncludeTargetWithoutRecordIsVoidAndError(): void
    {
        $result = $this->evaluate('badinc.com', [
            'badinc.com' => ['v=spf1 include:nospf.com -all'],
            'nospf.com' => [],
        ]);

        $this->assertSame(1, $result->voidCount);
        $this->assertContainsError($result);
        $this->assertSame('no SPF record found', $result->root->children[0]->note);
    }

    public function testExceedingTenLookupsIsFlagged(): void
    {
        $includes = [];
        $records = [];
        for ($i = 1; $i <= 11; $i++) {
            $host = "h{$i}.example.com";
            $includes[] = "include:{$host}";
            $records[$host] = ['v=spf1 -all'];
        }
        $records['big.com'] = ['v=spf1 ' . implode(' ', $includes) . ' -all'];

        $result = $this->evaluate('big.com', $records);

        $this->assertSame(11, $result->lookupCount);
        $this->assertFalse($result->withinLookupLimit());
    }

    public function testMacroTargetsAreNotExpanded(): void
    {
        $result = $this->evaluate('m.example.com', [
            'm.example.com' => ['v=spf1 include:%{i}._spf.example.com -all'],
        ]);

        $this->assertSame(1, $result->lookupCount);
        $this->assertSame('contains a macro; not expanded', $result->root->children[0]->note);
    }

    /**
     * @param array<string, list<string>> $records
     */
    private function evaluate(string $domain, array $records): SpfEvaluationResult
    {
        return (new SpfEvaluator(new FakeDnsResolver($records)))->evaluate($domain);
    }

    private function assertContainsError(SpfEvaluationResult $result): void
    {
        foreach ($result->issues as $issue) {
            if ($issue->severity === Severity::Error) {
                $this->assertTrue(true);

                return;
            }
        }

        $this->fail('Expected at least one error-level issue.');
    }
}
