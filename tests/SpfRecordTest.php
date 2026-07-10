<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Tests;

use Jonathanleist\Dmarcation\Severity;
use Jonathanleist\Dmarcation\Spf\SpfRecord;
use Jonathanleist\Dmarcation\ValidationResult;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SpfRecordTest extends TestCase
{
    public function testValidRecordHasNoErrors(): void
    {
        $result = $this->validate('v=spf1 include:_spf.google.com ip4:192.0.2.0/24 ~all');

        $this->assertTrue($result->isValid());
        $this->assertSame([], $result->getErrors());
    }

    public function testTermsAreParsed(): void
    {
        $record = SpfRecord::fromString('v=spf1 a mx -all');

        $names = array_map(static fn ($t): string => $t->name, $record->getTerms());
        $this->assertSame(['a', 'mx', 'all'], $names);
        $this->assertSame('spf1', $record->getVersion());
    }

    public function testEmptyRecordIsInvalid(): void
    {
        $this->assertFalse($this->validate('   ')->isValid());
    }

    public function testQuotedRecordIsParsed(): void
    {
        $result = $this->validate('"v=spf1 -all"');

        $this->assertTrue($result->isValid());
    }

    public function testMissingVersionIsError(): void
    {
        $result = $this->validate('include:example.com -all');

        $this->assertFalse($result->isValid());
        $this->assertTrue($this->hasError($result, 'v'));
    }

    public function testVersionMustBeFirst(): void
    {
        $result = $this->validate('a v=spf1 -all');

        $this->assertFalse($result->isValid());
        $this->assertTrue($this->hasError($result, 'v'));
    }

    public function testUnsupportedVersionIsError(): void
    {
        $result = $this->validate('v=spf2.0 -all');

        $this->assertFalse($result->isValid());
        $this->assertTrue($this->hasError($result, 'v'));
    }

    #[DataProvider('qualifierProvider')]
    public function testQualifiersAreParsed(string $prefix, ?string $expected): void
    {
        $record = SpfRecord::fromString("v=spf1 {$prefix}all");
        $term = $record->getTerms()[0];

        $this->assertSame('all', $term->name);
        $this->assertSame($expected, $term->qualifier);
    }

    /** @return iterable<string, array{0: string, 1: string|null}> */
    public static function qualifierProvider(): iterable
    {
        yield 'pass' => ['+', '+'];
        yield 'fail' => ['-', '-'];
        yield 'softfail' => ['~', '~'];
        yield 'neutral' => ['?', '?'];
        yield 'default' => ['', null];
    }

    public function testUnknownMechanismIsError(): void
    {
        $result = $this->validate('v=spf1 frobnicate -all');

        $this->assertFalse($result->isValid());
        $this->assertTrue($this->hasError($result, 'frobnicate'));
    }

    public function testUnknownModifierWarns(): void
    {
        $result = $this->validate('v=spf1 -all foo=bar');

        $this->assertTrue($result->isValid());
        $this->assertTrue($this->hasWarning($result, 'foo'));
    }

    public function testAllTakesNoArgument(): void
    {
        $result = $this->validate('v=spf1 all:example.com');

        $this->assertTrue($this->hasError($result, 'all'));
    }

    #[DataProvider('ip4Provider')]
    public function testIp4Values(string $value, bool $valid): void
    {
        $result = $this->validate("v=spf1 ip4:{$value} -all");

        $this->assertSame($valid, !$this->hasError($result, 'ip4'));
    }

    /** @return iterable<string, array{0: string, 1: bool}> */
    public static function ip4Provider(): iterable
    {
        yield 'plain address' => ['192.0.2.1', true];
        yield 'with cidr' => ['192.0.2.0/24', true];
        yield 'invalid octet' => ['999.0.0.1', false];
        yield 'cidr out of range' => ['192.0.2.0/33', false];
        yield 'ipv6 in ip4' => ['2001:db8::1', false];
    }

    #[DataProvider('ip6Provider')]
    public function testIp6Values(string $value, bool $valid): void
    {
        $result = $this->validate("v=spf1 ip6:{$value} -all");

        $this->assertSame($valid, !$this->hasError($result, 'ip6'));
    }

    /** @return iterable<string, array{0: string, 1: bool}> */
    public static function ip6Provider(): iterable
    {
        yield 'plain address' => ['2001:db8::1', true];
        yield 'with cidr' => ['2001:db8::/32', true];
        yield 'cidr out of range' => ['2001:db8::/129', false];
        yield 'ipv4 in ip6' => ['192.0.2.1', false];
    }

    public function testIncludeRequiresDomain(): void
    {
        $this->assertTrue($this->hasError($this->validate('v=spf1 include: -all'), 'include'));
        $this->assertFalse($this->hasError($this->validate('v=spf1 include:example.com -all'), 'include'));
    }

    #[DataProvider('dualCidrProvider')]
    public function testDualCidrMechanisms(string $value, bool $valid): void
    {
        $result = $this->validate("v=spf1 a{$value} -all");

        $this->assertSame($valid, !$this->hasError($result, 'a'));
    }

    /** @return iterable<string, array{0: string, 1: bool}> */
    public static function dualCidrProvider(): iterable
    {
        yield 'bare' => ['', true];
        yield 'domain only' => [':mail.example.com', true];
        yield 'ipv4 cidr' => ['/24', true];
        yield 'dual cidr' => [':mail.example.com/24//64', true];
        yield 'ipv6 only cidr' => ['//64', true];
        yield 'ipv4 cidr too large' => ['/40', false];
        yield 'ipv6 cidr too large' => ['//200', false];
    }

    public function testPtrIsDeprecated(): void
    {
        $result = $this->validate('v=spf1 ptr -all');

        $this->assertTrue($result->isValid());
        $this->assertTrue($this->hasWarning($result, 'ptr'));
    }

    public function testPlusAllWarns(): void
    {
        $result = $this->validate('v=spf1 +all');

        $this->assertTrue($result->isValid());
        $this->assertTrue($this->hasWarning($result, 'all'));
    }

    public function testTermsAfterAllWarn(): void
    {
        $result = $this->validate('v=spf1 -all include:example.com');

        $this->assertTrue($this->hasWarning($result, 'all'));
    }

    public function testDuplicateRedirectIsError(): void
    {
        $result = $this->validate('v=spf1 redirect=a.example.com redirect=b.example.com');

        $this->assertTrue($this->hasError($result, 'redirect'));
    }

    public function testDuplicateExpIsError(): void
    {
        $result = $this->validate('v=spf1 -all exp=a.example.com exp=b.example.com');

        $this->assertTrue($this->hasError($result, 'exp'));
    }

    public function testRedirectWithAllWarns(): void
    {
        $result = $this->validate('v=spf1 -all redirect=example.com');

        $this->assertTrue($this->hasWarning($result, 'redirect'));
    }

    public function testMissingAllAndRedirectWarns(): void
    {
        $result = $this->validate('v=spf1 include:example.com');

        $this->assertTrue($this->hasWarning($result, 'all'));
    }

    public function testTooManyTopLevelLookupsIsError(): void
    {
        $includes = implode(' ', array_map(
            static fn (int $i): string => "include:host{$i}.example.com",
            range(1, 11)
        ));
        $result = $this->validate("v=spf1 {$includes} -all");

        $this->assertFalse($result->isValid());
    }

    public function testCountLookupTermsIgnoresIpMechanisms(): void
    {
        $record = SpfRecord::fromString('v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx include:x.example.com -all');

        // a, mx, include -> 3; ip4, ip6, all -> 0.
        $this->assertSame(3, $record->countLookupTerms());
    }

    private function validate(string $record): ValidationResult
    {
        return SpfRecord::fromString($record)->validate();
    }

    private function hasError(ValidationResult $result, string $tag): bool
    {
        foreach ($result->getErrors() as $issue) {
            if ($issue->tag === $tag) {
                return true;
            }
        }

        return false;
    }

    private function hasWarning(ValidationResult $result, string $tag): bool
    {
        foreach ($result->getWarnings() as $issue) {
            if ($issue->tag === $tag && $issue->severity === Severity::Warning) {
                return true;
            }
        }

        return false;
    }
}
