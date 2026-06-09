<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation\Tests;

use Jonathanleist\Dmarcation\DmarcRecord;
use Jonathanleist\Dmarcation\Severity;
use Jonathanleist\Dmarcation\ValidationResult;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DmarcRecordTest extends TestCase
{
    public function testValidRecordHasNoErrors(): void
    {
        $result = $this->validate('v=DMARC1; p=reject; rua=mailto:dmarc@example.com');

        $this->assertTrue($result->isValid());
        $this->assertSame([], $result->getErrors());
    }

    public function testTagsAreParsed(): void
    {
        $result = $this->validate('v=DMARC1; p=reject; pct=50');

        $this->assertSame(
            ['v' => 'DMARC1', 'p' => 'reject', 'pct' => '50'],
            $result->getTags()
        );
    }

    public function testEmptyRecordIsInvalid(): void
    {
        $this->assertFalse($this->validate('   ')->isValid());
    }

    public function testQuotedRecordIsParsed(): void
    {
        $result = $this->validate('"v=DMARC1; p=none"');

        $this->assertTrue($result->isValid());
        $this->assertSame('DMARC1', $result->getTags()['v'] ?? null);
    }

    public function testMissingVersionIsError(): void
    {
        $result = $this->validate('p=none');

        $this->assertFalse($result->isValid());
        $this->assertTrue($this->hasError($result, 'v'));
    }

    public function testVersionMustBeFirst(): void
    {
        $result = $this->validate('p=none; v=DMARC1');

        $this->assertFalse($result->isValid());
        $this->assertTrue($this->hasError($result, 'v'));
    }

    public function testWrongVersionValueIsError(): void
    {
        $result = $this->validate('v=DMARC2; p=none');

        $this->assertFalse($result->isValid());
        $this->assertTrue($this->hasError($result, 'v'));
    }

    public function testMissingPolicyIsError(): void
    {
        $result = $this->validate('v=DMARC1');

        $this->assertFalse($result->isValid());
        $this->assertTrue($this->hasError($result, 'p'));
    }

    #[DataProvider('policyProvider')]
    public function testPolicyValues(string $value, bool $valid): void
    {
        $result = $this->validate("v=DMARC1; p={$value}");

        $this->assertSame($valid, !$this->hasError($result, 'p'));
    }

    /** @return iterable<string, array{0: string, 1: bool}> */
    public static function policyProvider(): iterable
    {
        yield 'none' => ['none', true];
        yield 'quarantine' => ['quarantine', true];
        yield 'reject' => ['reject', true];
        yield 'uppercase is rejected' => ['Reject', false];
        yield 'unknown value' => ['block', false];
    }

    #[DataProvider('alignmentProvider')]
    public function testAlignmentValues(string $tag, string $value, bool $valid): void
    {
        $result = $this->validate("v=DMARC1; p=none; {$tag}={$value}");

        $this->assertSame($valid, !$this->hasError($result, $tag));
    }

    /** @return iterable<string, array{0: string, 1: string, 2: bool}> */
    public static function alignmentProvider(): iterable
    {
        yield 'adkim relaxed' => ['adkim', 'r', true];
        yield 'adkim strict' => ['adkim', 's', true];
        yield 'adkim invalid' => ['adkim', 'x', false];
        yield 'aspf relaxed' => ['aspf', 'r', true];
        yield 'aspf invalid' => ['aspf', 'z', false];
    }

    #[DataProvider('pctProvider')]
    public function testPercentBounds(string $value, bool $valid): void
    {
        $result = $this->validate("v=DMARC1; p=none; pct={$value}");

        $this->assertSame($valid, !$this->hasError($result, 'pct'));
    }

    /** @return iterable<string, array{0: string, 1: bool}> */
    public static function pctProvider(): iterable
    {
        yield 'zero' => ['0', true];
        yield 'fifty' => ['50', true];
        yield 'hundred' => ['100', true];
        yield 'over hundred' => ['150', false];
        yield 'non-numeric' => ['abc', false];
    }

    #[DataProvider('reportIntervalProvider')]
    public function testReportInterval(string $value, bool $valid): void
    {
        $result = $this->validate("v=DMARC1; p=none; ri={$value}");

        $this->assertSame($valid, !$this->hasError($result, 'ri'));
    }

    /** @return iterable<string, array{0: string, 1: bool}> */
    public static function reportIntervalProvider(): iterable
    {
        yield 'default' => ['86400', true];
        yield 'zero' => ['0', true];
        yield 'negative' => ['-1', false];
        yield 'non-numeric' => ['soon', false];
    }

    public function testFailureOptionsValidList(): void
    {
        $result = $this->validate('v=DMARC1; p=none; ruf=mailto:f@example.com; fo=1:d:s');

        $this->assertFalse($this->hasError($result, 'fo'));
    }

    public function testFailureOptionInvalidValue(): void
    {
        $result = $this->validate('v=DMARC1; p=none; ruf=mailto:f@example.com; fo=9');

        $this->assertTrue($this->hasError($result, 'fo'));
    }

    public function testFailureOptionsWithoutRufWarns(): void
    {
        $result = $this->validate('v=DMARC1; p=none; fo=1');

        $this->assertTrue($result->isValid());
        $this->assertTrue($this->hasWarning($result, 'fo'));
    }

    public function testReportFormatUnknownWarns(): void
    {
        $result = $this->validate('v=DMARC1; p=none; rf=made-up');

        $this->assertTrue($result->isValid());
        $this->assertTrue($this->hasWarning($result, 'rf'));
    }

    #[DataProvider('uriProvider')]
    public function testReportingUris(string $value, bool $valid): void
    {
        $result = $this->validate("v=DMARC1; p=none; rua={$value}");

        $this->assertSame($valid, !$this->hasError($result, 'rua'));
    }

    /** @return iterable<string, array{0: string, 1: bool}> */
    public static function uriProvider(): iterable
    {
        yield 'valid mailto' => ['mailto:dmarc@example.com', true];
        yield 'valid mailto with size' => ['mailto:dmarc@example.com!10m', true];
        yield 'two valid uris' => ['mailto:a@example.com,mailto:b@example.com', true];
        yield 'missing scheme' => ['notanemail', false];
        yield 'invalid email' => ['mailto:not-an-email', false];
        yield 'bad size unit' => ['mailto:a@example.com!10x', false];
    }

    public function testUnknownTagWarns(): void
    {
        $result = $this->validate('v=DMARC1; p=none; foo=bar');

        $this->assertTrue($result->isValid());
        $this->assertTrue($this->hasWarning($result, 'foo'));
    }

    public function testDuplicateTagIsError(): void
    {
        $result = $this->validate('v=DMARC1; p=none; p=reject');

        $this->assertFalse($result->isValid());
    }

    public function testMalformedComponentIsError(): void
    {
        $result = $this->validate('v=DMARC1; p=none; garbage');

        $this->assertFalse($result->isValid());
    }

    private function validate(string $record): ValidationResult
    {
        return DmarcRecord::fromString($record)->validate();
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
