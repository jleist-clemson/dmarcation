<?php

declare(strict_types=1);

namespace Jonathanleist\Dmarcation;

/**
 * The outcome of validating a DMARC record: the parsed tags plus any errors
 * and warnings that were collected along the way.
 */
final class ValidationResult
{
    private array $issues = [];
    private array $tags = [];

    /**
     * Add a new issue to the result.
     * 
     * @param ValidationIssue $issue
     *
     * @return void
     */
    public function addIssue(ValidationIssue $issue): void
    {
        $this->issues[] = $issue;
    }

    /**
     * Add a new error to the result.
     * 
     * @param string $message
     * @param string|null $tag
     */
    public function addError(string $message, ?string $tag = null): void
    {
        $this->issues[] = new ValidationIssue(Severity::Error, $message, $tag);
    }

    /**
     * Add a new warning to the result.
     * 
     * @param string $message
     * @param string|null $tag
     *
     * @return void
     */
    public function addWarning(string $message, ?string $tag = null): void
    {
        $this->issues[] = new ValidationIssue(Severity::Warning, $message, $tag);
    }

    /**
     * A record is valid when it has produced no error-level issues. Warnings do
     * not affect validity.
     * 
     * @return bool
     */
    public function isValid(): bool
    {
        return $this->getErrors() === [];
    }

    /**
     * A getter for the issues array.
     * 
     * @return array
     */
    public function getIssues(): array
    {
        return $this->issues;
    }

    /**
     * A getter for the errors array.
     * 
     * @return array
     */
    public function getErrors(): array
    {
        return array_values(
            array_filter($this->issues, static fn (ValidationIssue $i): bool => $i->severity === Severity::Error)
        );
    }

    /**
     * A getter for the warnings array.
     * 
     * @return array
     */
    public function getWarnings(): array
    {
        return array_values(
            array_filter($this->issues, static fn (ValidationIssue $i): bool => $i->severity === Severity::Warning)
        );
    }

    /**
     * A setter for the tags array.
     * 
     * @param array $tags
     *
     * @return void
     */
    public function setTags(array $tags): void
    {
        $this->tags = $tags;
    }

    /**
     * A getter for the tags array.
     * 
     * @return array
     */
    public function getTags(): array
    {
        return $this->tags;
    }
}
