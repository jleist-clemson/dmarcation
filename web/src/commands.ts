import {
  ApiError,
  lookupDomain,
  validateRecord,
  type LookupResponse,
  type ValidationData,
} from "./api";

export type LineKind =
  | "input"
  | "text"
  | "error"
  | "warn"
  | "success"
  | "muted"
  | "heading";

export interface Line {
  kind: LineKind;
  text: string;
}

export interface CommandResult {
  lines: Line[];
  clear?: boolean;
}

const line = (kind: LineKind, text = ""): Line => ({ kind, text });

const HELP: Line[] = [
  line("heading", "Available commands:"),
  line("text", "  validate <record>     Validate a DMARC record string"),
  line("text", "  lookup <domain>       Fetch a domain's DMARC record and validate it"),
  line("text", "    [--ns=<server>]     ...querying a specific nameserver"),
  line("text", "  about                 About dmarcation"),
  line("text", "  help                  Show this help"),
  line("text", "  clear                 Clear the screen"),
  line("text", ""),
  line("muted", "Example: lookup google.com"),
  line("muted", "Example: validate v=DMARC1; p=reject; rua=mailto:dmarc@example.com"),
];

const ABOUT: Line[] = [
  line("heading", "dmarcation"),
  line("text", "A simple DMARC validator, written in PHP."),
  line("muted", "Validates record syntax (RFC 7489) and resolves policy via DNS,"),
  line("muted", "including organizational-domain inheritance for subdomains."),
];

function formatValidation(v: ValidationData): Line[] {
  const out: Line[] = [];

  const tags = Object.entries(v.tags);
  if (tags.length > 0) {
    out.push(line("heading", "Parsed tags:"));
    for (const [tag, value] of tags) {
      out.push(line("muted", `  ${tag.padEnd(6)} = ${value}`));
    }
    out.push(line("text", ""));
  }

  for (const issue of v.issues) {
    const label = issue.severity === "error" ? "ERROR" : "WARN ";
    const location = issue.tag ? ` [${issue.tag}]` : "";
    out.push(line(issue.severity === "error" ? "error" : "warn", `  ${label}${location} ${issue.message}`));
  }
  if (v.issues.length > 0) {
    out.push(line("text", ""));
  }

  if (v.valid) {
    out.push(line("success", `Valid DMARC record (${v.warningCount} warning(s)).`));
  } else {
    out.push(line("error", `Invalid DMARC record (${v.errorCount} error(s), ${v.warningCount} warning(s)).`));
  }

  return out;
}

function formatLookup(resp: LookupResponse): Line[] {
  const out: Line[] = [];

  out.push(line("heading", "Queries:"));
  for (const query of resp.queries) {
    const note =
      query.count === 0 ? "no record" : query.count === 1 ? "found" : `${query.count} records`;
    out.push(line("muted", `  ${query.name} (TXT) - ${note}`));
  }
  out.push(line("text", ""));

  if (resp.multiple && resp.multipleQuery) {
    out.push(
      line("error", `Multiple DMARC records at ${resp.multipleQuery.name} (RFC 7489 requires exactly one):`)
    );
    for (const record of resp.multipleQuery.records) {
      out.push(line("text", `  - ${record}`));
    }
    return out;
  }

  if (!resp.found || resp.record === null || resp.validation === null) {
    out.push(line("error", `No DMARC record found for ${resp.domain}.`));
    return out;
  }

  if (resp.inherited) {
    out.push(
      line(
        "warn",
        `No record at _dmarc.${resp.domain}; inherited from organizational domain ${resp.policyDomain}.`
      )
    );
  }

  out.push(line("text", `Record: ${resp.record} (published at _dmarc.${resp.policyDomain})`));
  out.push(line("text", ""));

  out.push(...formatValidation(resp.validation));

  if (resp.inherited && resp.effectivePolicy) {
    const via =
      resp.effectivePolicy.via === "sp"
        ? "via the 'sp' tag"
        : "via the 'p' tag (no 'sp' present)";
    out.push(line("text", ""));
    out.push(
      line("heading", `Effective subdomain policy: ${resp.effectivePolicy.policy} for ${resp.domain} (${via}).`)
    );
  }

  return out;
}

export async function runCommand(input: string): Promise<CommandResult> {
  const trimmed = input.trim();
  if (trimmed === "") {
    return { lines: [] };
  }

  const [command, ...rest] = trimmed.split(/\s+/);
  const argString = trimmed.slice(command.length).trim();

  switch (command.toLowerCase()) {
    case "help":
      return { lines: HELP };
    case "about":
      return { lines: ABOUT };
    case "clear":
      return { lines: [], clear: true };

    case "validate": {
      if (argString === "") {
        return { lines: [line("error", "usage: validate <record>")] };
      }
      try {
        const resp = await validateRecord(argString);
        return { lines: formatValidation(resp.validation) };
      } catch (e) {
        return { lines: [line("error", errorText(e))] };
      }
    }

    case "lookup": {
      let domain = "";
      let nameserver: string | undefined;
      for (const arg of rest) {
        if (arg.startsWith("--ns=")) {
          nameserver = arg.slice("--ns=".length);
        } else if (domain === "") {
          domain = arg;
        }
      }
      if (domain === "") {
        return { lines: [line("error", "usage: lookup <domain> [--ns=<server>]")] };
      }
      try {
        const resp = await lookupDomain(domain, nameserver);
        return { lines: formatLookup(resp) };
      } catch (e) {
        return { lines: [line("error", errorText(e))] };
      }
    }

    default:
      return {
        lines: [line("error", `command not found: ${command}. Type 'help'.`)],
      };
  }
}

function errorText(e: unknown): string {
  if (e instanceof ApiError) {
    return `error: ${e.message}`;
  }
  return "error: something went wrong.";
}
