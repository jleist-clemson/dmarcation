import {
  ApiError,
  lookupDomain,
  lookupSpf,
  validateRecord,
  validateSpf,
  type Issue,
  type LookupResponse,
  type SpfLookupResponse,
  type SpfTreeNode,
  type SpfValidationData,
  type ValidationData,
} from "./api";

/** Which validator a terminal tab drives. */
export type Mode = "dmarc" | "spf";

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

const DMARC_HELP: Line[] = [
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
  line("muted", "Tip: switch to the 'spf' tab to validate SPF records."),
];

const SPF_HELP: Line[] = [
  line("heading", "Available commands:"),
  line("text", "  validate <record>     Validate an SPF record string (syntax only)"),
  line("text", "  lookup <domain>       Fetch a domain's SPF record and evaluate it"),
  line("text", "    [--ns=<server>]     ...following include/redirect (10-lookup limit)"),
  line("text", "  about                 About the SPF validator"),
  line("text", "  help                  Show this help"),
  line("text", "  clear                 Clear the screen"),
  line("text", ""),
  line("muted", "Example: lookup github.com"),
  line("muted", "Example: validate v=spf1 include:_spf.google.com ~all"),
  line("muted", "Tip: switch to the 'dmarc' tab to validate DMARC records."),
];

const DMARC_ABOUT: Line[] = [
  line("heading", "dmarcation"),
  line("text", "A simple DMARC validator, written in PHP."),
  line("muted", "Validates record syntax (RFC 7489) and resolves policy via DNS,"),
  line("muted", "including organizational-domain inheritance for subdomains."),
];

const SPF_ABOUT: Line[] = [
  line("heading", "dmarcation - SPF"),
  line("text", "A simple SPF validator, written in PHP."),
  line("muted", "Validates record syntax (RFC 7208) and, on lookup, follows"),
  line("muted", "include/redirect to enforce the limit of 10 DNS lookups."),
];

/** Shared error/warning rendering used by both validators. */
function formatIssues(issues: Issue[]): Line[] {
  return issues.map((issue) => {
    const label = issue.severity === "error" ? "ERROR" : "WARN ";
    const location = issue.tag ? ` [${issue.tag}]` : "";
    return line(
      issue.severity === "error" ? "error" : "warn",
      `  ${label}${location} ${issue.message}`
    );
  });
}

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

  out.push(...formatIssues(v.issues));
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

function formatSpfValidation(v: SpfValidationData): Line[] {
  const out: Line[] = [];

  if (v.terms.length > 0) {
    out.push(line("heading", "Parsed terms:"));
    for (const term of v.terms) {
      const lookup = term.causesLookup ? "  (DNS lookup)" : "";
      out.push(line("muted", `  ${term.raw.padEnd(30)} ${term.description}${lookup}`));
    }
    out.push(line("text", ""));
  }

  out.push(...formatIssues(v.issues));
  if (v.issues.length > 0) {
    out.push(line("text", ""));
  }

  if (v.valid) {
    out.push(line("success", `Valid SPF record (${v.warningCount} warning(s)).`));
  } else {
    out.push(line("error", `Invalid SPF record (${v.errorCount} error(s), ${v.warningCount} warning(s)).`));
  }

  return out;
}

function formatSpfTree(node: SpfTreeNode, depth: number): Line[] {
  const indent = "  ".repeat(depth);
  const via = node.via === "root" ? "" : `${node.via}: `;
  const lookups = node.directLookups > 0 ? ` [${node.directLookups}]` : "";
  const note = node.note ? `  (${node.note})` : "";

  const out: Line[] = [
    line(node.note ? "warn" : "muted", `  ${indent}${via}${node.domain}${lookups}${note}`),
  ];
  for (const child of node.children) {
    out.push(...formatSpfTree(child, depth + 1));
  }
  return out;
}

function formatSpfLookup(resp: SpfLookupResponse): Line[] {
  const out: Line[] = [];

  out.push(line("heading", "Queries:"));
  for (const query of resp.queries) {
    const note =
      query.count === 0 ? "no record" : query.count === 1 ? "found" : `${query.count} records`;
    out.push(line("muted", `  ${query.name} (TXT) - ${note}`));
  }
  out.push(line("text", ""));

  if (resp.multiple) {
    out.push(line("error", `Multiple SPF records at ${resp.domain} (exactly one is allowed):`));
    for (const record of resp.multipleRecords) {
      out.push(line("text", `  - ${record}`));
    }
    return out;
  }

  if (!resp.found || resp.record === null || resp.validation === null) {
    out.push(line("error", `No SPF record found for ${resp.domain}.`));
    return out;
  }

  out.push(line("text", `Record: ${resp.record}`));
  out.push(line("text", ""));

  out.push(...formatSpfValidation(resp.validation));

  const evaluation = resp.evaluation;
  if (evaluation) {
    out.push(line("text", ""));
    out.push(line("heading", "Include/redirect tree:"));
    out.push(...formatSpfTree(evaluation.tree, 0));
    out.push(line("text", ""));

    out.push(...formatIssues(evaluation.issues));
    if (evaluation.issues.length > 0) {
      out.push(line("text", ""));
    }

    out.push(
      line(
        evaluation.withinLimit ? "success" : "error",
        `DNS lookups: ${evaluation.lookupCount} of ${evaluation.lookupLimit}`
      )
    );
    if (evaluation.voidCount > 0) {
      out.push(
        line(
          evaluation.withinVoidLimit ? "warn" : "error",
          `Void lookups: ${evaluation.voidCount} of ${evaluation.voidLimit}`
        )
      );
    }
  }

  return out;
}

async function runValidate(mode: Mode, argString: string): Promise<CommandResult> {
  if (argString === "") {
    return { lines: [line("error", "usage: validate <record>")] };
  }
  try {
    if (mode === "spf") {
      const resp = await validateSpf(argString);
      return { lines: formatSpfValidation(resp.validation) };
    }
    const resp = await validateRecord(argString);
    return { lines: formatValidation(resp.validation) };
  } catch (e) {
    return { lines: [line("error", errorText(e))] };
  }
}

async function runLookup(mode: Mode, rest: string[]): Promise<CommandResult> {
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
    if (mode === "spf") {
      const resp = await lookupSpf(domain, nameserver);
      return { lines: formatSpfLookup(resp) };
    }
    const resp = await lookupDomain(domain, nameserver);
    return { lines: formatLookup(resp) };
  } catch (e) {
    return { lines: [line("error", errorText(e))] };
  }
}

export async function runCommand(mode: Mode, input: string): Promise<CommandResult> {
  const trimmed = input.trim();
  if (trimmed === "") {
    return { lines: [] };
  }

  const [command, ...rest] = trimmed.split(/\s+/);
  const argString = trimmed.slice(command.length).trim();

  switch (command.toLowerCase()) {
    case "help":
      return { lines: mode === "spf" ? SPF_HELP : DMARC_HELP };
    case "about":
      return { lines: mode === "spf" ? SPF_ABOUT : DMARC_ABOUT };
    case "clear":
      return { lines: [], clear: true };
    case "validate":
      return runValidate(mode, argString);
    case "lookup":
      return runLookup(mode, rest);
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
