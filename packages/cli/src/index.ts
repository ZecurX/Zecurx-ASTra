#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import path from 'path';
import fs from 'fs';
import {
  createDefaultEngine,
  formatFinding,
  toSARIF,
  type ScanResult,
  type Finding,
  type Severity,
} from '../../engine/src';

const VERSION = '1.0.0';

const program = new Command();

program
  .name('zecurx')
  .description(
    'Zecurx CodeGuard - Static Application Security Testing (SAST) for JavaScript/TypeScript'
  )
  .version(VERSION);

program
  .command('scan')
  .description('Scan a directory or file for security vulnerabilities')
  .argument('<path>', 'Path to file or directory to scan')
  .option(
    '-f, --format <format>',
    'Output format: json, pretty, sarif',
    'pretty'
  )
  .option('-o, --output <file>', 'Write output to file')
  .option(
    '-s, --severity <level>',
    'Minimum severity to report: Low, Medium, High',
    'Low'
  )
  .option('--no-color', 'Disable colored output')
  .option('-q, --quiet', 'Only output findings, no summary')
  .action(
    async (
      targetPath: string,
      options: {
        format: 'json' | 'pretty' | 'sarif';
        output?: string;
        severity: Severity;
        color: boolean;
        quiet: boolean;
      }
    ) => {
      const absolutePath = path.resolve(targetPath);

      // Validate path exists
      if (!fs.existsSync(absolutePath)) {
        console.error(chalk.red(`Error: Path not found: ${absolutePath}`));
        process.exit(1);
      }

      // Create engine
      const engine = createDefaultEngine({
        severityThreshold: options.severity,
      });

      // Progress output for pretty format
      if (options.format === 'pretty' && !options.quiet) {
        console.log(chalk.blue('\n🔍 Zecurx CodeGuard - Security Scanner\n'));
        console.log(chalk.gray(`Scanning: ${absolutePath}`));
        console.log(chalk.gray(`Severity threshold: ${options.severity}\n`));

        engine.on((event) => {
          if (event.type === 'file:start') {
            process.stdout.write(
              chalk.gray(`  Analyzing: ${path.basename(event.file)}...`)
            );
          }
          if (event.type === 'file:end') {
            const count = event.result.findings.length;
            if (count > 0) {
              process.stdout.write(chalk.yellow(` ${count} finding(s)\n`));
            } else {
              process.stdout.write(chalk.green(' ✓\n'));
            }
          }
        });
      }

      // Run scan
      const result = await engine.scan(absolutePath);

      // Format output
      let output: string;
      switch (options.format) {
        case 'json':
          output = JSON.stringify(result, null, 2);
          break;
        case 'sarif':
          output = JSON.stringify(
            toSARIF(result.files.flatMap((f) => f.findings)),
            null,
            2
          );
          break;
        case 'pretty':
        default:
          output = formatPrettyOutput(result, options.quiet);
          break;
      }

      // Write output
      if (options.output) {
        fs.writeFileSync(options.output, output);
        if (!options.quiet) {
          console.log(chalk.green(`\nOutput written to: ${options.output}`));
        }
      } else if (options.format !== 'pretty') {
        console.log(output);
      }

      // Exit with error code if findings found
      if (result.summary.totalFindings > 0) {
        process.exit(1);
      }
    }
  );

program
  .command('rules')
  .description('List all available security rules')
  .option('-f, --format <format>', 'Output format: json, table', 'table')
  .action((options: { format: 'json' | 'table' }) => {
    const engine = createDefaultEngine();
    const rules = engine.getRules();

    if (options.format === 'json') {
      console.log(
        JSON.stringify(
          rules.map((r) => r.meta),
          null,
          2
        )
      );
      return;
    }

    console.log(chalk.blue('\n📋 Zecurx CodeGuard - Security Rules\n'));
    console.log(chalk.gray('─'.repeat(80)));

    for (const rule of rules) {
      const severity = colorSeverity(rule.meta.severity);
      console.log(
        `${chalk.white(rule.meta.id.padEnd(15))} ${severity.padEnd(20)} ${
          rule.meta.name
        }`
      );
      console.log(chalk.gray(`  ${rule.meta.description}`));
      if (rule.meta.cwe) {
        console.log(chalk.cyan(`  ${rule.meta.cwe}`));
      }
      console.log();
    }

    console.log(chalk.gray('─'.repeat(80)));
    console.log(chalk.gray(`Total: ${rules.length} rules\n`));
  });

function colorSeverity(severity: Severity): string {
  switch (severity) {
    case 'High':
      return chalk.red(severity);
    case 'Medium':
      return chalk.yellow(severity);
    case 'Low':
      return chalk.blue(severity);
  }
}

function formatPrettyOutput(result: ScanResult, quiet: boolean): string {
  const lines: string[] = [];

  if (!quiet) {
    lines.push('');
    lines.push(chalk.gray('─'.repeat(80)));
  }

  // Group findings by file
  const fileFindings = new Map<string, Finding[]>();
  for (const fileResult of result.files) {
    if (fileResult.findings.length > 0) {
      fileFindings.set(fileResult.file, fileResult.findings);
    }
  }

  // Output findings
  for (const [file, findings] of fileFindings) {
    lines.push('');
    lines.push(chalk.white.bold(file));

    for (const finding of findings) {
      const severity = colorSeverity(finding.severity);
      const location = chalk.gray(`${finding.line}:${finding.column}`);
      const cwe = finding.cwe ? chalk.cyan(` [${finding.cwe}]`) : '';

      lines.push(`  ${location} ${severity} ${finding.ruleId}${cwe}`);
      lines.push(`    ${finding.message}`);

      if (finding.snippet) {
        const snippetLines = finding.snippet
          .split('\n')
          .map((l) => chalk.gray(`    ${l}`));
        lines.push(...snippetLines);
      }
    }
  }

  if (!quiet) {
    lines.push('');
    lines.push(chalk.gray('─'.repeat(80)));
    lines.push('');

    // Summary
    const { summary } = result;
    lines.push(chalk.white.bold('Summary'));
    lines.push(`  Files scanned: ${summary.totalFiles}`);
    lines.push(`  Files with findings: ${summary.filesWithFindings}`);
    lines.push(`  Total findings: ${summary.totalFindings}`);
    lines.push('');
    lines.push(`  ${chalk.red('High')}: ${summary.bySeverity.High}`);
    lines.push(`  ${chalk.yellow('Medium')}: ${summary.bySeverity.Medium}`);
    lines.push(`  ${chalk.blue('Low')}: ${summary.bySeverity.Low}`);
    lines.push('');
    lines.push(chalk.gray(`Scan completed in ${result.duration}ms`));
    lines.push('');
  }

  // Print to console for pretty format
  for (const line of lines) {
    console.log(line);
  }

  return lines.join('\n');
}

program.parse();
