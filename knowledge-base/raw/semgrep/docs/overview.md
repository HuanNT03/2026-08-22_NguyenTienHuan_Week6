> ## Documentation Index
> Fetch the complete documentation index at: https://docs.semgrep.dev/llms.txt
> Use this file to discover all available pages before exploring further.

# Write rules

> Semgrep uses rules, which encapsulate pattern matching logic and data flow analysis, to scan your code for security issues, style violations, bugs, and more. In addition to rules available to you in the Semgrep Registry, you can write custom rules to determine what Semgrep detects in your repositories. You can write rules that:

* Automate code review comments.
* Identify secure coding violations.
* Scan configuration files.

See more use cases in [Rule ideas](/writing-rules/rule-ideas).

## Get started

For an introduction to writing Semgrep rules, use the interactive, example-based [Semgrep rule tutorial](https://semgrep.dev/learn).

You can write rules in your terminal and run them with the Semgrep command line tool, or you can write and test using the [Semgrep Editor](https://semgrep.dev/editor).

For example, the following sample rule detects the use of `is` when comparing Python strings. `is` checks reference equality, not value equality, and can exhibit nondeterministic behavior.

```yaml
### RULE

rules:
  - id: is-comparison
    languages:
      - python
    message: The operator 'is' is for reference equality, not value equality! Use
      `==` instead!
    pattern: $SOMEVAR is "..."
    severity: ERROR
```

```python
### TEST CODE

import application
if __name__ is '__main__':
    application.run()
```

## Next steps

The following articles guide you through rule-writing basics and act as references:

* [Pattern syntax](/writing-rules/pattern-syntax) describes what Semgrep patterns can do in detail and provides sample use cases.
* [Rule syntax](/writing-rules/rule-syntax) describes Semgrep YAML rule files, which can have multiple patterns, detailed output messages, and Rule-defined fixes. The syntax allows the composition of individual patterns with Boolean operators.
* [Contributing rules](/contributing/contributing-to-semgrep-rules-repository) gives you an overview of how you can contribute to Semgrep Registry rules. This document also provides information about tests and metadata fields that you can use for your rules.

Need rule ideas? See [Rule ideas](/writing-rules/rule-ideas) for everyday use cases and prompts to help you start writing rules from scratch.
