# CodeQL tools

GitHub provides the CodeQL command-line interface and CodeQL for Visual Studio Code for performing CodeQL analysis on open source codebases. For information on the use cases for each tool, see "[Running CodeQL queries ](#running-codeql-queries)."

## CodeQL command-line interface

The CodeQL command-line interface (CLI) is primarily used to create databases for
security research. You can also query CodeQL databases directly from the command line
or using the Visual Studio Code extension.
The CodeQL CLI can be downloaded from "[GitHub releases ](https://github.com/github/codeql-cli-binaries/releases)."
For more information, see "[CodeQL CLI ](https://docs.github.com/en/code-security/codeql-cli)" and the "[Change log ](#codeql-changes)."

## CodeQL packs

The standard CodeQL query and library packs
([source ](https://github.com/github/codeql/tree/codeql-cli/latest))
maintained by GitHub are:

- `codeql/actions-queries` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/actions/ql/src/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/actions/ql/src))
- `codeql/actions-all` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/actions/ql/lib/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/actions/ql/lib))
- `codeql/cpp-queries` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/cpp/ql/src/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/cpp/ql/src))
- `codeql/cpp-all` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/cpp/ql/lib/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/cpp/ql/lib))
- `codeql/csharp-queries` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/csharp/ql/src/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/csharp/ql/src))
- `codeql/csharp-all` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/csharp/ql/lib/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/csharp/ql/lib))
- `codeql/go-queries` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/go/ql/src/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/go/ql/src))
- `codeql/go-all` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/go/ql/lib/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/go/ql/lib))
- `codeql/java-queries` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/java/ql/src/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/java/ql/src))
- `codeql/java-all` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/java/ql/lib/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/java/ql/lib))
- `codeql/javascript-queries` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/javascript/ql/src/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/javascript/ql/src))
- `codeql/javascript-all` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/javascript/ql/lib/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/javascript/ql/lib))
- `codeql/python-queries` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/python/ql/src/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/python/ql/src))
- `codeql/python-all` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/python/ql/lib/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/python/ql/lib))
- `codeql/ruby-queries` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/ruby/ql/src/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/ruby/ql/src))
- `codeql/ruby-all` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/ruby/ql/lib/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/ruby/ql/lib))
- `codeql/rust-queries` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/rust/ql/src/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/rust/ql/src))
- `codeql/rust-all` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/rust/ql/lib/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/rust/ql/lib))
- `codeql/swift-queries` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/swift/ql/src/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/swift/ql/src))
- `codeql/swift-all` ([changelog ](https://github.com/github/codeql/tree/codeql-cli/latest/swift/ql/lib/CHANGELOG.md), [source ](https://github.com/github/codeql/tree/codeql-cli/latest/swift/ql/lib))

For more information, see "[About CodeQL packs ](https://docs.github.com/en/code-security/codeql-cli/codeql-cli-reference/about-codeql-packs)."

## CodeQL bundle

The CodeQL bundle consists of the CodeQL CLI together with the standard CodeQL query and library packs maintained by GitHub. The bundle is used by the CodeQL action in GitHub to generate code scanning results. If you use an external CI system, you can download the bundle from [GitHub releases ](https://github.com/github/codeql-action/releases), generate code scanning results, and upload them to GitHub.

## CodeQL for Visual Studio Code

You can analyze CodeQL databases in Visual Studio Code using the CodeQL
extension, which provides an enhanced environment for writing and running custom
queries and viewing the results. For more information, see "[CodeQL
for Visual Studio Code ](https://docs.github.com/en/code-security/codeql-for-vs-code/)."
