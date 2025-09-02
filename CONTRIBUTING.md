# Contributing to Fido2NetLib

The project is open to contributions through PRs. Discussions, feature requests and bug reports are encouraged through [issues](https://github.com/passwordless-lib/fido2-net-lib/issues).

Since Fido2-net-lib is part of the .NET Foundation, we ask our contributors to abide by their [Code of Conduct](https://dotnetfoundation.org/code-of-conduct).

## To run the project locally

Start Fido2Demo (preferably https, expected url https://localhost:5001) and open https://localhost:5001/ in the browser.
You also need to either set the MetadataService to `null` or add the applicationSettings as described below.

The HTML and javascript is copied (and then updated) from WebAuthn.io.

Feedback, issues and pull requests are VERY welcome.

## Coding guidelines

❕ The content of the code that we write.

### Coding style guidelines – general

The most general guideline is that we use all the VS default settings in terms of code formatting, except that we put System namespaces before other namespaces.

1. Use four spaces of indentation (no tabs)
2. Use `_camelCase` for private fields
3. Avoid `this.` unless absolutely necessary
4. Always specify member visibility, even if it's the default (i.e. `private string _foo;` not `string _foo;`)
5. Separate all statements with new lines. Opening an closing braces enclosing multiple statements should also get their own lines.
6. Use any language features available to you (expression-bodied members, throw expressions, tuples, etc.) as long as they make for readable, manageable code. This is pretty bad: `public (int, string) GetData(string filter) => (Data.Status, Data.GetWithFilter(filter ?? throw new ArgumentNullException(nameof(filter))));`
7. Feel free to use the `var` keyword, unless the variable type isn't immediately obvious from reading the code line.
8. For primitive types, use keywords (like `int`) instead of type names (like `Int32`)
9. Describe with XmlDoc any externally visible type or member you create
10. Do not create `public` fields. Use `public` properties with `private` backing fields instead.

### Cross-platform coding

Our frameworks should work on CoreCLR, which supports multiple operating systems. Don't assume we only run (and develop) on Windows. Code should be sensitive to the differences between OS's. Here are some specifics to consider.

#### Line breaks

Windows uses `\r\n`, OS X and Linux uses `\n`. When it is important, use `Environment.NewLine` instead of hard-coding the line break.

Note: this may not always be possible or necessary.

Be aware that these line-endings may cause problems in code when using `@""` text blocks with line breaks.

#### Environment Variables

OS's use different variable names to represent similar settings. Code should consider these differences.

For example, when looking for the user's home directory, on Windows the variable is `USERPROFILE` but on most Linux systems it is `HOME`.

```cs
var homeDir = Environment.GetEnvironmentVariable("USERPROFILE")
                  ?? Environment.GetEnvironmentVariable("HOME");
```

#### File path separators

Windows uses `\` and OS X and Linux use `/` to separate directories. Instead of hard-coding either type of slash, use `Path.Combine()` or `Path.DirectorySeparatorChar`.

If this is not possible (such as in scripting), use a forward slash. Windows is more forgiving than Linux in this regard.

### When to use `internals` vs. `public` and when to use `InternalsVisibleTo`

As a modern set of frameworks, usage of internal types and members is allowed, but discouraged.

`InternalsVisibleTo` is used only to allow a unit test to test internal types and members of its runtime assembly. We do not use `InternalsVisibleTo` between two runtime assemblies.

If two runtime assemblies need to share common helpers then we will use a "shared source" solution with build-time only packages. Check out the some of the projects in https://github.com/aspnet/Common/ and how they are referenced from other solutions.

If two runtime assemblies need to call each other's APIs, the APIs must be public. If we need it, it is likely that our users need it.

### Async method patterns

#### Use the `Async` suffix

By default all async methods must have the `Async` suffix. There are some exceptional circumstances where a method name from a previous framework will be grandfathered in.

#### Cancellation token pattern

Passing cancellation tokens is done with an optional parameter with a value of `default(CancellationToken)`, which is equivalent to `CancellationToken.None` (one of the few places that we use optional parameters). The main exception to this is in web scenarios where there is already an `HttpContext` being passed around, in which case the context has its own cancellation token that can be used when needed.

Sample async method:

```cs
public Task GetDataAsync(
    QueryParams query,
    int maxData,
    CancellationToken cancellationToken = default(CancellationToken))
{
    ...
}
```

#### Use `ConfigureAwait` on awaited methods

When using `await`, the awaited task should be called with `ConfigureAwait(false)`.

The following is incorrect

```cs
crlFile = await DownloadData(cdp);
```
Use this instead:
```cs
crlFile = await DownloadData(cdp).ConfigureAwait(false);
```

This will help performance by reducing thread switching and reduce chances of deadlocks in applications that use a SynchronizationContext.

### Extension method patterns

The general rule is: if a regular static method would suffice, avoid extension methods.

Extension methods are often useful to create chainable method calls, for example, when constructing complex objects, or creating queries.

Internal extension methods are allowed, but bear in mind the previous guideline: ask yourself if an extension method is truly the most appropriate pattern.

The namespace of the extension method class should generally be the namespace that represents the functionality of the extension method, as opposed to the namespace of the target type. One common exception to this is that the namespace for middleware extension methods is normally always the same is the namespace of `IAppBuilder`.

The class name of an extension method container (also known as a "sponsor type") should generally follow the pattern of `<Feature>Extensions`, `<Target><Feature>Extensions`, or `<Feature><Target>Extensions`. For example:

```cs
namespace Food {
    class Fruit { ... }
}

namespace Fruit.Eating {
    class FruitExtensions { public static void Eat(this Fruit fruit); }
  OR
    class FruitEatingExtensions { public static void Eat(this Fruit fruit); }
  OR
    class EatingFruitExtensions { public static void Eat(this Fruit fruit); }
}
```

When writing extension methods for an interface the sponsor type name must not start with an `I`.

## Build

[![Build status](https://anders.visualstudio.com/Fido2/_apis/build/status/Fido2-CI?label=Build)](https://anders.visualstudio.com/Fido2/_build/latest?definitionId=2)
[![Test Status](https://anders.visualstudio.com/Fido2/_apis/build/status/Fido2%20Tests?branchName=master&label=Tests)](https://anders.visualstudio.com/Fido2/_build/latest?definitionId=3?branchName=master)

All PR's and the master branch is built with Azure Devops.

Scripts to build, pack and publish a nuget package are located in ./scripts/

## Conformance testing tool
To run a suit of test of different verifications and attestation formats, register and download the [FIDO Test tools](https://fidoalliance.org/tool-request-agreement/)

## Other

A complimentary [blog post](http://ideasof.andersaberg.com/development/fido2-net-library) with some lessons learned since starting this library
