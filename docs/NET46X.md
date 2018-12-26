# Compatibility with .NET Framework 4.6.1 and 4.6.2

When .NET Standard 2.0 was introduced, .NET Framework 4.6.1 and 4.6.2 were already out.
Because the .NET 4.6.X Sku was the most stable release back then, the .NET Foundation decided
it was worth breaking the theme of the .NET Standard a little and declare .NET 4.6.1 and 4.6.2 as
.NET Standard 2.0 compatible even though there were some exotic APIs missing.

This was done under the assumption that these APIs are not that commonly used, such that incompatibility
would not make much problems.
While the underlying assumption holds true to this today, Fido2 uses several of these APIs.

See the official documentation regarding this issue for more information: <https://github.com/dotnet/standard/tree/master/docs/planning/netstandard-2.0#net-framework-461-supporting-net-standard-20>

## Consequences for FIDO2

For us this means that when consuming this package in a .NET 4.6.1 or 4.6.2 targeting project, at runtime you will see
TypeLoadExceptions for types like "ECPoint" - essentially breaking the functionality of this library.

## FI0404

Because NuGet doesn't give us the ability to reduce these frameworks from the .NET Standard restore graphs,
we have to fall back to MSBuild errors preventing you to even build a project with the offending configurations.