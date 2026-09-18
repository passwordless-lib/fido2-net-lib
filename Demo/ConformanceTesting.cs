using System.IO.Compression;

using Fido2NetLib;

namespace Fido2Demo;

public static class ConformanceTesting
{
    private static readonly object _syncRoot = new();

    private static IMetadataService _instance;

    /// <summary>
    /// Builds the metadata service the conformance endpoints use: the conformance MDS for the given origin, plus the
    /// metadata statements the tool ships for its virtual authenticators. Those statements are the tool's and cannot
    /// be redistributed with this repository, so whoever runs the tool supplies them: <paramref name="metadataPath"/>
    /// is either the zip the tool exports or a directory it was unpacked into.
    /// </summary>
    public static IMetadataService MetadataServiceInstance(string metadataPath, string origin)
    {
        if (_instance == null)
        {
            lock (_syncRoot)
            {
                if (_instance == null)
                {
                    var statementsDirectory = MetadataStatementsDirectory(metadataPath);
                    var statementCount = Directory.Exists(statementsDirectory) ? Directory.GetFiles(statementsDirectory, "*.json", SearchOption.AllDirectories).Length : 0;

                    Console.WriteLine(statementCount > 0
                        ? $"[conformance] {statementCount} metadata statement(s) loaded from {metadataPath}"
                        : $"[conformance] WARNING: no metadata statements found at {metadataPath}; every attestation test will fail with AaGuidNotFound. Point conformance:metadata at the tool's metadata zip or an unpacked copy of it.");

                    var conformanceRepository = new ConformanceMetadataRepository(null, origin);
                    List<IMetadataRepository> repos = [
                        conformanceRepository,
                        new FileSystemMetadataRepository(statementsDirectory)
                    ];
                    var simpleService = new ConformanceMetadataService(repos);
                    simpleService.InitializeAsync().Wait();
                    _instance = simpleService;
                }
            }
        }
        return _instance;
    }

    /// <summary>
    /// A zip is unpacked into a fresh temporary directory so the file-system repository can read it; anything else
    /// is taken to be a directory already.
    /// </summary>
    private static string MetadataStatementsDirectory(string metadataPath)
    {
        if (!File.Exists(metadataPath) || !string.Equals(Path.GetExtension(metadataPath), ".zip", StringComparison.OrdinalIgnoreCase))
            return metadataPath;

        var directory = Path.Combine(Path.GetTempPath(), "fido2-conformance-metadata", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        using var zip = ZipFile.OpenRead(metadataPath);
        foreach (var entry in zip.Entries)
        {
            if (entry.Name.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                entry.ExtractToFile(Path.Combine(directory, entry.Name));
        }

        return directory;
    }
}
