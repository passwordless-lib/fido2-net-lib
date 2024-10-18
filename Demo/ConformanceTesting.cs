using Fido2NetLib;

namespace Fido2Demo;

public static class ConformanceTesting
{
    private static readonly object _syncRoot = new();

    private static IMetadataService _instance;

    public static IMetadataService MetadataServiceInstance(string cacheDir, string origin)
    {
        if (_instance == null)
        {
            lock (_syncRoot)
            {
                if (_instance == null)
                {
                    var repos = new List<IMetadataRepository>
                    {
                        new ConformanceMetadataRepository(null, origin),
                        new FileSystemMetadataRepository(cacheDir)
                    };
                    var simpleService = new ConformanceMetadataService(repos);
                    simpleService.InitializeAsync().Wait();
                    _instance = simpleService;
                }
            }
        }
        return _instance;
    }
}
