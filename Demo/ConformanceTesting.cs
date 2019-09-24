using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Fido2NetLib;

namespace Fido2Demo
{
    public static class ConformanceTesting
    {
        private static object _syncRoot = new object();

        private static IMetadataService _instance;

        public static IMetadataService MetadataServiceInstance(string cacheDir)
        {
            if(_instance == null)
            {
                lock(_syncRoot)
                {
                    if(_instance == null)
                    {
                        var repos = new List<IMetadataRepository>
                        {
                            new ConformanceMetadataRepository(null),
                            new FileSystemMetadataRepository(cacheDir)
                        };
                        _instance = new SimpleMetadataService(repos);
                        _instance.Initialize().Wait();
                    }
                }
            }
            return _instance;
        }
    }
}
