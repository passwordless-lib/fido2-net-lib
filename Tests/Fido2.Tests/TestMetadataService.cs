using Fido2NetLib;

namespace Test
{
    public class TestMetadataService : ConformanceMetadataService
    {
        public TestMetadataService(IEnumerable<IMetadataRepository> repositories) : base(repositories)
        {
        }

        public void ChangeEntryGuid(Guid oldGuid, Guid newGuid)
        {
            if (!_entries.ContainsKey(oldGuid))
                return;

            _entries.Remove(oldGuid, out var entry);
            entry.AaGuid = newGuid;
            _entries.TryAdd(newGuid, entry);
        }
    }
}
