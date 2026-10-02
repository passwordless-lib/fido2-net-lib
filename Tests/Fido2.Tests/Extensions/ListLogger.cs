using Microsoft.Extensions.Logging;

namespace Test;

/// <summary>
/// An <see cref="ILogger{T}"/> that keeps every entry, so tests can assert on what a component reported.
/// </summary>
internal sealed class ListLogger<T> : ILogger<T>
{
    public sealed record Entry(LogLevel Level, EventId EventId, string Message, Exception Exception);

    public List<Entry> Entries { get; } = [];

    public IEnumerable<Entry> WithEventId(int eventId) => Entries.Where(e => e.EventId.Id == eventId);

    public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
    {
        Entries.Add(new Entry(logLevel, eventId, formatter(state, exception), exception));
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();
        public void Dispose() { }
    }
}
