using System.ComponentModel;

using Fido2NetLib;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for configuring FIDO2 services in an <see cref="IServiceCollection"/>.
/// </summary>
public static class Fido2NetLibBuilderExtensions
{
    /// <summary>
    /// Adds FIDO2 services to the specified service collection using configuration from an IConfiguration instance.
    /// </summary>
    /// <param name="services">The service collection to add FIDO2 services to.</param>
    /// <param name="configuration">The configuration containing FIDO2 settings.</param>
    /// <returns>An <see cref="IFido2NetLibBuilder"/> for configuring additional FIDO2 services.</returns>
    /// <remarks>
    /// This method registers the core FIDO2 services:
    /// <list type="bullet">
    /// <item><description><see cref="IFido2"/> as a scoped service</description></item>
    /// <item><description><see cref="Fido2Configuration"/> as a singleton from configuration</description></item>
    /// <item><description><see cref="ISystemClock"/> as a singleton (if not already registered)</description></item>
    /// </list>
    /// No metadata service is registered by default. Use the returned builder to add metadata services.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> or <paramref name="configuration"/> is null.</exception>
    public static IFido2NetLibBuilder AddFido2(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<Fido2Configuration>(configuration);

        services.AddSingleton(
            resolver => resolver.GetRequiredService<IOptions<Fido2Configuration>>().Value);

        services.AddScoped<IFido2, Fido2>();
        services.TryAddSingleton<ISystemClock, SystemClock>();

        return new Fido2NetLibBuilder(services);
    }

    /// <summary>
    /// Adds FIDO2 services to the specified service collection using a configuration action.
    /// </summary>
    /// <param name="services">The service collection to add FIDO2 services to.</param>
    /// <param name="setupAction">An action to configure the FIDO2 configuration options.</param>
    /// <returns>An <see cref="IFido2NetLibBuilder"/> for configuring additional FIDO2 services.</returns>
    /// <remarks>
    /// This method registers the core FIDO2 services:
    /// <list type="bullet">
    /// <item><description><see cref="IFido2"/> as a scoped service</description></item>
    /// <item><description><see cref="Fido2Configuration"/> as a singleton from the setup action</description></item>
    /// <item><description><see cref="ISystemClock"/> as a singleton (if not already registered)</description></item>
    /// </list>
    /// No metadata service is registered by default. Use the returned builder to add metadata services.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> or <paramref name="setupAction"/> is null.</exception>
    public static IFido2NetLibBuilder AddFido2(this IServiceCollection services, Action<Fido2Configuration> setupAction)
    {
        services.Configure(setupAction);

        services.AddSingleton(
            resolver => resolver.GetRequiredService<IOptions<Fido2Configuration>>().Value);

        services.AddScoped<IFido2, Fido2>();
        services.TryAddSingleton<ISystemClock, SystemClock>();

        return new Fido2NetLibBuilder(services);
    }
    
    /// <summary>
    /// Adds a custom metadata service implementation to the FIDO2 builder.
    /// </summary>
    /// <typeparam name="T">The type of metadata service to add. Must implement <see cref="IMetadataService"/>.</typeparam>
    /// <param name="builder">The FIDO2 builder instance.</param>
    /// <returns>The <see cref="IFido2NetLibBuilder"/> for method chaining.</returns>
    /// <remarks>
    /// This method registers the specified metadata service implementation as a scoped service,
    /// replacing any previously registered <see cref="IMetadataService"/>.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> is null.</exception>
    public static IFido2NetLibBuilder AddMetadataService<T>(this IFido2NetLibBuilder builder)
        where T : class, IMetadataService
    {
        builder.Services.AddScoped<IMetadataService, T>();
        return builder;
    }
    
    /// <summary>
    /// Adds the distributed cache-based metadata service to the FIDO2 builder.
    /// </summary>
    /// <param name="builder">The FIDO2 builder instance.</param>
    /// <returns>The <see cref="IFido2NetLibBuilder"/> for method chaining.</returns>
    /// <remarks>
    /// This method registers the <see cref="DistributedCacheMetadataService"/> as a scoped service.
    /// This service provides caching capabilities for metadata using both memory and distributed cache.
    /// Ensure that memory cache and distributed cache services are registered before calling this method.
    /// Use the returned builder to add metadata repositories.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> is null.</exception>
    public static IFido2NetLibBuilder AddCachedMetadataService(this IFido2NetLibBuilder builder)
    {
        builder.Services.AddScoped<IMetadataService, DistributedCacheMetadataService>();
        return builder;
    }
    
    /// <summary>
    /// Adds a custom metadata repository implementation to the FIDO2 builder.
    /// </summary>
    /// <typeparam name="T">The type of metadata repository to add. Must implement <see cref="IMetadataRepository"/>.</typeparam>
    /// <param name="builder">The FIDO2 builder instance.</param>
    /// <returns>The <see cref="IFido2NetLibBuilder"/> for method chaining.</returns>
    /// <remarks>
    /// This method registers the specified metadata repository implementation as a scoped service,
    /// replacing any previously registered <see cref="IMetadataRepository"/>.
    /// The repository provides metadata statements for authenticator validation and attestation verification.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> is null.</exception>
    public static IFido2NetLibBuilder AddMetadataRepository<T>(this IFido2NetLibBuilder builder)
        where T : class, IMetadataRepository
    {
        builder.Services.AddScoped<IMetadataRepository, T>();
        return builder;
    }
    
    /// <summary>
    /// Adds a file system-based metadata repository to the FIDO2 builder.
    /// </summary>
    /// <param name="builder">The FIDO2 builder instance.</param>
    /// <param name="directoryPath">The directory path containing metadata statement JSON files.</param>
    /// <returns>The <see cref="IFido2NetLibBuilder"/> for method chaining.</returns>
    /// <remarks>
    /// This method registers a <see cref="FileSystemMetadataRepository"/> as a scoped service.
    /// The repository loads metadata statements from JSON files in the specified directory.
    /// Each file should contain a valid metadata statement JSON document.
    /// This is typically used for development, testing, or offline scenarios.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> or <paramref name="directoryPath"/> is null.</exception>
    /// <exception cref="DirectoryNotFoundException">Thrown when the specified directory does not exist at runtime.</exception>
    public static IFido2NetLibBuilder AddFileSystemMetadataRepository(this IFido2NetLibBuilder builder, string directoryPath)
    {
        builder.Services.AddScoped<IMetadataRepository, FileSystemMetadataRepository>(provider =>
        {
            return new FileSystemMetadataRepository(directoryPath);
        });

        return builder;
    }

    /// <summary>
    /// DO NOT USE IN PRODUCTION: Adds a conformance metadata repository to the FIDO2 builder for FIDO Alliance conformance testing.
    /// </summary>
    /// <param name="builder">The FIDO2 builder instance.</param>
    /// <param name="client">Optional HTTP client to use for requests. If null, a default client will be created.</param>
    /// <param name="origin">The origin URL for conformance testing requests.</param>
    /// <returns>The <see cref="IFido2NetLibBuilder"/> for method chaining.</returns>
    /// <remarks>
    /// This method registers a <see cref="ConformanceMetadataRepository"/> as a scoped service.
    /// This repository is specifically designed for FIDO Alliance conformance testing and fetches
    /// metadata from the conformance testing endpoints. It combines multiple metadata sources
    /// into a single BLOB for comprehensive testing scenarios.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> is null.</exception>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static IFido2NetLibBuilder AddConformanceMetadataRepository(
        this IFido2NetLibBuilder builder,
        HttpClient client = null,
        string origin = "")
    {
        builder.Services.AddScoped<IMetadataRepository>(provider =>
        {
            return new ConformanceMetadataRepository(client, origin);
        });

        return builder;
    }
    
    /// <summary>
    /// Adds the official FIDO Alliance Metadata Service (MDS) repository to the FIDO2 builder.
    /// </summary>
    /// <param name="builder">The FIDO2 builder instance.</param>
    /// <param name="clientBuilder">Optional action to configure the HTTP client used for MDS requests.</param>
    /// <returns>The <see cref="IFido2NetLibBuilder"/> for method chaining.</returns>
    /// <remarks>
    /// This method registers a <see cref="Fido2MetadataServiceRepository"/> as a scoped service
    /// and configures an HTTP client specifically for communicating with the FIDO Alliance MDS v3
    /// endpoint at https://mds3.fidoalliance.org/. The repository fetches and validates
    /// JWT-signed metadata BLOBs containing authenticator metadata and certification status.
    /// 
    /// The HTTP client is registered with a specific name and can be further configured
    /// using the optional <paramref name="clientBuilder"/> action (e.g., for adding authentication,
    /// custom headers, or timeout settings).
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> is null.</exception>
    public static IFido2NetLibBuilder AddFidoMetadataRepository(this IFido2NetLibBuilder builder, Action<IHttpClientBuilder> clientBuilder = null)
    {
        var httpClientBuilder = builder.Services.AddHttpClient(nameof(Fido2MetadataServiceRepository), client =>
        {
            client.BaseAddress = new Uri("https://mds3.fidoalliance.org/");
        });

        if (clientBuilder != null)
            clientBuilder(httpClientBuilder);

        builder.Services.AddScoped<IMetadataRepository, Fido2MetadataServiceRepository>();

        return builder;
    }
}

/// <summary>
/// Provides a builder interface for configuring FIDO2 services.
/// </summary>
public interface IFido2NetLibBuilder
{
    IServiceCollection Services { get; }
}

/// <summary>
/// Default implementation of <see cref="IFido2NetLibBuilder"/> for configuring FIDO2 services.
/// </summary>
public class Fido2NetLibBuilder : IFido2NetLibBuilder
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Fido2NetLibBuilder"/> class.
    /// </summary>
    /// <param name="services">The services.</param>
    /// <exception cref="System.ArgumentNullException">services</exception>
    public Fido2NetLibBuilder(IServiceCollection services)
    {
        Services = services ?? throw new ArgumentNullException(nameof(services));
    }

    /// <summary>
    /// Gets the services.
    /// </summary>
    /// <value>
    /// The services.
    /// </value>
    public IServiceCollection Services { get; }
}
