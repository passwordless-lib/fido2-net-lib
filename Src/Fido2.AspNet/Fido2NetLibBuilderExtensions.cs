using Fido2NetLib;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

public static class Fido2NetLibBuilderExtensions
{
    public static IFido2NetLibBuilder AddFido2(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<Fido2Configuration>(configuration);

        services.AddSingleton(
            resolver => resolver.GetRequiredService<IOptions<Fido2Configuration>>().Value);

        services.AddScoped<IFido2, Fido2>();
        services.TryAddSingleton<ISystemClock, SystemClock>();

        return new Fido2NetLibBuilder(services);
    }

    public static IFido2NetLibBuilder AddFido2(this IServiceCollection services, Action<Fido2Configuration> setupAction)
    {
        services.Configure(setupAction);

        services.AddSingleton(
            resolver => resolver.GetRequiredService<IOptions<Fido2Configuration>>().Value);

        services.AddScoped<IFido2, Fido2>();
        services.TryAddSingleton<ISystemClock, SystemClock>();

        return new Fido2NetLibBuilder(services);
    }
    
    public static IFido2NetLibBuilder AddMetadataService<T>(this IFido2NetLibBuilder builder)
        where T : class, IMetadataService
    {
        builder.Services.AddScoped<IMetadataService, T>();
        return builder;
    }
    
    
    public static IFido2NetLibBuilder AddCachedMetadataService(this IFido2NetLibBuilder builder)
    {
        builder.Services.AddScoped<IMetadataService, DistributedCacheMetadataService>();
        return builder;
    }

    public static IFido2NetLibBuilder AddFileSystemMetadataRepository(this IFido2NetLibBuilder builder, string directoryPath)
    {
        builder.Services.AddScoped<IMetadataRepository, FileSystemMetadataRepository>(provider =>
        {
            return new FileSystemMetadataRepository(directoryPath);
        });

        return builder;
    }

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

public interface IFido2NetLibBuilder
{
    IServiceCollection Services { get; }
}

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
