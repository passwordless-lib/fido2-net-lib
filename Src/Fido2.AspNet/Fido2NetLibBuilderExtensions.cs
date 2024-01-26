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

        services.AddServices();

        return new Fido2NetLibBuilder(services);
    }

    private static void AddServices(this IServiceCollection services)
    {
        services.AddScoped<IFido2, Fido2>();
        services.AddSingleton<IMetadataService, NullMetadataService>(); //Default implementation if we choose not to enable MDS
        services.TryAddSingleton<ISystemClock, SystemClock>();
    }

    public static IFido2NetLibBuilder AddFido2(this IServiceCollection services, Action<Fido2Configuration> setupAction)
    {
        services.Configure(setupAction);

        services.AddSingleton(
            resolver => resolver.GetRequiredService<IOptions<Fido2Configuration>>().Value);

        services.AddServices();

        return new Fido2NetLibBuilder(services);
    }

    public static void AddCachedMetadataService(this IFido2NetLibBuilder builder, Action<IFido2MetadataServiceBuilder> configAction)
    {
        builder.Services.AddScoped<IMetadataService, DistributedCacheMetadataService>();

        configAction(new Fido2NetLibBuilder(builder.Services));
    }

    public static IFido2MetadataServiceBuilder AddFileSystemMetadataRepository(this IFido2MetadataServiceBuilder builder, string directoryPath)
    {
        builder.Services.AddScoped<IMetadataRepository, FileSystemMetadataRepository>(provider =>
        {
            return new FileSystemMetadataRepository(directoryPath);
        });

        return builder;
    }

    public static IFido2MetadataServiceBuilder AddConformanceMetadataRepository(
        this IFido2MetadataServiceBuilder builder,
        HttpClient client = null,
        string origin = "")
    {
        builder.Services.AddScoped<IMetadataRepository>(provider =>
        {
            return new ConformanceMetadataRepository(client, origin);
        });

        return builder;
    }

    public static IFido2MetadataServiceBuilder AddFidoMetadataRepository(this IFido2MetadataServiceBuilder builder, Action<IHttpClientBuilder> clientBuilder = null)
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

public interface IFido2MetadataServiceBuilder
{
    IServiceCollection Services { get; }
}

public class Fido2NetLibBuilder : IFido2NetLibBuilder, IFido2MetadataServiceBuilder
{
    /// <summary>
    /// Initializes a new instance of the <see cref="IdentityServerBuilder"/> class.
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
