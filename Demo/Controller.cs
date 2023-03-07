using System.Text;

using Fido2NetLib;
using Fido2NetLib.Development;

using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Fido2Demo;

[Route("api/[controller]")]
public class MyController : Controller
{
    public static IMetadataService _mds;
    public static readonly DevelopmentInMemoryStore DemoStorage = new DevelopmentInMemoryStore();

    private readonly IConfiguration _configuration;
    private readonly IHostEnvironment _env;

    public MyController(IConfiguration configuration, IHostEnvironment env)
    {
        _configuration = configuration;
        _env = env;
    }

    [HttpGet]
    [Route("/debug")]
    public IActionResult Debug()
    {
        var builder = new StringBuilder();

        builder.AppendLine($"Environment: {_env.EnvironmentName}");
        builder.AppendLine($"fido2:serverDomain: {_configuration["fido2:serverDomain"]}");
        builder.AppendLine($"fido2:origins: {string.Join(",", _configuration["fido2:serverDomain"])}");

        return Ok(builder.ToString());
    }
}
