using BlazorWasmDemo.Client;
using BlazorWasmDemo.Client.Shared;
using BlazorWasmDemo.Client.Shared.Toasts;

using Fido2.BlazorWebAssembly;

using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddSingleton(_ => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });
builder.Services.AddSingleton<ToastService>();
builder.Services.AddSingleton<UserService>();
builder.Services.AddWebAuthn();

await builder.Build().RunAsync();

internal class Constants
{
    public const string GithubBaseUrl = "https://github.com/passwordless-lib/fido2-net-lib/blob/master/";
}
