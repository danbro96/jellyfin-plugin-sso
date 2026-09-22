using System.Text.Json;
using Jellyfin.Plugin.SSO_Auth.Api;

namespace SSO_Auth.Tests;

/// <summary>
/// The callback page posts camelCase keys into the PascalCase AuthResponse, which only
/// binds because Jellyfin leaves MVC's case-insensitive web defaults in place. If that
/// ever changes every field silently binds null and login fails with a generic error.
/// </summary>
public class AuthResponseBindingTests
{
    // Mirrors Microsoft.AspNetCore.Mvc.JsonOptions, which Jellyfin overrides only for
    // naming policy, converters, comments, indentation and number handling.
    private static readonly JsonSerializerOptions MvcLike = new JsonSerializerOptions(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = null,
    };

    [Fact]
    public void BindsCamelCasePayloadFromTheCallbackPage()
    {
        const string Payload = """
            {"deviceId":"abc123","appName":"Jellyfin Web","appVersion":"10.8.0","deviceName":"Firefox","data":"state-value"}
            """;

        var response = JsonSerializer.Deserialize<AuthResponse>(Payload, MvcLike);

        Assert.NotNull(response);
        Assert.Equal("abc123", response!.DeviceID);
        Assert.Equal("Jellyfin Web", response.AppName);
        Assert.Equal("10.8.0", response.AppVersion);
        Assert.Equal("Firefox", response.DeviceName);
        Assert.Equal("state-value", response.Data);
    }

    [Fact]
    public void BindsPascalCasePayloadToo()
    {
        const string Payload = """
            {"DeviceID":"abc123","AppName":"Jellyfin Web","AppVersion":"10.8.0","DeviceName":"Firefox","Data":"state-value"}
            """;

        var response = JsonSerializer.Deserialize<AuthResponse>(Payload, MvcLike);

        Assert.Equal("abc123", response!.DeviceID);
        Assert.Equal("state-value", response.Data);
    }
}
