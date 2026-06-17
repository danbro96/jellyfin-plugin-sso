using System.Collections.Generic;
using System.IO;
using System.Xml.Serialization;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace SSO_Auth.Tests;

/// <summary>
/// Tests for XML serialization of the plugin configuration types. Jellyfin persists plugin
/// configuration via XmlSerializer, so a round-trip must preserve the configured values —
/// including the custom <see cref="SerializableDictionary{TKey,TValue}"/>.
/// </summary>
public class ConfigSerializationTests
{
    private static T RoundTrip<T>(T value)
    {
        var serializer = new XmlSerializer(typeof(T));
        using var buffer = new MemoryStream();
        serializer.Serialize(buffer, value);
        buffer.Position = 0;
        return (T)serializer.Deserialize(buffer)!;
    }

    [Fact]
    public void SerializableDictionary_RoundTrips()
    {
        var original = new SerializableDictionary<string, string>
        {
            ["alpha"] = "one",
            ["beta"] = "two",
        };

        var restored = RoundTrip(original);

        Assert.Equal(2, restored.Count);
        Assert.Equal("one", restored["alpha"]);
        Assert.Equal("two", restored["beta"]);
    }

    [Fact]
    public void PluginConfiguration_DefaultsAreEmptyButNotNull()
    {
        var config = new PluginConfiguration();

        Assert.NotNull(config.OidConfigs);
        Assert.NotNull(config.SamlConfigs);
        Assert.Empty(config.OidConfigs);
        Assert.Empty(config.SamlConfigs);
    }

    [Fact]
    public void PluginConfiguration_RoundTrips_OidProviderWithRolesAndFolders()
    {
        var config = new PluginConfiguration();
        config.OidConfigs["keycloak"] = new OidConfig
        {
            OidEndpoint = "https://idp.example.com",
            OidClientId = "jellyfin",
            Enabled = true,
            Roles = new[] { "jellyfin-user" },
            AdminRoles = new[] { "jellyfin-admin" },
            RoleClaim = "resource_access.jellyfin.roles",
            EnableFolderRoles = true,
            FolderRoleMapping = new List<FolderRoleMap>
            {
                new FolderRoleMap { Role = "media", Folders = new List<string> { "folder-1" } },
            },
        };

        var restored = RoundTrip(config);

        Assert.True(restored.OidConfigs.ContainsKey("keycloak"));
        var oid = restored.OidConfigs["keycloak"];
        Assert.Equal("https://idp.example.com", oid.OidEndpoint);
        Assert.Equal("jellyfin", oid.OidClientId);
        Assert.True(oid.Enabled);
        Assert.Equal(new[] { "jellyfin-user" }, oid.Roles);
        Assert.Equal("resource_access.jellyfin.roles", oid.RoleClaim);
        Assert.True(oid.EnableFolderRoles);
        Assert.Single(oid.FolderRoleMapping);
        Assert.Equal("media", oid.FolderRoleMapping[0].Role);
        Assert.Equal(new[] { "folder-1" }, oid.FolderRoleMapping[0].Folders);
    }

    [Fact]
    public void PluginConfiguration_RoundTrips_SamlProvider()
    {
        var config = new PluginConfiguration();
        config.SamlConfigs["okta"] = new SamlConfig
        {
            SamlEndpoint = "https://okta.example.com/sso",
            SamlClientId = "jellyfin",
            SamlCertificate = "BASE64CERT",
            Enabled = true,
            EnabledFolders = new[] { "movies", "shows" },
        };

        var restored = RoundTrip(config);

        Assert.True(restored.SamlConfigs.ContainsKey("okta"));
        var saml = restored.SamlConfigs["okta"];
        Assert.Equal("https://okta.example.com/sso", saml.SamlEndpoint);
        Assert.Equal("jellyfin", saml.SamlClientId);
        Assert.Equal("BASE64CERT", saml.SamlCertificate);
        Assert.True(saml.Enabled);
        Assert.Equal(new[] { "movies", "shows" }, saml.EnabledFolders);
    }
}
