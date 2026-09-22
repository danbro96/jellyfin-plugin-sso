using System;
using System.IO;
using System.Linq;
using System.Xml.Serialization;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace SSO_Auth.Tests;

/// <summary>
/// Pins the on-disk config schema against a frozen 4.x SSO-Auth.xml, so an upgrade
/// to 5.x cannot silently drop a provider or an account link.
/// </summary>
public class ConfigUpgradeTests
{
    private static PluginConfiguration LoadFixture()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "TestData", "config-4.1.2.xml");
        using var reader = new StreamReader(path);
        return (PluginConfiguration)new XmlSerializer(typeof(PluginConfiguration)).Deserialize(reader)!;
    }

    [Fact]
    public void Deserializes_OidProvider_FromFourDotXConfig()
    {
        var oid = LoadFixture().OidConfigs["authentik"];

        Assert.Equal("https://auth.example.com/application/o/jellyfin/", oid.OidEndpoint);
        Assert.Equal("jellyfin", oid.OidClientId);
        Assert.Equal("s3cr3t", oid.OidSecret);
        Assert.True(oid.Enabled);
        Assert.True(oid.EnableAuthorization);
        Assert.True(oid.EnableAllFolders);
        Assert.Equal(new[] { "folder-a" }, oid.EnabledFolders);
        Assert.Equal(new[] { "jellyfin-admins", "platform-admins" }, oid.AdminRoles);
        Assert.Equal(new[] { "jellyfin-users", "jellyfin-admins" }, oid.Roles);
        Assert.Equal("groups", oid.RoleClaim);
        Assert.Equal(new[] { "email", "groups" }, oid.OidScopes);
        Assert.Equal("preferred_username", oid.DefaultUsernameClaim);
        Assert.Equal("Jellyfin", oid.DefaultProvider);
        Assert.Equal("https", oid.SchemeOverride);
        Assert.Equal(8920, oid.PortOverride);
        Assert.True(oid.NewPath);
        Assert.True(oid.DisablePushedAuthorization);
        Assert.False(oid.DisableHttps);
        Assert.False(oid.DoNotLoadProfile);
    }

    [Fact]
    public void Deserializes_LiveTvAndFolderRoles_FromFourDotXConfig()
    {
        var oid = LoadFixture().OidConfigs["authentik"];

        Assert.True(oid.EnableFolderRoles);
        Assert.True(oid.EnableLiveTvRoles);
        Assert.True(oid.EnableLiveTv);
        Assert.False(oid.EnableLiveTvManagement);
        Assert.Equal(new[] { "tv-users" }, oid.LiveTvRoles);
        Assert.Equal(new[] { "tv-admins" }, oid.LiveTvManagementRoles);

        var map = Assert.Single(oid.FolderRoleMapping);
        Assert.Equal("jellyfin-users", map.Role);
        Assert.Equal(new[] { "movies", "shows" }, map.Folders);
    }

    [Fact]
    public void Preserves_CanonicalLinks_AcrossUpgrade()
    {
        var config = LoadFixture();

        var oidLinks = config.OidConfigs["authentik"].CanonicalLinks;
        Assert.Equal(2, oidLinks.Count);
        Assert.Equal(Guid.Parse("11111111-2222-3333-4444-555555555555"), oidLinks["DanBro"]);
        Assert.Equal(Guid.Parse("66666666-7777-8888-9999-000000000000"), oidLinks["AntAlf"]);

        var samlLinks = config.SamlConfigs["okta"].CanonicalLinks;
        Assert.Equal(Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"), Assert.Single(samlLinks).Value);
    }

    [Fact]
    public void Deserializes_SamlProvider_FromFourDotXConfig()
    {
        var saml = LoadFixture().SamlConfigs["okta"];

        Assert.Equal("https://okta.example.com/sso/saml", saml.SamlEndpoint);
        Assert.Equal("jellyfin-saml", saml.SamlClientId);
        Assert.Equal("MIIBfakecert", saml.SamlCertificate);
        Assert.True(saml.Enabled);
        Assert.False(saml.EnableAllFolders);
        Assert.Equal(new[] { "folder-b" }, saml.EnabledFolders);
        Assert.Equal(new[] { "saml-admins" }, saml.AdminRoles);
        Assert.Equal(new[] { "saml-users" }, saml.Roles);
        Assert.Null(saml.PortOverride);
        Assert.False(saml.NewPath);
    }

    [Fact]
    public void CanonicalLinks_WritesSurviveOnAFreshConfig()
    {
        // The getter used to hand out a throwaway dictionary when the backing field was
        // null, so writes through it were silently discarded.
        var config = new OidConfig();
        var id = Guid.NewGuid();

        config.CanonicalLinks["someone"] = id;

        Assert.Equal(id, config.CanonicalLinks["someone"]);
    }

    [Fact]
    public void IgnoresUnknownElements()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "TestData", "config-4.1.2.xml");
        var xml = File.ReadAllText(path)
            .Replace("<NewPath>true</NewPath>", "<NewPath>true</NewPath><SomeFutureSetting>x</SomeFutureSetting>", StringComparison.Ordinal);

        using var reader = new StringReader(xml);
        var config = (PluginConfiguration)new XmlSerializer(typeof(PluginConfiguration)).Deserialize(reader)!;

        Assert.True(config.OidConfigs["authentik"].Enabled);
    }
}
