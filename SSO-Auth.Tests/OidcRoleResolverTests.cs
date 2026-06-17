using System.Collections.Generic;
using System.Security.Claims;
using Jellyfin.Plugin.SSO_Auth.Api;
using Jellyfin.Plugin.SSO_Auth.Config;
using Xunit;

namespace SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="OidcRoleResolver"/> — the OIDC claim -> authorization mapping extracted
/// from the OID callback. Pure logic, no Jellyfin server required.
/// </summary>
public class OidcRoleResolverTests
{
    private static Claim[] Claims(params (string Type, string Value)[] claims)
    {
        var list = new List<Claim>();
        foreach (var (type, value) in claims)
        {
            list.Add(new Claim(type, value));
        }

        return list.ToArray();
    }

    [Fact]
    public void NoRolesConfigured_PreferredUsername_GrantsAccess()
    {
        var config = new OidConfig { Roles = null };
        var result = OidcRoleResolver.Resolve(Claims(("preferred_username", "alice")), config);

        Assert.True(result.Valid);
        Assert.Equal("alice", result.Username);
        Assert.False(result.Admin);
    }

    [Fact]
    public void NoRolesConfigured_EmptyRolesArray_GrantsAccess()
    {
        var config = new OidConfig { Roles = System.Array.Empty<string>() };
        var result = OidcRoleResolver.Resolve(Claims(("preferred_username", "bob")), config);

        Assert.True(result.Valid);
        Assert.Equal("bob", result.Username);
    }

    [Fact]
    public void CustomUsernameClaim_IsHonored()
    {
        var config = new OidConfig { DefaultUsernameClaim = "email" };
        var result = OidcRoleResolver.Resolve(Claims(("email", "carol@example.com")), config);

        Assert.True(result.Valid);
        Assert.Equal("carol@example.com", result.Username);
    }

    [Fact]
    public void SubFallback_UsedWhenPreferredUsernameMissing()
    {
        var config = new OidConfig { Roles = null };
        var result = OidcRoleResolver.Resolve(Claims(("sub", "user-123")), config);

        Assert.True(result.Valid);
        Assert.Equal("user-123", result.Username);
    }

    [Fact]
    public void RolesConfigured_MatchingRole_GrantsAccess()
    {
        var config = new OidConfig
        {
            Roles = new[] { "jellyfin-user" },
            RoleClaim = "roles",
        };
        var result = OidcRoleResolver.Resolve(
            Claims(("preferred_username", "dave"), ("roles", "jellyfin-user")),
            config);

        Assert.True(result.Valid);
        Assert.Equal("dave", result.Username);
    }

    [Fact]
    public void RolesConfigured_NonMatchingRole_DeniesAccess()
    {
        var config = new OidConfig
        {
            Roles = new[] { "jellyfin-user" },
            RoleClaim = "roles",
        };
        var result = OidcRoleResolver.Resolve(
            Claims(("preferred_username", "eve"), ("roles", "some-other-role")),
            config);

        Assert.False(result.Valid);
        // Username is still captured even when access is denied.
        Assert.Equal("eve", result.Username);
    }

    [Fact]
    public void AdminRole_SetsAdmin()
    {
        var config = new OidConfig
        {
            Roles = new[] { "user" },
            AdminRoles = new[] { "admin" },
            RoleClaim = "roles",
        };
        var result = OidcRoleResolver.Resolve(
            Claims(("preferred_username", "frank"), ("roles", "admin")),
            config);

        Assert.True(result.Admin);
    }

    [Fact]
    public void NestedJsonRoleClaim_ResolvesRolesArray()
    {
        // RoleClaim path: resource_access.jellyfin.roles -> ["jellyfin-user"]
        var config = new OidConfig
        {
            Roles = new[] { "jellyfin-user" },
            RoleClaim = "resource_access.jellyfin.roles",
        };
        var claimValue = "{\"jellyfin\":{\"roles\":[\"jellyfin-user\",\"other\"]}}";
        var result = OidcRoleResolver.Resolve(
            Claims(("preferred_username", "grace"), ("resource_access", claimValue)),
            config);

        Assert.True(result.Valid);
    }

    [Fact]
    public void EscapedDotInRoleClaim_TreatedAsLiteral()
    {
        // "resource\.access" is a single literal segment containing a dot, then ".roles".
        var config = new OidConfig
        {
            Roles = new[] { "admin" },
            RoleClaim = "resource\\.access.roles",
        };
        var claimValue = "{\"roles\":[\"admin\"]}";
        var result = OidcRoleResolver.Resolve(
            Claims(("preferred_username", "heidi"), ("resource.access", claimValue)),
            config);

        Assert.True(result.Valid);
    }

    [Fact]
    public void SingleSegmentRoleClaim_UsesRawClaimValue()
    {
        var config = new OidConfig
        {
            Roles = new[] { "vip" },
            RoleClaim = "membership",
        };
        var result = OidcRoleResolver.Resolve(
            Claims(("preferred_username", "ivan"), ("membership", "vip")),
            config);

        Assert.True(result.Valid);
    }

    [Fact]
    public void MalformedJsonRoleClaim_DoesNotThrow_DeniesAccess()
    {
        var config = new OidConfig
        {
            Roles = new[] { "jellyfin-user" },
            RoleClaim = "resource_access.roles",
        };
        var result = OidcRoleResolver.Resolve(
            Claims(("preferred_username", "judy"), ("resource_access", "this is not json")),
            config);

        Assert.False(result.Valid);
    }

    [Fact]
    public void MissingIntermediateSegment_DeniesAccess()
    {
        var config = new OidConfig
        {
            Roles = new[] { "jellyfin-user" },
            RoleClaim = "resource_access.jellyfin.roles",
        };
        // No "jellyfin" object present.
        var result = OidcRoleResolver.Resolve(
            Claims(("preferred_username", "ken"), ("resource_access", "{\"other\":{\"roles\":[\"x\"]}}")),
            config);

        Assert.False(result.Valid);
    }

    [Fact]
    public void FolderRoles_AccumulatedOnlyWhenEnabled()
    {
        var mapping = new List<FolderRoleMap>
        {
            new FolderRoleMap { Role = "media", Folders = new List<string> { "folder-1", "folder-2" } },
        };

        var enabled = new OidConfig
        {
            Roles = new[] { "media" },
            RoleClaim = "roles",
            EnableFolderRoles = true,
            FolderRoleMapping = mapping,
        };
        var enabledResult = OidcRoleResolver.Resolve(
            Claims(("preferred_username", "laura"), ("roles", "media")),
            enabled);
        Assert.Equal(new[] { "folder-1", "folder-2" }, enabledResult.Folders);

        var disabled = new OidConfig
        {
            Roles = new[] { "media" },
            RoleClaim = "roles",
            EnableFolderRoles = false,
            FolderRoleMapping = mapping,
        };
        var disabledResult = OidcRoleResolver.Resolve(
            Claims(("preferred_username", "laura"), ("roles", "media")),
            disabled);
        Assert.Empty(disabledResult.Folders);
    }

    [Fact]
    public void LiveTvRoles_GatedByEnableLiveTvRoles()
    {
        var config = new OidConfig
        {
            Roles = new[] { "tv" },
            RoleClaim = "roles",
            EnableLiveTvRoles = true,
            LiveTvRoles = new[] { "tv" },
            LiveTvManagementRoles = new[] { "tv-admin" },
        };
        var result = OidcRoleResolver.Resolve(
            Claims(("preferred_username", "mike"), ("roles", "tv")),
            config);
        Assert.True(result.EnableLiveTv);
        Assert.False(result.EnableLiveTvManagement);

        var disabled = new OidConfig
        {
            Roles = new[] { "tv" },
            RoleClaim = "roles",
            EnableLiveTvRoles = false,
            LiveTvRoles = new[] { "tv" },
        };
        var disabledResult = OidcRoleResolver.Resolve(
            Claims(("preferred_username", "mike"), ("roles", "tv")),
            disabled);
        Assert.False(disabledResult.EnableLiveTv);
    }
}
