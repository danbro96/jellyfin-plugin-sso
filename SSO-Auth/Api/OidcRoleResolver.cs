using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Jellyfin.Plugin.SSO_Auth.Config;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// The outcome of evaluating an OpenID provider's claims against an <see cref="OidConfig"/>.
/// The values are role-derived signals; the caller merges them onto the configuration-based
/// defaults (it never downgrades an already-granted permission).
/// </summary>
public sealed class OidcAuthorizationResult
{
    /// <summary>
    /// Gets or sets the resolved username (from the configured username claim, or the "sub"
    /// fallback). <c>null</c> when no matching claim was present.
    /// </summary>
    public string Username { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the user is permitted to sign in.
    /// </summary>
    public bool Valid { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the user is an administrator.
    /// </summary>
    public bool Admin { get; set; }

    /// <summary>
    /// Gets the folders granted via role mapping. Only populated when
    /// <see cref="OidConfig.EnableFolderRoles"/> is set.
    /// </summary>
    public List<string> Folders { get; } = new List<string>();

    /// <summary>
    /// Gets or sets a value indicating whether a role granted Live TV access.
    /// </summary>
    public bool EnableLiveTv { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether a role granted Live TV management.
    /// </summary>
    public bool EnableLiveTvManagement { get; set; }
}

/// <summary>
/// Resolves OpenID claims into a Jellyfin authorization decision (username, validity, admin,
/// folder access, and Live TV access). This logic was extracted verbatim from the OID callback
/// so it can be unit-tested in isolation; it uses <see cref="System.Text.Json"/> rather than a
/// third-party JSON library.
/// </summary>
public static class OidcRoleResolver
{
    /// <summary>
    /// Evaluates the provided claims against the given provider configuration.
    /// </summary>
    /// <param name="claims">The claims returned by the OpenID provider.</param>
    /// <param name="config">The provider configuration.</param>
    /// <returns>The role-derived authorization signals.</returns>
    public static OidcAuthorizationResult Resolve(IEnumerable<Claim> claims, OidConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        var claimList = claims is null ? Array.Empty<Claim>() : claims.ToArray();

        var result = new OidcAuthorizationResult();
        bool noRolesConfigured = config.Roles == null || config.Roles.Length == 0;

        // The regex splits on any "." not preceded by a "\": a.b.c -> a, b, c, but a.b\.c -> a, b.c
        // (after the escaped dots are unescaped). This claim path is invariant, so split it once.
        string[] segments = string.IsNullOrEmpty(config.RoleClaim)
            ? Array.Empty<string>()
            : Regex.Split(config.RoleClaim.Trim(), "(?<!\\\\)\\.").Select(i => i.Replace("\\.", ".")).ToArray();

        foreach (var claim in claimList)
        {
            if (claim.Type == (config.DefaultUsernameClaim?.Trim() ?? "preferred_username"))
            {
                result.Username = claim.Value;
                if (noRolesConfigured)
                {
                    result.Valid = true;
                }
            }

            if (segments.Length > 0 && claim.Type == segments[0])
            {
                foreach (string role in ExtractRoles(claim.Value, segments))
                {
                    ApplyRole(role, config, result);
                }
            }
        }

        // If the preferred-username claim didn't grant access, fall back to the "sub" claim.
        if (!result.Valid)
        {
            foreach (var claim in claimList)
            {
                if (claim.Type == "sub")
                {
                    result.Username = claim.Value;
                    if (noRolesConfigured)
                    {
                        result.Valid = true;
                    }
                }
            }
        }

        return result;
    }

    // Applies a single role to the result: validity, admin, folder, and Live TV mappings.
    private static void ApplyRole(string role, OidConfig config, OidcAuthorizationResult result)
    {
        if (config.Roles != null && config.Roles.Contains(role))
        {
            result.Valid = true;
        }

        if (config.AdminRoles != null && config.AdminRoles.Contains(role))
        {
            result.Admin = true;
        }

        if (config.EnableFolderRoles && config.FolderRoleMapping != null)
        {
            foreach (FolderRoleMap folderRoleMap in config.FolderRoleMapping)
            {
                if (role.Equals(folderRoleMap.Role?.Trim(), StringComparison.Ordinal) && folderRoleMap.Folders != null)
                {
                    result.Folders.AddRange(folderRoleMap.Folders);
                }
            }
        }

        if (config.EnableLiveTvRoles)
        {
            if (config.LiveTvRoles != null && config.LiveTvRoles.Contains(role))
            {
                result.EnableLiveTv = true;
            }

            if (config.LiveTvManagementRoles != null && config.LiveTvManagementRoles.Contains(role))
            {
                result.EnableLiveTvManagement = true;
            }
        }
    }

    // Extracts the roles from a claim value. With a single-segment role claim the value is the
    // role itself; otherwise the value is JSON and we traverse the nested objects to the final
    // segment, which must be an array of strings. Malformed/unexpected JSON yields no roles
    // (the previous Newtonsoft-based code would throw on invalid JSON).
    private static IReadOnlyList<string> ExtractRoles(string claimValue, string[] segments)
    {
        if (segments.Length == 1)
        {
            return new[] { claimValue };
        }

        try
        {
            if (JsonNode.Parse(claimValue) is not JsonObject json)
            {
                return Array.Empty<string>();
            }

            for (int i = 1; i < segments.Length - 1; i++)
            {
                if (json[segments[i]] is not JsonObject next)
                {
                    return Array.Empty<string>();
                }

                json = next;
            }

            if (json[segments[^1]] is not JsonArray rolesArray)
            {
                return Array.Empty<string>();
            }

            return rolesArray
                .Where(node => node is not null)
                .Select(node => node.GetValue<string>())
                .ToList();
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException)
        {
            // Malformed JSON, or a non-string role element: treat as "no roles".
            return Array.Empty<string>();
        }
    }
}
