using System;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// A redacted view of an in-progress OpenID flow.
/// </summary>
public sealed class OidStateInfo
{
    /// <summary>
    /// Gets or sets the state value keying the flow.
    /// </summary>
    public required string State { get; set; }

    /// <summary>
    /// Gets or sets the provider that issued the state.
    /// </summary>
    public required string Provider { get; set; }

    /// <summary>
    /// Gets or sets when the flow started.
    /// </summary>
    public required DateTime Created { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the flow has been validated.
    /// </summary>
    public required bool Valid { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the flow is an account link rather than a login.
    /// </summary>
    public required bool IsLinking { get; set; }

    /// <summary>
    /// Gets or sets the resolved provider username, if the flow has progressed that far.
    /// </summary>
    public required string Username { get; set; }
}
