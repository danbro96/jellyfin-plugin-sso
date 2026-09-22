using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace Jellyfin.Plugin.SSO_Auth.Api;

/// <summary>
/// Tracks in-progress OpenID flows. A state is only ever redeemable once, at the provider
/// that issued it, and only within its lifetime.
/// </summary>
public sealed class OidStateStore
{
    private readonly ConcurrentDictionary<string, TimedAuthorizeState> _states = new ConcurrentDictionary<string, TimedAuthorizeState>();
    private readonly TimeSpan _lifetime;
    private readonly Func<DateTime> _clock;

    /// <summary>
    /// Initializes a new instance of the <see cref="OidStateStore"/> class.
    /// </summary>
    /// <param name="lifetime">How long a state remains redeemable.</param>
    /// <param name="clock">Source of the current UTC time.</param>
    public OidStateStore(TimeSpan lifetime, Func<DateTime> clock)
    {
        _lifetime = lifetime;
        _clock = clock;
    }

    /// <summary>
    /// Gets the shared store used by the controller.
    /// </summary>
    public static OidStateStore Instance { get; } = new OidStateStore(TimeSpan.FromMinutes(1), () => DateTime.UtcNow);

    /// <summary>
    /// Adds a state, replacing any existing entry with the same key.
    /// </summary>
    /// <param name="state">The state to track.</param>
    public void Add(TimedAuthorizeState state)
    {
        _states[state.State.State] = state;
    }

    /// <summary>
    /// Gets a state for the given provider, if it exists and has not expired.
    /// </summary>
    /// <param name="stateValue">The state value to look up.</param>
    /// <param name="provider">The provider the request arrived at.</param>
    /// <returns>The matching state, or null.</returns>
    public TimedAuthorizeState Get(string stateValue, string provider)
    {
        if (stateValue == null || !_states.TryGetValue(stateValue, out var state))
        {
            return null;
        }

        return IsExpired(state) || !IssuedBy(state, provider) ? null : state;
    }

    /// <summary>
    /// Removes and returns a validated state, so it cannot be redeemed twice.
    /// </summary>
    /// <param name="stateValue">The state value to redeem.</param>
    /// <param name="provider">The provider the request arrived at.</param>
    /// <returns>The redeemed state, or null if it is missing, expired, unvalidated or from another provider.</returns>
    public TimedAuthorizeState Redeem(string stateValue, string provider)
    {
        var state = Get(stateValue, provider);
        if (state == null || !state.Valid)
        {
            return null;
        }

        return _states.TryRemove(stateValue, out var removed) ? removed : null;
    }

    /// <summary>
    /// Drops every expired state.
    /// </summary>
    public void RemoveExpired()
    {
        foreach (var kvp in _states.ToArray())
        {
            if (IsExpired(kvp.Value))
            {
                _states.TryRemove(kvp.Key, out _);
            }
        }
    }

    /// <summary>
    /// Lists the tracked flows without exposing the PKCE code verifier or nonce.
    /// </summary>
    /// <returns>A redacted view of each tracked flow.</returns>
    public IReadOnlyList<OidStateInfo> List()
    {
        return _states.ToArray().Select(kvp => new OidStateInfo
        {
            State = kvp.Key,
            Provider = kvp.Value.Provider,
            Created = kvp.Value.Created,
            Valid = kvp.Value.Valid,
            IsLinking = kvp.Value.IsLinking,
            Username = kvp.Value.Username,
        }).ToList();
    }

    private static bool IssuedBy(TimedAuthorizeState state, string provider)
    {
        return string.Equals(state.Provider, provider, StringComparison.Ordinal);
    }

    private bool IsExpired(TimedAuthorizeState state)
    {
        return _clock().Subtract(state.Created) > _lifetime;
    }
}
