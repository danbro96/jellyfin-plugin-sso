using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient;
using Jellyfin.Plugin.SSO_Auth.Api;

namespace SSO_Auth.Tests;

public class OidStateStoreTests
{
    private DateTime _now = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);

    private OidStateStore NewStore(TimeSpan? lifetime = null)
        => new OidStateStore(lifetime ?? TimeSpan.FromMinutes(1), () => _now);

    private TimedAuthorizeState NewState(string stateValue, string provider, bool valid = true, string username = "bob")
    {
        var state = new TimedAuthorizeState(new AuthorizeState { State = stateValue }, _now, provider)
        {
            Valid = valid,
            Username = username,
            Folders = new List<string>(),
        };
        return state;
    }

    [Fact]
    public void Redeem_ReturnsState_ForIssuingProvider()
    {
        var store = NewStore();
        store.Add(NewState("abc", "authentik"));

        var redeemed = store.Redeem("abc", "authentik");

        Assert.NotNull(redeemed);
        Assert.Equal("bob", redeemed!.Username);
    }

    [Fact]
    public void Redeem_RejectsStateFromAnotherProvider()
    {
        var store = NewStore();
        store.Add(NewState("abc", "low-trust-idp"));

        Assert.Null(store.Redeem("abc", "corporate-idp"));
        Assert.Null(store.Get("abc", "corporate-idp"));

        // Still redeemable at the provider that issued it.
        Assert.NotNull(store.Redeem("abc", "low-trust-idp"));
    }

    [Fact]
    public void Redeem_IsOneShot()
    {
        var store = NewStore();
        store.Add(NewState("abc", "authentik"));

        Assert.NotNull(store.Redeem("abc", "authentik"));
        Assert.Null(store.Redeem("abc", "authentik"));
    }

    [Fact]
    public void Redeem_RejectsExpiredState_EvenWithoutASweep()
    {
        var store = NewStore(TimeSpan.FromMinutes(1));
        store.Add(NewState("abc", "authentik"));

        _now = _now.AddMinutes(2);

        Assert.Null(store.Get("abc", "authentik"));
        Assert.Null(store.Redeem("abc", "authentik"));
    }

    [Fact]
    public void Redeem_RejectsUnvalidatedState()
    {
        var store = NewStore();
        store.Add(NewState("abc", "authentik", valid: false));

        Assert.Null(store.Redeem("abc", "authentik"));

        // Get still resolves it, so the callback can populate it.
        Assert.NotNull(store.Get("abc", "authentik"));
    }

    [Fact]
    public void Redeem_RejectsUnknownOrNullState()
    {
        var store = NewStore();

        Assert.Null(store.Redeem("nope", "authentik"));
        Assert.Null(store.Redeem(null, "authentik"));
    }

    [Fact]
    public void RemoveExpired_DropsOnlyExpiredEntries()
    {
        var store = NewStore(TimeSpan.FromMinutes(1));
        store.Add(NewState("old", "authentik"));

        _now = _now.AddMinutes(2);
        store.Add(NewState("fresh", "authentik"));

        store.RemoveExpired();

        Assert.Null(store.Get("old", "authentik"));
        Assert.NotNull(store.Get("fresh", "authentik"));
    }

    [Fact]
    public void List_DoesNotExposeCodeVerifierOrNonce()
    {
        var store = NewStore();
        var state = new TimedAuthorizeState(
            new AuthorizeState { State = "abc", CodeVerifier = "super-secret-verifier" },
            _now,
            "authentik")
        {
            Username = "bob",
            Folders = new List<string>(),
        };
        store.Add(state);

        var listed = Assert.Single(store.List());

        Assert.Equal("abc", listed.State);
        Assert.Equal("authentik", listed.Provider);
        Assert.Equal("bob", listed.Username);
        Assert.DoesNotContain("super-secret-verifier", System.Text.Json.JsonSerializer.Serialize(listed), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConcurrentAddAndSweep_DoesNotThrowAndRedeemsExactlyOnce()
    {
        var store = NewStore(TimeSpan.FromMinutes(5));
        const int Count = 500;

        var adds = Task.Run(() =>
        {
            for (int i = 0; i < Count; i++)
            {
                store.Add(NewState("state-" + i.ToString(System.Globalization.CultureInfo.InvariantCulture), "authentik"));
            }
        });

        var sweeps = Task.Run(() =>
        {
            for (int i = 0; i < Count; i++)
            {
                store.RemoveExpired();
                store.List();
            }
        });

        await Task.WhenAll(adds, sweeps);

        var redeemers = Enumerable.Range(0, 8)
            .Select(_ => Task.Run(() => store.Redeem("state-1", "authentik")))
            .ToArray();
        var results = await Task.WhenAll(redeemers);

        Assert.Single(results, r => r != null);
    }
}
