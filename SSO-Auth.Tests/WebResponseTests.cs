using Jellyfin.Plugin.SSO_Auth;
using Xunit;

namespace SSO_Auth.Tests;

/// <summary>
/// Tests for <see cref="WebResponse"/> — the HTML/JS the plugin returns during the auth flow.
/// Pure string generation, no Jellyfin server required.
/// </summary>
public class WebResponseTests
{
    [Fact]
    public void Generator_ComposesAuthUrl_FromModeAndProvider()
    {
        var html = WebResponse.Generator("the-data", "myprovider", "https://jf.example.com", "OID");

        Assert.Contains("https://jf.example.com/sso/OID/Auth/myprovider", html);
        Assert.Contains("the-data", html);
    }

    [Fact]
    public void Generator_NotLinking_EmitsFalseGuard()
    {
        var html = WebResponse.Generator("d", "p", "https://jf.example.com", "OID", isLinking: false);
        Assert.Contains("if (false)", html);
        Assert.DoesNotContain("if (true)", html);
    }

    [Fact]
    public void Generator_Linking_EmitsTrueGuardAndLinkUrl()
    {
        var html = WebResponse.Generator("d", "p", "https://jf.example.com", "SAML", isLinking: true);
        Assert.Contains("if (true)", html);
        Assert.Contains("/sso/SAML/Link/p/", html);
    }

    [Fact]
    public void Generator_ConvertsUnicodeHostToPunycode()
    {
        var html = WebResponse.Generator("d", "p", "https://exämple.com", "OID");

        // The internationalized domain is converted to its ASCII (punycode) form.
        Assert.Contains("https://xn--exmple-cua.com/sso/OID/Auth/p", html);
        Assert.DoesNotContain("exämple.com", html);
    }

    [Fact]
    public void LoadingRedirect_EmitsSpinnerAndRedirect()
    {
        var html = WebResponse.LoadingRedirect("https://idp.example.com/authorize?client_id=abc");

        Assert.Contains("window.location.replace(", html);
        Assert.Contains("http-equiv='refresh'", html);
    }

    [Fact]
    public void LoadingRedirect_EncodesUrl_PreventingBreakout()
    {
        // A URL containing characters that could break out of the HTML/JS context must be encoded.
        var html = WebResponse.LoadingRedirect("https://idp/a?b=1&c=\"x\"");

        // HTML-encoded in the <meta> refresh.
        Assert.Contains("&amp;", html);
        // JSON-encoded in the script: System.Text.Json escapes the quote as ".
        Assert.Contains("\\u0022", html);
        // The raw, unescaped breakout sequence must not appear anywhere.
        Assert.DoesNotContain("c=\"x\"", html);
    }
}
