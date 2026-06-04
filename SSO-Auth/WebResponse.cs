using System.Globalization;

namespace Jellyfin.Plugin.SSO_Auth;

/// <summary>
/// A helper class to return HTML for the client's auth flow.
/// </summary>
public static class WebResponse
{
    /// <summary>
    /// The shared HTML between all of the responses.
    /// </summary>
    public static readonly string Base = @"<!DOCTYPE html>
<html><head>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<style>
  html, body { height: 100%; }
  body {
    margin: 0;
    background: #101010;
    color: #d1cfce;
    font-family: Noto Sans, Noto Sans HK, Noto Sans JP, Noto Sans KR, Noto Sans SC, Noto Sans TC, sans-serif;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    text-align: center;
  }
  .sso-spinner {
    width: 48px; height: 48px; margin: 0 auto 1.25em;
    border: 4px solid rgba(255, 255, 255, 0.15);
    border-top-color: #00a4dc;
    border-radius: 50%;
    animation: sso-spin 0.9s linear infinite;
  }
  @keyframes sso-spin { to { transform: rotate(360deg); } }
  #sso-status { margin: 0; font-size: 1.05rem; opacity: 0.9; }
</style>
</head><body>
<div class='sso-box'>
  <div class='sso-spinner'></div>
  <p id='sso-status'>Signing in…</p>
</div>
<noscript>Please enable Javascript to complete the login</noscript>
<script>
console.log('[SSO-Auth] callback build: loading-ui');

function isTv() {
    // This is going to be really difficult to get right
    const userAgent = navigator.userAgent.toLowerCase();

    // The OculusBrowsers userAgent also has the samsungbrowser defined but is not a tv.
    if (userAgent.indexOf('oculusbrowser') !== -1) {
        return false;
    }

    if (userAgent.indexOf('tv') !== -1) {
        return true;
    }

    if (userAgent.indexOf('samsungbrowser') !== -1) {
        return true;
    }

    if (userAgent.indexOf('viera') !== -1) {
        return true;
    }

    return isWeb0s();
}

function isWeb0s() {
    const userAgent = navigator.userAgent.toLowerCase();

    return userAgent.indexOf('netcast') !== -1
        || userAgent.indexOf('web0s') !== -1;
}

function isMobile(userAgent) {
    const terms = [
        'mobi',
        'ipad',
        'iphone',
        'ipod',
        'silk',
        'gt-p1000',
        'nexus 7',
        'kindle fire',
        'opera mini'
    ];

    const lower = userAgent.toLowerCase();

    for (let i = 0, length = terms.length; i < length; i++) {
        if (lower.indexOf(terms[i]) !== -1) {
            return true;
        }
    }

    return false;
}

function hasKeyboard(browser) {
    if (browser.touch) {
        return true;
    }

    if (browser.xboxOne) {
        return true;
    }

    if (browser.ps4) {
        return true;
    }

    if (browser.edgeUwp) {
        // This is OK for now, but this won't always be true
        // Should we use this?
        // https://gist.github.com/wagonli/40d8a31bd0d6f0dd7a5d
        return true;
    }

    return !!browser.tv;
}

function iOSversion() {
    // MacIntel: Apple iPad Pro 11 iOS 13.1
    if (/iP(hone|od|ad)|MacIntel/.test(navigator.platform)) {
        const tests = [
            // Original test for getting full iOS version number in iOS 2.0+
            /OS (\d+)_(\d+)_?(\d+)?/,
            // Test for iPads running iOS 13+ that can only get the major OS version
            /Version\/(\d+)/
        ];
        for (const test of tests) {
            const matches = (navigator.appVersion).match(test);
            if (matches) {
                return [
                    parseInt(matches[1], 10),
                    parseInt(matches[2] || 0, 10),
                    parseInt(matches[3] || 0, 10)
                ];
            }
        }
    }
    return [];
}

function web0sVersion(browser) {
    // Detect webOS version by web engine version

    if (browser.chrome) {
        const userAgent = navigator.userAgent.toLowerCase();

        if (userAgent.indexOf('netcast') !== -1) {
            // The built-in browser (NetCast) may have a version that doesn't correspond to the actual web engine
            // Since there is no reliable way to detect webOS version, we return an undefined version

            console.warn('Unable to detect webOS version - NetCast');

            return undefined;
        }

        // The next is only valid for the app

        if (browser.versionMajor >= 94) {
            return 23;
        } else if (browser.versionMajor >= 87) {
            return 22;
        } else if (browser.versionMajor >= 79) {
            return 6;
        } else if (browser.versionMajor >= 68) {
            return 5;
        } else if (browser.versionMajor >= 53) {
            return 4;
        } else if (browser.versionMajor >= 38) {
            return 3;
        } else if (browser.versionMajor >= 34) {
            // webOS 2 browser
            return 2;
        } else if (browser.versionMajor >= 26) {
            // webOS 1 browser
            return 1;
        }
    } else if (browser.versionMajor >= 538) {
        // webOS 2 app
        return 2;
    } else if (browser.versionMajor >= 537) {
        // webOS 1 app
        return 1;
    }

    console.error('Unable to detect webOS version');

    return undefined;
}

let _supportsCssAnimation;
let _supportsCssAnimationWithPrefix;
function supportsCssAnimation(allowPrefix) {
    // TODO: Assess if this is still needed, as all of our targets should natively support CSS animations.
    if (allowPrefix && (_supportsCssAnimationWithPrefix === true || _supportsCssAnimationWithPrefix === false)) {
        return _supportsCssAnimationWithPrefix;
    }
    if (_supportsCssAnimation === true || _supportsCssAnimation === false) {
        return _supportsCssAnimation;
    }

    let animation = false;
    const domPrefixes = ['Webkit', 'O', 'Moz'];
    const elm = document.createElement('div');

    if (elm.style.animationName !== undefined) {
        animation = true;
    }

    if (animation === false && allowPrefix) {
        for (const domPrefix of domPrefixes) {
            if (elm.style[domPrefix + 'AnimationName'] !== undefined) {
                animation = true;
                break;
            }
        }
    }

    if (allowPrefix) {
        _supportsCssAnimationWithPrefix = animation;
        return _supportsCssAnimationWithPrefix;
    } else {
        _supportsCssAnimation = animation;
        return _supportsCssAnimation;
    }
}

const uaMatch = function (ua) {
    ua = ua.toLowerCase();

    const match = /(chrome)[ /]([\w.]+)/.exec(ua)
        || /(edg)[ /]([\w.]+)/.exec(ua)
        || /(edga)[ /]([\w.]+)/.exec(ua)
        || /(edgios)[ /]([\w.]+)/.exec(ua)
        || /(edge)[ /]([\w.]+)/.exec(ua)
        || /(opera)[ /]([\w.]+)/.exec(ua)
        || /(opr)[ /]([\w.]+)/.exec(ua)
        || /(safari)[ /]([\w.]+)/.exec(ua)
        || /(firefox)[ /]([\w.]+)/.exec(ua)
        || ua.indexOf('compatible') < 0 && /(mozilla)(?:.*? rv:([\w.]+)|)/.exec(ua)
        || [];

    const versionMatch = /(version)[ /]([\w.]+)/.exec(ua);

    let platform_match = /(ipad)/.exec(ua)
        || /(iphone)/.exec(ua)
        || /(windows)/.exec(ua)
        || /(android)/.exec(ua)
        || [];

    let browser = match[1] || '';

    if (browser === 'edge') {
        platform_match = [''];
    }

    if (browser === 'opr') {
        browser = 'opera';
    }

    let version;
    if (versionMatch && versionMatch.length > 2) {
        version = versionMatch[2];
    }

    version = version || match[2] || '0';

    let versionMajor = parseInt(version.split('.')[0], 10);

    if (isNaN(versionMajor)) {
        versionMajor = 0;
    }

    return {
        browser: browser,
        version: version,
        platform: platform_match[0] || '',
        versionMajor: versionMajor
    };
};

const userAgent = navigator.userAgent;

const matched = uaMatch(userAgent);
const browser = {};

if (matched.browser) {
    browser[matched.browser] = true;
    browser.version = matched.version;
    browser.versionMajor = matched.versionMajor;
}

if (matched.platform) {
    browser[matched.platform] = true;
}

browser.edgeChromium = browser.edg || browser.edga || browser.edgios;

if (!browser.chrome && !browser.edgeChromium && !browser.edge && !browser.opera && userAgent.toLowerCase().indexOf('webkit') !== -1) {
    browser.safari = true;
}

browser.osx = userAgent.toLowerCase().indexOf('mac os x') !== -1;

// This is a workaround to detect iPads on iOS 13+ that report as desktop Safari
// This may break in the future if Apple releases a touchscreen Mac
// https://forums.developer.apple.com/thread/119186
if (browser.osx && !browser.iphone && !browser.ipod && !browser.ipad && navigator.maxTouchPoints > 1) {
    browser.ipad = true;
}

if (userAgent.toLowerCase().indexOf('playstation 4') !== -1) {
    browser.ps4 = true;
    browser.tv = true;
}

if (isMobile(userAgent)) {
    browser.mobile = true;
}

if (userAgent.toLowerCase().indexOf('xbox') !== -1) {
    browser.xboxOne = true;
    browser.tv = true;
}
browser.animate = typeof document !== 'undefined' && document.documentElement.animate != null;
browser.hisense = userAgent.toLowerCase().includes('hisense');
browser.tizen = userAgent.toLowerCase().indexOf('tizen') !== -1 || window.tizen != null;
browser.vidaa = userAgent.toLowerCase().includes('vidaa');
browser.web0s = isWeb0s();
browser.edgeUwp = browser.edge && (userAgent.toLowerCase().indexOf('msapphost') !== -1 || userAgent.toLowerCase().indexOf('webview') !== -1);

if (browser.web0s) {
    browser.web0sVersion = web0sVersion(browser);
} else if (browser.tizen) {
    // UserAgent string contains 'Safari' and 'safari' is set by matched browser, but we only want 'tizen' to be true
    delete browser.safari;

    const v = (navigator.appVersion).match(/Tizen (\d+).(\d+)/);
    browser.tizenVersion = parseInt(v[1], 10);
} else {
    browser.orsay = userAgent.toLowerCase().indexOf('smarthub') !== -1;
}

if (browser.edgeUwp) {
    browser.edge = true;
}

browser.tv = isTv();
browser.operaTv = browser.tv && userAgent.toLowerCase().indexOf('opr/') !== -1;

if (browser.mobile || browser.tv) {
    browser.slow = true;
}

/* eslint-disable-next-line compat/compat */
if (typeof document !== 'undefined' && ('ontouchstart' in window) || (navigator.maxTouchPoints > 0)) {
    browser.touch = true;
}

browser.keyboard = hasKeyboard(browser);
browser.supportsCssAnimation = supportsCssAnimation;

browser.iOS = browser.ipad || browser.iphone || browser.ipod;

if (browser.iOS) {
    browser.iOSVersion = iOSversion();

    if (browser.iOSVersion && browser.iOSVersion.length >= 2) {
        browser.iOSVersion = browser.iOSVersion[0] + (browser.iOSVersion[1] / 10);
    }
}

function getDeviceName() {
	var deviceName = '';
    if (!deviceName) {
        if (browser.tizen) {
            deviceName = 'Samsung Smart TV';
        } else if (browser.web0s) {
            deviceName = 'LG Smart TV';
        } else if (browser.operaTv) {
            deviceName = 'Opera TV';
        } else if (browser.xboxOne) {
            deviceName = 'Xbox One';
        } else if (browser.ps4) {
            deviceName = 'Sony PS4';
        } else if (browser.chrome) {
            deviceName = 'Chrome';
        } else if (browser.edgeChromium) {
            deviceName = 'Edge Chromium';
        } else if (browser.edge) {
            deviceName = 'Edge';
        } else if (browser.firefox) {
            deviceName = 'Firefox';
        } else if (browser.opera) {
            deviceName = 'Opera';
        } else if (browser.safari) {
            deviceName = 'Safari';
        } else {
            deviceName = 'Web Browser';
        }

        if (browser.ipad) {
            deviceName += ' iPad';
        } else if (browser.iphone) {
            deviceName += ' iPhone';
        } else if (browser.android) {
            deviceName += ' Android';
        }
    }

    return deviceName;
}

const sleep = (milliseconds) => {
    return new Promise(resolve => setTimeout(resolve, milliseconds))
}

";

    /// <summary>
    /// A generator for the web response that incorporates the data from the server.
    /// </summary>
    /// <param name="data">The data of the auth flow. Is signed XML for SAML and a state ID for OpenID.</param>
    /// <param name="provider">The name of the provider to callback to.</param>
    /// <param name="baseUrl">The base URL of the Jellyfin installation.</param>
    /// <param name="mode">The mode of the function; SAML or OID.</param>
    /// <param name="isLinking">Whether or not this request is to link accounts (Rather than authenticate).</param>
    /// <returns>A string with the HTML to serve to the client.</returns>
    public static string Generator(string data, string provider, string baseUrl, string mode, bool isLinking = false)
    {
        // Strip out the protocol (http:// or https://) and convert the domain to Punycode
        var idnMapping = new IdnMapping();
        var protocolSeparatorIndex = baseUrl.IndexOf("//");
        var protocol = baseUrl.Substring(0, protocolSeparatorIndex + 2);
        var domain = baseUrl.Substring(protocolSeparatorIndex + 2);
        var punycodeDomain = idnMapping.GetAscii(domain);
        var punycodeBaseUrl = protocol + punycodeDomain;

        return Base + @"
function ssoAppHost() {
    try {
        if (window.NativeShell && window.NativeShell.AppHost) {
            return window.NativeShell.AppHost;
        }
    } catch (e) {}
    return null;
}

function ssoHostValue(host, method, fallback) {
    try {
        if (host && typeof host[method] === 'function') {
            var value = host[method]();
            if (value) {
                return value;
            }
        }
    } catch (e) {}
    return fallback;
}

function resolveDeviceId(host) {
    var fromNative = ssoHostValue(host, 'deviceId', null);
    if (fromNative) {
        return fromNative;
    }
    var stored = localStorage.getItem('_deviceId2');
    if (stored) {
        return stored;
    }
    var generated;
    try {
        generated = (window.crypto && window.crypto.randomUUID) ? window.crypto.randomUUID() : null;
    } catch (e) {
        generated = null;
    }
    if (!generated) {
        generated = 'sso-' + Date.now().toString(36) + Math.random().toString(36).slice(2);
    }
    // Persist so the web client (which reads _deviceId2) reuses the same device id.
    try { localStorage.setItem('_deviceId2', generated); } catch (e) {}
    return generated;
}

async function getServerInfo(baseUrl) {
    try {
        var resp = await fetch(baseUrl + '/System/Info/Public');
        if (resp.ok) {
            return await resp.json();
        }
    } catch (e) {}
    return null;
}

async function link(request) {
    const jfCredentialsString = localStorage.getItem(""jellyfin_credentials"");

    if (jfCredentialsString == null) return;

    const jfCredentials = JSON.parse(jfCredentialsString);
    const jfUser = jfCredentials['Servers'][0]['UserId'];
    const jfToken = jfCredentials['Servers'][0]['AccessToken'];

    if (jfUser == null) return;
    if (jfToken == null) return;

    const url = '" + $"{punycodeBaseUrl}/sso/{mode}/Link/{provider}/" + @"' + jfUser;

    return new Promise(resolve => {
       var xhr = new XMLHttpRequest();
       xhr.open('POST', url, true);
       xhr.setRequestHeader('Content-Type', 'application/json');
       xhr.setRequestHeader('Accept', 'application/json');

       xhr.setRequestHeader(
           'X-Emby-Authorization', 
           `MediaBrowser Client=""${request.appName}"",Device=""${request.deviceName}"",DeviceId=""${request.deviceId}"",Version=""${request.appVersion}"",Token=""${jfToken}""`)

       xhr.onload = function(e) {
         resolve(xhr.response);
       };
       xhr.onerror = function (e) {
         console.log(e);
         resolve(undefined);
       };
       xhr.send(JSON.stringify(request));
    })
}

async function main() {
    var data = '" + data + @"';

    // Resolve the device identity WITHOUT loading jellyfin-web in a hidden iframe.
    // Native apps expose it via the NativeShell bridge; the web client persists it
    // in localStorage._deviceId2; otherwise generate (and persist) a fresh id.
    var host = ssoAppHost();
    var deviceId = resolveDeviceId(host);
    var appName = ssoHostValue(host, 'appName', 'Jellyfin Web');
    var appVersion = ssoHostValue(host, 'appVersion', '10.8.0');
    var deviceName = ssoHostValue(host, 'deviceName', getDeviceName());

    var request = {deviceId, appName, appVersion, deviceName, data};

    if (" + $"{isLinking}".ToLower() + @") await link(request);

    var url = '" + punycodeBaseUrl + "/sso/" + mode + "/Auth/" + provider + @"';

    let response = await new Promise(resolve => {
       var xhr = new XMLHttpRequest();
       xhr.open('POST', url, true);
       xhr.setRequestHeader('Content-Type', 'application/json');
       xhr.setRequestHeader('Accept', 'application/json');
       xhr.onload = function(e) {
         resolve(xhr.response);
       };
       xhr.onerror = function () {
         resolve(undefined);
       };
       xhr.send(JSON.stringify(request));
    })
    if (!response) {
        document.body.innerHTML = '<p>Login failed: no response from the server. Please try again.</p>';
        return;
    }

    var responseJson = JSON.parse(response);
    if (!responseJson || !responseJson['User'] || !responseJson['AccessToken']) {
        document.body.innerHTML = '<p>Login failed. Please try again.</p>';
        return;
    }

    var serverId = responseJson['User']['ServerId'];
    var userId = 'user-' + responseJson['User']['Id'] + '-' + serverId;
    responseJson['User']['EnableAutoLogin'] = true;
    localStorage.setItem(userId, JSON.stringify(responseJson['User']));

    // Write credentials directly. Reuse the server entry jellyfin-web already wrote
    // (it connected to this server before showing the login page); fall back to
    // synthesising one from the public server info. No hidden iframe, no busy-wait.
    var jfCreds;
    try {
        jfCreds = JSON.parse(localStorage.getItem('jellyfin_credentials'));
    } catch (e) {
        jfCreds = null;
    }
    if (!jfCreds || !Array.isArray(jfCreds['Servers'])) {
        jfCreds = { Servers: [] };
    }

    var server = null;
    if (serverId) {
        server = jfCreds['Servers'].find(function (s) { return s && s['Id'] === serverId; });
    }
    if (!server) {
        // Reuse Servers[0] only when it is this server (or has no id yet);
        // never clobber the token of a different server.
        var first = jfCreds['Servers'][0];
        if (first && (!first['Id'] || !serverId || first['Id'] === serverId)) {
            server = first;
        }
    }
    if (!server) {
        var info = await getServerInfo('" + punycodeBaseUrl + @"');
        server = {
            Id: serverId || (info && info['Id']),
            ManualAddress: '" + punycodeBaseUrl + @"',
            Name: (info && info['ServerName']) || 'Jellyfin',
            LastConnectionMode: 2
        };
        jfCreds['Servers'].unshift(server);
    }
    server['AccessToken'] = responseJson['AccessToken'];
    server['UserId'] = responseJson['User']['Id'];
    server['DateLastAccessed'] = Date.now();

    localStorage.setItem('jellyfin_credentials', JSON.stringify(jfCreds));
    localStorage.setItem('enableAutoLogin', 'true');
    window.location.replace('" + punycodeBaseUrl + @"/web/index.html');
}

document.addEventListener('DOMContentLoaded', function () {
    main().catch(function (err) {
        console.error('[SSO-Auth] login error', err);
        var msg = (err && err.message) ? err.message : String(err);
        document.body.innerHTML = '<p>SSO login error: ' + msg + '</p>';
    });
});
</script></body></html>";
    }

    /// <summary>
    /// A minimal spinner page that immediately redirects to <paramref name="url"/>. Returned by
    /// the OIDC start endpoint instead of a bare 302, so the user gets a loading screen the moment
    /// they click the SSO button. Because the browser keeps the current document visible through
    /// the silent redirect chain (302s render nothing), this spinner stays up until the callback
    /// page renders — covering the otherwise-blank token-exchange window.
    /// </summary>
    /// <param name="url">The provider authorize URL to redirect the client to.</param>
    /// <returns>An HTML loading page that redirects to <paramref name="url"/>.</returns>
    public static string LoadingRedirect(string url)
    {
        var htmlUrl = System.Net.WebUtility.HtmlEncode(url);
        var jsUrl = System.Text.Json.JsonSerializer.Serialize(url);
        return @"<!DOCTYPE html>
<html><head>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<meta http-equiv='refresh' content='0;url=" + htmlUrl + @"'>
<style>
  html, body { height: 100%; }
  body {
    margin: 0; background: #101010; color: #d1cfce;
    font-family: Noto Sans, Noto Sans HK, Noto Sans JP, Noto Sans KR, Noto Sans SC, Noto Sans TC, sans-serif;
    display: flex; align-items: center; justify-content: center; min-height: 100vh; text-align: center;
  }
  .sso-spinner {
    width: 48px; height: 48px; margin: 0 auto 1.25em;
    border: 4px solid rgba(255, 255, 255, 0.15); border-top-color: #00a4dc;
    border-radius: 50%; animation: sso-spin 0.9s linear infinite;
  }
  @keyframes sso-spin { to { transform: rotate(360deg); } }
  p { margin: 0; font-size: 1.05rem; opacity: 0.9; }
</style>
</head><body>
<div><div class='sso-spinner'></div><p>Signing in…</p></div>
<script>window.location.replace(" + jsUrl + @");</script>
</body></html>";
    }
}
