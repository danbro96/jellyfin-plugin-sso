using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Jellyfin.Plugin.SSO_Auth;
using Xunit;

namespace SSO_Auth.Tests;

/// <summary>
/// Tests for the hand-rolled SAML <see cref="Response"/> and <see cref="AuthRequest"/> in
/// <c>Saml.cs</c>. This is the security-critical path: signature validation, the signature-
/// wrapping defense, and assertion expiry. Self-signed certs are generated per test.
/// </summary>
public class SamlResponseTests
{
    private const string SamlNs = "urn:oasis:names:tc:SAML:2.0:assertion";
    private const string SamlpNs = "urn:oasis:names:tc:SAML:2.0:protocol";

    private static string BuildResponseXml(
        string responseId,
        string assertionId,
        DateTime notOnOrAfter,
        string nameId,
        string? extraAssertionId = null)
    {
        var extra = extraAssertionId is null
            ? string.Empty
            : $@"<saml:Assertion ID=""{extraAssertionId}"" Version=""2.0""><saml:Issuer>injected</saml:Issuer></saml:Assertion>";

        return $@"<samlp:Response xmlns:samlp=""{SamlpNs}"" xmlns:saml=""{SamlNs}"" ID=""{responseId}"" Version=""2.0"">
  <saml:Assertion ID=""{assertionId}"" Version=""2.0"">
    <saml:Subject>
      <saml:NameID>{nameId}</saml:NameID>
      <saml:SubjectConfirmation>
        <saml:SubjectConfirmationData NotOnOrAfter=""{notOnOrAfter.ToUniversalTime():yyyy-MM-ddTHH:mm:ssZ}"" />
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name=""User.email""><saml:AttributeValue>{nameId}@example.com</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name=""Role""><saml:AttributeValue>admin</saml:AttributeValue><saml:AttributeValue>user</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
  {extra}
</samlp:Response>";
    }

    // Signs the element identified by referenceId with an enveloped signature, appending the
    // <Signature> inside that element. Returns the signed XML string and the public cert (DER).
    private static (string Xml, byte[] CertDer) Sign(string xml, string referenceId, RSA? signingKey = null)
    {
        using var key = signingKey ?? RSA.Create(2048);
        var req = new CertificateRequest("CN=Test SAML IdP", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var certDer = cert.Export(X509ContentType.Cert);

        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        doc.LoadXml(xml);

        var signedXml = new SignedXml(doc) { SigningKey = key };
        var reference = new Reference("#" + referenceId);
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);
        signedXml.ComputeSignature();

        var target = (XmlElement)doc.SelectSingleNode($"//*[@ID='{referenceId}']")!;
        target.AppendChild(doc.ImportNode(signedXml.GetXml(), true));
        return (doc.OuterXml, certDer);
    }

    private static byte[] OtherCertDer()
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=Other", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return cert.Export(X509ContentType.Cert);
    }

    [Fact]
    public void ValidSignedResponse_RootSignature_IsValid()
    {
        var xml = BuildResponseXml("_resp1", "_assert1", DateTime.UtcNow.AddMinutes(10), "alice");
        var (signed, certDer) = Sign(xml, "_resp1");

        var response = new Response(certDer);
        response.LoadXml(signed);

        Assert.True(response.IsValid());
    }

    [Fact]
    public void ValidSignedResponse_AssertionSignature_IsValid()
    {
        var xml = BuildResponseXml("_resp1", "_assert1", DateTime.UtcNow.AddMinutes(10), "alice");
        var (signed, certDer) = Sign(xml, "_assert1");

        var response = new Response(certDer);
        response.LoadXml(signed);

        Assert.True(response.IsValid());
    }

    [Fact]
    public void NoSignature_IsNotValid()
    {
        var xml = BuildResponseXml("_resp1", "_assert1", DateTime.UtcNow.AddMinutes(10), "alice");
        var response = new Response(OtherCertDer());
        response.LoadXml(xml);

        Assert.False(response.IsValid());
    }

    [Fact]
    public void TamperedBodyAfterSigning_IsNotValid()
    {
        var xml = BuildResponseXml("_resp1", "_assert1", DateTime.UtcNow.AddMinutes(10), "alice");
        var (signed, certDer) = Sign(xml, "_resp1");

        // Tamper a signed value after signing.
        var tampered = signed.Replace("alice@example.com", "evil@example.com");

        var response = new Response(certDer);
        response.LoadXml(tampered);

        Assert.False(response.IsValid());
    }

    [Fact]
    public void SignedWithDifferentCertificate_IsNotValid()
    {
        var xml = BuildResponseXml("_resp1", "_assert1", DateTime.UtcNow.AddMinutes(10), "alice");
        var (signed, _) = Sign(xml, "_resp1");

        // Validate against an unrelated certificate.
        var response = new Response(OtherCertDer());
        response.LoadXml(signed);

        Assert.False(response.IsValid());
    }

    [Fact]
    public void SignatureWrapping_SignedInjectedAssertion_IsNotValid()
    {
        // The signature covers an injected assertion (_evil) that is neither the document root
        // nor the canonical /Response/Assertion node -> ValidateSignatureReference must reject it.
        var xml = BuildResponseXml("_resp1", "_assert1", DateTime.UtcNow.AddMinutes(10), "alice", extraAssertionId: "_evil");
        var (signed, certDer) = Sign(xml, "_evil");

        var response = new Response(certDer);
        response.LoadXml(signed);

        Assert.False(response.IsValid());
    }

    [Fact]
    public void ExpiredAssertion_IsNotValid()
    {
        var xml = BuildResponseXml("_resp1", "_assert1", DateTime.UtcNow.AddMinutes(-10), "alice");
        var (signed, certDer) = Sign(xml, "_resp1");

        var response = new Response(certDer);
        response.LoadXml(signed);

        Assert.False(response.IsValid());
    }

    [Fact]
    public void Getters_ExtractNameIdEmailAndAttributes()
    {
        var xml = BuildResponseXml("_resp1", "_assert1", DateTime.UtcNow.AddMinutes(10), "alice");
        var response = new Response(OtherCertDer());
        response.LoadXml(xml);

        Assert.Equal("alice", response.GetNameID());
        Assert.Equal("alice@example.com", response.GetEmail());
        Assert.Equal("admin", response.GetCustomAttribute("Role"));
        Assert.Equal(new[] { "admin", "user" }, response.GetCustomAttributes("Role"));
    }

    [Fact]
    public void Xxe_ExternalEntityIsNotResolved()
    {
        // XmlResolver is null in LoadXml, so an external entity must not be fetched. Loading
        // such a document throws rather than silently exfiltrating the referenced resource.
        var path = Path.Combine(Path.GetTempPath(), "sso-xxe-" + Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(path, "TOP-SECRET");
        try
        {
            var uri = new Uri(path).AbsoluteUri;
            var malicious =
                $"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"{uri}\">]>" +
                $"<samlp:Response xmlns:samlp=\"{SamlpNs}\" xmlns:saml=\"{SamlNs}\" ID=\"_r\">" +
                "<saml:Assertion ID=\"_a\"><saml:Subject><saml:NameID>&xxe;</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>";

            var response = new Response(OtherCertDer());
            var ex = Record.Exception(() => response.LoadXml(malicious));

            // Either loading throws (DTD/entity disabled), or — if it parses — the secret was not read in.
            if (ex is null)
            {
                Assert.DoesNotContain("TOP-SECRET", response.Xml);
            }
            else
            {
                Assert.IsType<XmlException>(ex);
            }
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void AuthRequest_RedirectUrl_EncodesAndAddsSamlRequest()
    {
        var request = new AuthRequest("my-issuer", "https://jellyfin.example.com/sso/SAML/r/provider");

        var url = request.GetRedirectUrl("https://idp.example.com/sso");
        Assert.StartsWith("https://idp.example.com/sso?SAMLRequest=", url);

        var withQuery = request.GetRedirectUrl("https://idp.example.com/sso?foo=bar", "relay-123");
        Assert.Contains("&SAMLRequest=", withQuery);
        Assert.Contains("&RelayState=relay-123", withQuery);
    }

    [Fact]
    public void AuthRequest_Base64Request_InflatesToAuthnRequestXml()
    {
        var request = new AuthRequest("my-issuer", "https://jellyfin.example.com/acs");
        var base64 = request.GetRequest(AuthRequest.AuthRequestFormat.Base64);

        var deflated = Convert.FromBase64String(base64);
        using var input = new MemoryStream(deflated);
        using var deflate = new DeflateStream(input, CompressionMode.Decompress);
        using var reader = new StreamReader(deflate, Encoding.UTF8);
        var xml = reader.ReadToEnd();

        Assert.Contains("AuthnRequest", xml);
        Assert.Contains("my-issuer", xml);
        Assert.Contains("https://jellyfin.example.com/acs", xml);
    }
}
