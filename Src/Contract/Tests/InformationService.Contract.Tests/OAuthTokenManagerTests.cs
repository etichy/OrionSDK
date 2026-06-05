using System;
using System.Text;
using NUnit.Framework;
using SolarWinds.InformationService.Contract2;

namespace SolarWinds.InformationService.Contract2.Tests
{
    [TestFixture]
    public class OAuthTokenManagerTests
    {
        // ── Constructor validation ────────────────────────────────────────────

        [Test]
        public void Constructor_NullServer_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => new OAuthTokenManager(null));
        }

        [Test]
        public void Constructor_WhitespaceServer_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => new OAuthTokenManager("   "));
        }

        [Test]
        public void Constructor_ServerWithPath_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => new OAuthTokenManager("host/evil"));
        }

        [Test]
        public void Constructor_ServerWithQuery_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => new OAuthTokenManager("host?foo=bar"));
        }

        [Test]
        public void Constructor_PlainHostname_Succeeds()
        {
            var mgr = new OAuthTokenManager("myhost");
            Assert.That(mgr.Server, Is.EqualTo("myhost"));
        }

        [Test]
        public void Constructor_HostWithPort_Succeeds()
        {
            var mgr = new OAuthTokenManager("myhost:17778");
            Assert.That(mgr.Server, Is.EqualTo("myhost:17778"));
        }

        // ── GetCurrentToken — pre-auth ────────────────────────────────────────

        [Test]
        public void GetCurrentToken_BeforeAcquire_ThrowsApplicationException()
        {
            var mgr = new OAuthTokenManager("host");
            var ex = Assert.Throws<ApplicationException>(() => mgr.GetCurrentToken());
            Assert.That(ex.Message, Does.Contain("not been completed"));
        }

        // ── ApplyTokenResponse / expiry math ─────────────────────────────────

        [Test]
        public void ApplyTokenResponse_ExpiresInAbove30_TokenIsLive()
        {
            var mgr = new OAuthTokenManager("host");
            mgr.ApplyTokenResponse(new OAuthTokenManager.TokenResponse
            {
                AccessToken = "tok",
                RefreshToken = "ref",
                ExpiresIn = 300
            });
            Assert.That(mgr.GetCurrentToken(), Is.EqualTo("tok"));
        }

        [Test]
        public void ApplyTokenResponse_ExpiresIn30_UsesFloor_TokenIsLive()
        {
            var mgr = new OAuthTokenManager("host");
            mgr.ApplyTokenResponse(new OAuthTokenManager.TokenResponse
            {
                AccessToken = "tok",
                RefreshToken = "ref",
                ExpiresIn = 30
            });
            Assert.That(mgr.GetCurrentToken(), Is.EqualTo("tok"));
        }

        [Test]
        public void ApplyTokenResponse_ExpiresInZero_UsesFloor_TokenIsLive()
        {
            var mgr = new OAuthTokenManager("host");
            mgr.ApplyTokenResponse(new OAuthTokenManager.TokenResponse
            {
                AccessToken = "tok",
                RefreshToken = "ref",
                ExpiresIn = 0
            });
            Assert.That(mgr.GetCurrentToken(), Is.EqualTo("tok"));
        }

        [Test]
        public void ApplyTokenResponse_SetsLastAccountUsername_FromPreferredUsername()
        {
            string payloadJson = "{\"preferred_username\":\"jdoe\",\"sub\":\"123\"}";
            string jwt = BuildJwt(payloadJson);

            var mgr = new OAuthTokenManager("host");
            mgr.ApplyTokenResponse(new OAuthTokenManager.TokenResponse
            {
                AccessToken = jwt,
                RefreshToken = "ref",
                ExpiresIn = 300
            });

            Assert.That(mgr.LastAccountUsername, Is.EqualTo("jdoe"));
        }

        [Test]
        public void ApplyTokenResponse_NullRefreshToken_PreservesExistingRefreshToken()
        {
            var mgr = new OAuthTokenManager("host");
            mgr.ApplyTokenResponse(new OAuthTokenManager.TokenResponse
            {
                AccessToken = "tok1",
                RefreshToken = "original-refresh",
                ExpiresIn = 300
            });

            // Refresh response that omits refresh_token
            mgr.ApplyTokenResponse(new OAuthTokenManager.TokenResponse
            {
                AccessToken = "tok2",
                RefreshToken = null,
                ExpiresIn = 300
            });

            Assert.That(mgr.GetCurrentToken(), Is.EqualTo("tok2"));
        }

        // ── ExtractUsernameFromJwt ────────────────────────────────────────────

        [Test]
        public void ExtractUsernameFromJwt_Null_ReturnsNull()
        {
            Assert.That(OAuthTokenManager.ExtractUsernameFromJwt(null), Is.Null);
        }

        [Test]
        public void ExtractUsernameFromJwt_Empty_ReturnsNull()
        {
            Assert.That(OAuthTokenManager.ExtractUsernameFromJwt(""), Is.Null);
        }

        [Test]
        public void ExtractUsernameFromJwt_MissingDots_ReturnsNull()
        {
            Assert.That(OAuthTokenManager.ExtractUsernameFromJwt("notajwt"), Is.Null);
        }

        [Test]
        public void ExtractUsernameFromJwt_MalformedBase64Payload_ReturnsNull()
        {
            Assert.That(OAuthTokenManager.ExtractUsernameFromJwt("header.!!!.sig"), Is.Null);
        }

        [Test]
        public void ExtractUsernameFromJwt_PreferredUsername_ReturnsIt()
        {
            string jwt = BuildJwt("{\"preferred_username\":\"alice\",\"email\":\"a@b.com\",\"sub\":\"123\"}");
            Assert.That(OAuthTokenManager.ExtractUsernameFromJwt(jwt), Is.EqualTo("alice"));
        }

        [Test]
        public void ExtractUsernameFromJwt_NoPreferredUsername_FallsBackToEmail()
        {
            string jwt = BuildJwt("{\"email\":\"alice@example.com\",\"sub\":\"123\"}");
            Assert.That(OAuthTokenManager.ExtractUsernameFromJwt(jwt), Is.EqualTo("alice@example.com"));
        }

        [Test]
        public void ExtractUsernameFromJwt_OnlySub_FallsBackToSub()
        {
            string jwt = BuildJwt("{\"sub\":\"user-sub-value\"}");
            Assert.That(OAuthTokenManager.ExtractUsernameFromJwt(jwt), Is.EqualTo("user-sub-value"));
        }

        [Test]
        public void ExtractUsernameFromJwt_NoClaims_ReturnsNull()
        {
            string jwt = BuildJwt("{\"iat\":1234567890}");
            Assert.That(OAuthTokenManager.ExtractUsernameFromJwt(jwt), Is.Null);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static string BuildJwt(string payloadJson)
        {
            string payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return "eyJhbGciOiJSUzI1NiJ9." + payload + ".sig";
        }
    }
}
