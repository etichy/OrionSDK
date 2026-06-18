using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SolarWinds.InformationService.Contract2
{
    public class OAuthTokenManager
    {
        private static readonly string[] Scopes = { "swis", "offline_access" };

        private readonly string _clientId;
        private readonly string _server;
        private readonly RemoteCertificateValidationCallback _certValidator;
        private readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1, 1);
        private string _accessToken;
        private string _refreshToken;
        private DateTime _accessTokenExpiry = DateTime.MinValue;

        public string Server => _server;
        public string LastAccountUsername { get; private set; } = string.Empty;

        private string AuthorizeUrl => $"https://{_server}/oauth/authorize";
        private string TokenUrl => $"https://{_server}/oauth/token";

        public OAuthTokenManager(string server, RemoteCertificateValidationCallback certValidator = null, string clientId = "swql_studio")
        {
            if (string.IsNullOrWhiteSpace(server))
                throw new ArgumentNullException(nameof(server));

            // Validate that _server is a plain host[:port] — no path or query components
            // that could escape into the constructed HTTPS URL opened by Process.Start.
            if (!Uri.TryCreate("https://" + server + "/", UriKind.Absolute, out var probe)
                || !string.IsNullOrEmpty(probe.Query)
                || probe.PathAndQuery != "/")
            {
                throw new ArgumentException("Server must be a plain hostname or host:port value.", nameof(server));
            }

            _server = server;
            _certValidator = certValidator;
            _clientId = clientId;
        }

        public async Task AcquireTokenAsync(CancellationToken cancellationToken = default)
        {
            string codeVerifier = GenerateCodeVerifier();
            string codeChallenge = GenerateCodeChallenge(codeVerifier);
            string state = GenerateRandomBase64Url(16);

            int port = FindFreePort();
            string redirectUri = $"http://localhost:{port}/";

            string authUrl = AuthorizeUrl
                + "?response_type=code"
                + "&client_id=" + Uri.EscapeDataString(_clientId)
                + "&redirect_uri=" + Uri.EscapeDataString(redirectUri)
                + "&scope=" + Uri.EscapeDataString(string.Join(" ", Scopes))
                + "&state=" + Uri.EscapeDataString(state)
                + "&code_challenge=" + Uri.EscapeDataString(codeChallenge)
                + "&code_challenge_method=S256";

            using (var listener = new HttpListener())
            {
                listener.Prefixes.Add(redirectUri);
                listener.Start();

                Process.Start(new ProcessStartInfo(authUrl) { UseShellExecute = true });

                string code = null;
                string error = null;
                string errorDescription = null;

                using (cancellationToken.Register(() => listener.Stop()))
                {
                    while (code == null && error == null)
                    {
                        HttpListenerContext context;
                        try
                        {
                            context = await listener.GetContextAsync().ConfigureAwait(false);
                        }
                        catch (HttpListenerException) when (cancellationToken.IsCancellationRequested)
                        {
                            throw new OperationCanceledException(cancellationToken);
                        }

                        var query = context.Request.QueryString;

                        bool isCallback = query["code"] != null || query["error"] != null || query["state"] != null;
                        if (isCallback)
                        {
                            error = query["error"];
                            errorDescription = query["error_description"];

                            if (error == null)
                            {
                                if (!string.Equals(query["state"], state, StringComparison.Ordinal))
                                    throw new ApplicationException("OAuth state mismatch.");

                                code = query["code"];
                                if (string.IsNullOrEmpty(code))
                                    throw new ApplicationException("OAuth authorization response did not contain a code.");
                            }

                            bool isSuccess = error == null;
                            string title = isSuccess ? "Authentication Successful" : "Authentication Failed";
                            string body = isSuccess
                                ? "You have been signed in successfully. You may close this browser tab and return to SWQL Studio."
                                : $"Sign-in could not be completed: <strong>{System.Net.WebUtility.HtmlEncode(errorDescription ?? error)}</strong>";
                            string iconColor = isSuccess ? "#2e7d32" : "#c62828";
                            string icon = isSuccess ? "✔" : "✖";

                            string html = $@"<!DOCTYPE html>
<html lang=""en"">
<head>
  <meta charset=""utf-8"" />
  <meta name=""viewport"" content=""width=device-width, initial-scale=1"" />
  <title>{title}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f5f5f5;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      color: #212121;
    }}
    .card {{
      background: #fff;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,.12);
      padding: 48px 40px;
      max-width: 480px;
      width: 100%;
      text-align: center;
    }}
    .icon {{
      font-size: 48px;
      color: {iconColor};
      margin-bottom: 16px;
    }}
    h1 {{
      font-size: 22px;
      font-weight: 600;
      margin-bottom: 12px;
      color: {iconColor};
    }}
    p {{
      font-size: 15px;
      line-height: 1.6;
      color: #555;
    }}
    .footer {{
      margin-top: 32px;
      font-size: 12px;
      color: #aaa;
    }}
  </style>
</head>
<body>
  <div class=""card"">
    <div class=""icon"">{icon}</div>
    <h1>{title}</h1>
    <p>{body}</p>
    <p class=""footer"">{_clientId}</p>
  </div>
</body>
</html>";
                            byte[] responsePage = Encoding.UTF8.GetBytes(html);
                            context.Response.ContentType = "text/html; charset=utf-8";
                            context.Response.ContentLength64 = responsePage.Length;
                            await context.Response.OutputStream.WriteAsync(responsePage, 0, responsePage.Length).ConfigureAwait(false);
                            context.Response.Close();
                        }
                        else
                        {
                            context.Response.StatusCode = 404;
                            context.Response.Close();
                        }
                    }
                }

                if (error != null)
                    throw new ApplicationException($"OAuth authorization failed: {error} — {errorDescription}");

                await ExchangeCodeForTokensAsync(code, codeVerifier, redirectUri, cancellationToken).ConfigureAwait(false);
            }
        }

        public string GetCurrentToken()
        {
            if (_accessToken == null)
                throw new ApplicationException("OAuth authentication has not been completed. Please reconnect.");

            if (DateTime.UtcNow < _accessTokenExpiry)
                return _accessToken;

            if (_refreshToken == null)
                throw new OAuthSessionExpiredException();

            // Serialize concurrent refreshes so only one thread hits the token endpoint.
            // Uses Task.Run to avoid blocking a captured SynchronizationContext (e.g. the
            // WinForms UI thread) when called from the WCF message inspector.
            _refreshLock.Wait();
            try
            {
                // Re-check expiry under the lock — another thread may have already refreshed.
                if (DateTime.UtcNow < _accessTokenExpiry)
                    return _accessToken;

                RefreshAccessTokenSync();
                return _accessToken;
            }
            catch (Exception ex)
            {
                throw new ApplicationException("OAuth token refresh failed: " + ex.Message, ex);
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        public Task SignOutAsync()
        {
            _accessToken = null;
            _refreshToken = null;
            _accessTokenExpiry = DateTime.MinValue;
            LastAccountUsername = string.Empty;
            return Task.CompletedTask;
        }

        private async Task ExchangeCodeForTokensAsync(string code, string codeVerifier, string redirectUri, CancellationToken cancellationToken)
        {
            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _clientId,
                ["code"] = code,
                ["redirect_uri"] = redirectUri,
                ["code_verifier"] = codeVerifier,
            };

            var response = await PostFormAsync(parameters, cancellationToken).ConfigureAwait(false);
            ApplyTokenResponse(response);
        }

        private void RefreshAccessTokenSync()
        {
            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = _clientId,
                ["refresh_token"] = _refreshToken,
            };

            // Task.Run escapes any captured SynchronizationContext so the async
            // continuations inside PostFormAsync are never scheduled back onto a
            // single-threaded context (e.g. the WinForms message loop), preventing
            // the GetResult() call from deadlocking.
            var response = Task.Run(() => PostFormAsync(parameters, CancellationToken.None)).GetAwaiter().GetResult();
            ApplyTokenResponse(response);
        }

        private async Task<TokenResponse> PostFormAsync(Dictionary<string, string> parameters, CancellationToken cancellationToken)
        {
            var handler = new HttpClientHandler();
            if (_certValidator != null)
            {
                handler.ServerCertificateCustomValidationCallback =
                    (msg, cert, chain, errors) => _certValidator(msg, cert, chain, errors);
            }

            using (var client = new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(30) })
            using (var content = new FormUrlEncodedContent(parameters))
            {
                var httpResponse = await client.PostAsync(TokenUrl, content, cancellationToken).ConfigureAwait(false);
                byte[] body = await httpResponse.Content.ReadAsByteArrayAsync().ConfigureAwait(false);

                if (!httpResponse.IsSuccessStatusCode)
                    throw new ApplicationException($"Token request failed ({(int)httpResponse.StatusCode}): {Encoding.UTF8.GetString(body)}");

                var serializer = new DataContractJsonSerializer(typeof(TokenResponse));
                using (var stream = new System.IO.MemoryStream(body))
                    return (TokenResponse)serializer.ReadObject(stream);
            }
        }

        internal void ApplyTokenResponse(TokenResponse response)
        {
            // Subtract 30 s as a refresh-before-expiry buffer.
            // If ExpiresIn is 0 or very small, use a 60-second window so a single
            // refresh doesn't immediately re-expire and cause a storm.
            int effectiveExpiry = response.ExpiresIn > 30 ? response.ExpiresIn - 30 : 60;

            string jwt = response.IdToken ?? response.AccessToken;
            string username = ExtractUsernameFromJwt(jwt) ?? string.Empty;

            _accessToken = response.AccessToken;
            // Only overwrite the refresh token when the server returns a new one.
            // Some servers (non-rotating) omit it in the refresh response intending
            // the original to remain valid — nulling it would break the next refresh.
            if (!string.IsNullOrEmpty(response.RefreshToken))
                _refreshToken = response.RefreshToken;
            _accessTokenExpiry = DateTime.UtcNow.AddSeconds(effectiveExpiry);
            LastAccountUsername = username;
        }

        private static string GenerateCodeVerifier() => GenerateRandomBase64Url(32);

        private static string GenerateCodeChallenge(string codeVerifier)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
                return Base64UrlEncode(hash);
            }
        }

        private static string GenerateRandomBase64Url(int byteLength)
        {
            var bytes = new byte[byteLength];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(bytes);
            return Base64UrlEncode(bytes);
        }

        private static string Base64UrlEncode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        private static int FindFreePort()
        {
            var tcpListener = new TcpListener(IPAddress.Loopback, 0);
            tcpListener.Start();
            int port = ((IPEndPoint)tcpListener.LocalEndpoint).Port;
            tcpListener.Stop();
            return port;
        }

        internal static string ExtractUsernameFromJwt(string jwt)
        {
            if (string.IsNullOrEmpty(jwt))
                return null;

            string[] parts = jwt.Split('.');
            if (parts.Length < 2)
                return null;

            try
            {
                string payload = parts[1].Replace('-', '+').Replace('_', '/');
                payload += new string('=', (4 - payload.Length % 4) % 4);
                string json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));

                foreach (string claim in new[] { "preferred_username", "email", "sub" })
                {
                    string key = $"\"{claim}\":\"";
                    int start = json.IndexOf(key, StringComparison.Ordinal);
                    if (start < 0) continue;
                    start += key.Length;
                    int end = json.IndexOf('"', start);
                    if (end > start)
                        return json.Substring(start, end - start);
                }
            }
            catch { }

            return null;
        }

        [DataContract]
        internal class TokenResponse
        {
            [DataMember(Name = "access_token")]
            public string AccessToken { get; set; }

            [DataMember(Name = "refresh_token")]
            public string RefreshToken { get; set; }

            [DataMember(Name = "expires_in")]
            public int ExpiresIn { get; set; }

            [DataMember(Name = "id_token")]
            public string IdToken { get; set; }
        }
    }
}
