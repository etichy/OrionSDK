using System.Net;
using System.Net.Security;
using System.ServiceModel;
using SolarWinds.InformationService.Contract2;
using SwqlStudio.Properties;

namespace SwqlStudio
{
    internal class OrionOAuthInfoService : InfoServiceBase
    {
        // Intentionally duplicates OrionHttpsInfoService's static ctor.
        // Each class independently ensures the process-wide HTTPS settings are correct
        // without depending on the other having been loaded first.
        static OrionOAuthInfoService()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback = CertificateValidatorWithCache.ValidateRemoteCertificate;
        }

        private OAuthTokenManager _tokenManager;

        public OrionOAuthInfoService()
        {
            _protocolName = "https";
            _endpoint = Settings.Default.OrionV3HttpsEndpointPath;
            _endpointConfigName = string.Empty;

            // Build a binding with no client credential type — do NOT reuse "SWIS.Over.HTTP"
            // which has clientCredentialType="Basic". Sending Basic + Bearer simultaneously
            // would cause the server to apply the wrong auth path.
            var binding = new BasicHttpBinding
            {
                MaxReceivedMessageSize = int.MaxValue,
                MaxBufferSize = int.MaxValue,
                Security =
                {
                    Mode = BasicHttpSecurityMode.Transport,
                    Transport = { ClientCredentialType = HttpClientCredentialType.None }
                }
            };
            binding.ReaderQuotas.MaxStringContentLength = int.MaxValue;
            binding.ReaderQuotas.MaxArrayLength = int.MaxValue;

            _binding = binding;
            // _credentials is set in CreateProxy once the token manager is initialised
        }

        public OAuthTokenManager TokenManager => _tokenManager;

        // Called from NewConnection dialog before CreateProxy so authentication
        // can happen while the dialog is still open.
        public void InitTokenManager(string server)
        {
            if (_tokenManager == null || _tokenManager.Server != server)
                _tokenManager = new OAuthTokenManager(server);
        }

        public override string ServiceType => "Orion (v3) OAuth";

        protected override int Port => Settings.Default.DefaultInfoServiceHttpsPort;

        public override InfoServiceProxy CreateProxy(string server)
        {
            if (_tokenManager == null)
                _tokenManager = new OAuthTokenManager(server);

            _credentials = new BearerTokenCredentials(() => _tokenManager.GetCurrentToken());

            return base.CreateProxy(server);
        }
    }
}
