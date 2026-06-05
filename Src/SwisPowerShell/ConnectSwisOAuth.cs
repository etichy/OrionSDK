using System;
using System.Management.Automation;
using System.Threading;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using SolarWinds.InformationService.Contract2;

namespace SwisPowerShell
{
    [Cmdlet(VerbsCommunications.Connect, "SwisOAuth")]
    [OutputType(typeof(InfoServiceProxy))]
    public class ConnectSwisOAuth : PSCmdlet
    {
        private const string HttpsEndpoint = "https://{0}:17774/SolarWinds/InformationService/v3/OrionBasic";

        [Parameter(Mandatory = true, Position = 0, HelpMessage = "Hostname or IP address of the Orion server.")]
        public string Hostname { get; set; }

        [Parameter(HelpMessage = "Trust all SSL/TLS certificates (useful for self-signed certs in dev environments).")]
        public SwitchParameter TrustAllCertificates { get; set; }

        private CancellationTokenSource _cts;

        protected override void StopProcessing()
        {
            _cts?.Cancel();
        }

        protected override void ProcessRecord()
        {
            base.ProcessRecord();

            RemoteCertificateValidationCallback certCallback = TrustAllCertificates.IsPresent
                ? (sender, cert, chain, errors) => true
                : (RemoteCertificateValidationCallback)ValidateCertificate;

            var tokenManager = new OAuthTokenManager(Hostname, certCallback);

            _cts = new CancellationTokenSource();
            try
            {
                tokenManager.AcquireTokenAsync(_cts.Token).GetAwaiter().GetResult();
            }
            catch (OperationCanceledException)
            {
                WriteWarning("OAuth authentication was cancelled.");
                return;
            }
            finally
            {
                _cts.Dispose();
                _cts = null;
            }

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

            var credentials = new BearerTokenCredentials(() => tokenManager.GetCurrentToken());
            var uri = new Uri(string.Format(HttpsEndpoint, Hostname));

            var proxy = new InfoServiceProxy(uri, binding, credentials);
            WriteObject(proxy);
        }

        private bool ValidateCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            if (errors == SslPolicyErrors.None)
                return true;

            try { WriteWarning($"SSL certificate error: {errors}. Use -TrustAllCertificates to bypass certificate validation."); }
            catch (NotImplementedException) { }
            return false;
        }
    }
}
