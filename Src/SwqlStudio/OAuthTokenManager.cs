// OAuthTokenManager lives in SolarWinds.InformationService.Contract2 (Src/Contract/OAuthTokenManager.cs).
// This file re-exports the type into the SwqlStudio namespace so existing references compile unchanged.

using SolarWinds.InformationService.Contract2;

namespace SwqlStudio
{
    internal class OAuthTokenManager : SolarWinds.InformationService.Contract2.OAuthTokenManager
    {
        public OAuthTokenManager(string server)
            : base(server, CertificateValidatorWithCache.ValidateRemoteCertificate)
        {
        }
    }
}
