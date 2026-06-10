using System;

namespace SolarWinds.InformationService.Contract2
{
    public class OAuthSessionExpiredException : Exception
    {
        public OAuthSessionExpiredException()
            : base("OAuth session expired. Please re-authenticate to continue.")
        {
        }
    }
}
