using System;
using System.ServiceModel;

namespace SolarWinds.InformationService.Contract2
{
    public class BearerTokenCredentials : ServiceCredentials
    {
        private readonly Func<string> _tokenProvider;

        public BearerTokenCredentials(Func<string> tokenProvider)
        {
            _tokenProvider = tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));
        }

        public override CredentialType CredentialType => CredentialType.Bearer;

        public override void ApplyTo(ChannelFactory channelFactory)
        {
            // Only add the bearer token behavior — do NOT touch channelFactory.Credentials.*
            // Setting built-in WCF credential slots alongside a Bearer header causes dual auth.
            channelFactory.Endpoint.EndpointBehaviors.Add(new BearerTokenBehavior(_tokenProvider));
        }
    }
}
