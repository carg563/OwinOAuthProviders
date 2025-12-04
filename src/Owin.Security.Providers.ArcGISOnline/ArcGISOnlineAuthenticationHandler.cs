using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Serilog;
using ILogger = Microsoft.Owin.Logging.ILogger;

namespace Owin.Security.Providers.ArcGISOnline
{
    public class ArcGISOnlineAuthenticationHandler : AuthenticationHandler<ArcGISOnlineAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public ArcGISOnlineAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                Log.Information("Authenticating Post Challenge");
                string code = null;
                string state = null;

                var query = Request.Query;

                Log.Information($"Authenticating: Request query {Request.Query}");

                var values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }

                Log.Information($"Authenticating: code from Esri {code}");

                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }
                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var requestPrefix = Request.Scheme + "://" + Request.Host;
                var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;
                Log.Information($"Authenticating: Redirect Uri {redirectUri}");

                // Build up the body for the token request
                var body = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri),
                    new KeyValuePair<string, string>("client_id", Options.ClientId),
                    new KeyValuePair<string, string>("client_secret", Options.ClientSecret)
                };

                // Request the token
                var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.Endpoints.TokenEndpoint);
                requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                requestMessage.Content = new FormUrlEncodedContent(body);

                Log.Information($"Authenticating: Authorization EndPoint {requestMessage.RequestUri.ToString()}");

                var tokenResponse = await _httpClient.SendAsync(requestMessage);
                tokenResponse.EnsureSuccessStatusCode();
                Log.Information($"Authenticating: Received success response from Token endpoint");

                var text = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                dynamic response = JsonConvert.DeserializeObject<dynamic>(text);
                var accessToken = (string)response.access_token;
                var refreshToken = (string)response.refresh_token;
                if (accessToken == null)
                {
                    Log.Information($"Authenticating: token is null??");
                }
                if (response.expires_in == null)
                {
                    Log.Information($"Authenticating: expiry is null??");
                }

                var expiresIn = 900;
                if (response.expires_in != null)
                {
                    expiresIn = (int)response.expires_in;
                }


                Log.Information($"Authenticating: Retrieving ArcGIS Online user information");
                // Get the ArcGISOnline user
                var userRequest = new HttpRequestMessage(HttpMethod.Get, Options.Endpoints.UserInfoEndpoint + "?f=json&token=" + Uri.EscapeDataString(accessToken));
                userRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                var userResponse = await _httpClient.SendAsync(userRequest, Request.CallCancelled);
                userResponse.EnsureSuccessStatusCode();
                text = await userResponse.Content.ReadAsStringAsync();
                var user = JsonConvert.DeserializeObject<Provider.ArcGISOnlineUser>(text);

                Log.Information($"Authenticating: Retrieved user information");

                var context = new ArcGISOnlineAuthenticatedContext(Context, user, accessToken, refreshToken, expiresIn)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };


                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.UserName))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.UserName, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Name))
                {
                    context.Identity.AddClaim(new Claim("urn:ArcGISOnline:name", context.Name, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Link))
                {
                    context.Identity.AddClaim(new Claim("urn:ArcGISOnline:url", context.Link, XmlSchemaString, Options.AuthenticationType));
                }

                Log.Information($"Authenticating: Created claims identity");

                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                Log.Information($"Authenticating: Return claims identity");

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                Log.Error(ex, $"An error occured trying to Authenticate: {ex.Message}");
                if (ex.InnerException != null)
                {
                    Log.Error(ex.InnerException, $"An error occured trying to Authenticate: {ex.InnerException.Message}");
                }
                _logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge == null) return Task.FromResult<object>(null);
            var baseUri =
                Request.Scheme +
                Uri.SchemeDelimiter +
                Request.Host +
                Request.PathBase;

            var currentUri =
                baseUri +
                Request.Path +
                Request.QueryString;

            var redirectUri =
                baseUri +
                Options.CallbackPath;
            var properties = challenge.Properties;
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = currentUri;
            }

            GenerateCorrelationId(properties);
            var state = Options.StateDataFormat.Protect(properties);
            // comma separated
            var scope = string.Join(",", Options.Scope);

            var authorizationEndpoint =
                Options.Endpoints.AuthorizationEndpoint +
                "?client_id=" + Uri.EscapeDataString(Options.ClientId) +
                "&response_type=" + Uri.EscapeDataString(scope) +
                "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                "&state=" + Uri.EscapeDataString(state);

            Response.Redirect(authorizationEndpoint);

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (!Options.CallbackPath.HasValue || Options.CallbackPath != Request.Path) return false;
            // TODO: error responses

            var ticket = await AuthenticateAsync();
            if (ticket == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new ArcGISOnlineReturnEndpointContext(Context, ticket)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = ticket.Properties.RedirectUri
            };

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null &&
                context.Identity != null)
            {
                var grantIdentity = context.Identity;
                if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, grantIdentity);
            }

            if (context.IsRequestCompleted || context.RedirectUri == null) return context.IsRequestCompleted;
            var redirectUri = context.RedirectUri;
            if (context.Identity == null)
            {

                // add a redirect hint that sign-in failed in some way
                redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
            }
            Response.Redirect(redirectUri);
            context.RequestCompleted();

            return context.IsRequestCompleted;
        }
    }
}