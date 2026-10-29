using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using SyncClipboard.Server.Core.CredentialChecker;

namespace SyncClipboard.Server.Core;

public class BasicAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ICredentialChecker checker
        ) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    internal static bool TryParseCredentials(string? authorizationHeader, out string username, out string password)
    {
        username = string.Empty;
        password = string.Empty;

        if (string.IsNullOrWhiteSpace(authorizationHeader))
        {
            return false;
        }

        var separator = authorizationHeader.IndexOfAny([' ', '\t']);
        if (separator < 0 || !authorizationHeader[..separator].Equals("Basic", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var token = authorizationHeader[separator..].Trim();
        if (token.Length == 0)
        {
            return false;
        }

        try
        {
            var credentialString = new UTF8Encoding(false, true).GetString(Convert.FromBase64String(token));
            var colon = credentialString.IndexOf(':');
            if (colon < 0)
            {
                return false;
            }

            username = credentialString[..colon];
            password = credentialString[(colon + 1)..];
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authHeader = Request.Headers.Authorization.ToString();
        if (TryParseCredentials(authHeader, out var username, out var password))
        {
            if (checker.Check(username, password))
            {
                var claims = new[] { new Claim("name", username), new Claim(ClaimTypes.Role, "Admin") };
                var identity = new ClaimsIdentity(claims, "Basic");
                var claimsPrincipal = new ClaimsPrincipal(identity);
                return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(claimsPrincipal, Scheme.Name)));
            }

            Response.StatusCode = 401;
            Response.Headers.WWWAuthenticate = "Basic realm=\"SyncClipboard\"";
            return Task.FromResult(AuthenticateResult.Fail("Invalid Authorization Header"));
        }
        else
        {
            Response.StatusCode = 401;
            Response.Headers.WWWAuthenticate = "Basic realm=\"SyncClipboard\"";
            return Task.FromResult(AuthenticateResult.Fail("Invalid Authorization Header"));
        }
    }
}
