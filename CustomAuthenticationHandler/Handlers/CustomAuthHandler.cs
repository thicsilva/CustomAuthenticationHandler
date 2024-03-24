using System.IdentityModel.Tokens.Jwt;
using System.Text.Encodings.Web;
using CustomAuthenticationHandler.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace CustomAuthenticationHandler.Handlers;

public class CustomAuthHandler : AuthenticationHandler<JwtBearerOptions>
{
    private readonly TokenService _tokenService;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            var token = await _tokenService.ValidateToken(Context);
            if (string.IsNullOrEmpty(token))
                return AuthenticateResult.NoResult();

            var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token);
            var principal = await _tokenService.GetClaimsPrincipalFromToken(token);
            var tokenValidatedContext = new TokenValidatedContext(Context, Scheme, Options)
            {
                Principal = principal,
                SecurityToken = jwtToken,
                Properties =
                {
                    ExpiresUtc = GetSafeDateTime(jwtToken.ValidTo),
                    IssuedUtc = GetSafeDateTime(jwtToken.ValidFrom)
                }
            };

            if (Options.SaveToken)
            {
                tokenValidatedContext.Properties.StoreTokens(new[]
                {
                    new AuthenticationToken { Name = "access_token", Value = token }
                });
            }

            tokenValidatedContext.Success();
            return tokenValidatedContext.Result;
        }
        catch (Exception e)
        {
            return AuthenticateResult.Fail(e);
        }
    }

    private DateTimeOffset? GetSafeDateTime(DateTime dateTime)
    {
        if (dateTime == DateTime.MinValue)
        {
            return null;
        }

        return dateTime;
    }

    [Obsolete("Obsolete")]
    public CustomAuthHandler(IOptionsMonitor<JwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder,
        ISystemClock clock, TokenService tokenService) : base(options, logger, encoder, clock)
    {
        _tokenService = tokenService;
    }

    public CustomAuthHandler(IOptionsMonitor<JwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder,
        TokenService tokenService) : base(options, logger, encoder)
    {
        _tokenService = tokenService;
    }
}