﻿using System.Security.Claims;
using System.Security.Principal;
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
        var (isValid, token) = await _tokenService.ValidateToken(Context);
        if (!isValid||token is null)
            return AuthenticateResult.NoResult();

        var identity = new ClaimsIdentity(token.Claims, Scheme.Name);
        var principal = new GenericPrincipal(identity, null);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }
    
    [Obsolete("Obsolete")]
    public CustomAuthHandler(IOptionsMonitor<JwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock, TokenService tokenService) : base(options, logger, encoder, clock)
    {
        _tokenService = tokenService;
    }

    public CustomAuthHandler(IOptionsMonitor<JwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder, TokenService tokenService) : base(options, logger, encoder)
    {
        _tokenService = tokenService;
    }
}