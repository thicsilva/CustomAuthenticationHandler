namespace CustomAuthenticationHandler.Services;

public class AuthService
{
    private static readonly IDictionary<string, string> PrivateUsers = new Dictionary<string, string>()
        { { "user", "pass" }, { "habib", "123" } };

    private static readonly IDictionary<string, string> PrivateTokens = new Dictionary<string, string>();

    private readonly TokenService _tokenService;

    public static IReadOnlyDictionary<string, string> Users => PrivateUsers.AsReadOnly();
    public static IReadOnlyDictionary<string, string> Tokens => PrivateTokens.AsReadOnly();

    public AuthService(TokenService tokenService)
    {
        _tokenService = tokenService;
    }

    public string? Authenticate(string username, string password, HttpContext context)
    {
        if (!PrivateUsers.Any(e => e.Key == username && e.Value == password))
            return null;


        var accessToken = _tokenService.GenerateAccessToken(username);
        context.Response.Headers.TryAdd(TokenService.AccessTokenHeader, accessToken);
        var refreshToken= _tokenService.GenerateRefreshToken(username);
        PrivateTokens.TryAdd(refreshToken, username);
        return refreshToken;
    }

    public void RevokeAuthentication(HttpContext context)
    {
        if (context.Request.Headers.TryGetValue(TokenService.RefreshTokenHeader, out var refreshToken))
        {
            PrivateTokens.Remove(refreshToken.ToString());
        }
        
        context.Response.Headers.TryAdd(TokenService.AccessTokenHeader, "");
        context.Response.Headers.TryAdd(TokenService.RefreshTokenHeader, "");
    }
}