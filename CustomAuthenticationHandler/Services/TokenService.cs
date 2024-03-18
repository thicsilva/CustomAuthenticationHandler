using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CustomAuthenticationHandler.Services;

public class TokenService
{
    private static readonly byte[] AccessTokenKey = "=HjVgdED7kGFldhqbbqT-zdEyrFkIpu:g+nhzr(6:z8crdauOZF2/LD6vpUxLZ3XQtZc_5*)PS)dG!zMAVqwT*iYRL9TUsWma/7s-m(#!:(!6GnNe8?=.=Fr@o/grs-f*fC8(iKH+-HojPkAT96Yj*PWsLZcP1.v(oj!d1ndDzweQtDr_zGkIBVvgo87JXRwVgjGG15-JLQ-q?ldSJ9wZgQHAhU@t##2U#hUmmtGJRCgM=TbzusJ5A8LB=@9X78.712H3V.Ukk(RoXHdPuOXS7iBRkX-YXG5OAMrP0t!RivcFDfzZ?)y.uvuM/FtqEa4a*cKwZn8EZ(9tD-7IYo*Th9S:I(rFY9R*)YwXOa4!:Z?:=1:4lb8WikvgfTcWLBngHu#8CRW=54uyPNHLj18)+3JaQ/uX+ZUN5VK846a*mB?ov#01_x1#sGJ.T:R*Q/ttZvq#ostgKkcs#@fcIdCp5vy8!:b5TAa.!/aB.r)fZ!BY?@BveoDmyID?FNmD3c."u8.ToArray();
    private static readonly byte[] RefreshTokenKey = "V1s@=dRmc2I)zZ=1qYzrHXDRr*L)ol.iK?!Y!MKy9pZH)6w6elYG8k+9Aux2Hin0DxlMnj-4U+r!(@TqRUkJMsaLI5=nsV(dXvP+joAM1k2izbz(eNb:WH*rtWWNjbpDbKrOU9qEJ+wW=dCe!**JpUtBeM*LAk01)oH2+g:7Lx2huFAvygy__dYq:+nqv#-D#dYipB.d4aNnU9vvecs(_:@iugiv5oSyjQlkBL2C:=N??+v3iri!O9jvx@OdZI:pC/jnuXzDojnS/0ks3ENH?IPyZ?IOfEJ8FEMYgsATXaQ0mGEkEJbKo=cw/NH?9AMyACX.Mlcx(_5l2(.s0t(#8BY:2zB/*bJEp(+_#Fm_)?)j!oxXd:6(L-60f7UQGCS_9#Vr_AS*bNRQOYPN.so/My_jrK61x8yLAEbE4#??:/)DXF!.tHIom.Iz7uyQKri-=gD1Hkttr?W3yDK*-SVpmIcVnR9x?9onJHc9w6/Z=v@o7M@x0Gr#OTZ!/xjG/K3X"u8.ToArray();
    public const string AccessTokenHeader = "X-Access-Token";
    public const string RefreshTokenHeader = "X-Refresh-Token";

    public async Task<(bool, JsonWebToken?)> ValidateToken(HttpContext context)
    {
        var (isValid, validatedToken) = await ValidateAccessToken(context);
        if (!isValid || validatedToken is null)
            return await ValidateRefreshToken(context);

        return (isValid, validatedToken);
    }

    private async Task<(bool, JsonWebToken?)> ValidateRefreshToken(HttpContext context)
    {
        if (!context.Request.Headers.TryGetValue(RefreshTokenHeader, out var token) || string.IsNullOrEmpty(token))
            return (false, null);
        var validateToken = await GetValidatedToken(token!, RefreshTokenKey);
        if (validateToken is null)
            return (false, null);

        var user = AuthService.Tokens.FirstOrDefault(e => e.Key.Equals(token));
        if (user.Value is null)
            return (false, null);

        var accessToken = GenerateAccessToken(user.Value);
        context.Response.Headers.TryAdd(AccessTokenHeader, accessToken);
        return (true, validateToken);
    }

    private async Task<(bool, JsonWebToken?)> ValidateAccessToken(HttpContext context)
    {
        if (!context.Request.Headers.TryGetValue(AccessTokenHeader, out var token) || string.IsNullOrEmpty(token))
            return (false, null);
        var validateToken = await GetValidatedToken(token!, AccessTokenKey);
        return (validateToken != null, validateToken);
    }

    private async Task<JsonWebToken?> GetValidatedToken(string token, byte[] key)
    {
        var tokenHandler = new JsonWebTokenHandler();
        try
        {
            var validatedToken = await tokenHandler.ValidateTokenAsync(token, new TokenValidationParameters()
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero

            });
            
            var jwtToken = (JsonWebToken)validatedToken.SecurityToken;
            return jwtToken;
        }
        catch
        {
            return null;
        }
    }

    public string GenerateAccessToken(string user)
    {
        return GenerateToken(user, AccessTokenKey, DateTime.UtcNow.AddMinutes(1));
    }

    public string GenerateRefreshToken(string user)
    {
        return GenerateToken(user, RefreshTokenKey, DateTime.UtcNow.AddDays(365));
    }

    private string GenerateToken(string user, byte[] key, DateTime expiration)
    {
        var signingCredentials =
            new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature);
        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(new List<Claim>() { new(ClaimTypes.Name, user) }),
            Expires = expiration,
            SigningCredentials = signingCredentials,
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}