using CustomAuthenticationHandler.DTO;
using CustomAuthenticationHandler.Handlers;
using CustomAuthenticationHandler.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CustomAuthenticationHandler.Controllers;

[ApiController]
[Route("api/auth")]
[Authorize]
public class AuthController:ControllerBase
{
    private readonly AuthService _authService;

    public AuthController(AuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public IActionResult Login([FromBody] AuthDto authDto)
    {
        var refreshToken = _authService.Authenticate(authDto.Login, authDto.Password, HttpContext);
        if (!string.IsNullOrEmpty(refreshToken))
            return Ok(new AuthResponseDto(refreshToken));

        return NotFound();
    }

    [HttpPost("logoff")]
    public void Logoff()
    {
        _authService.RevokeAuthentication(HttpContext);
    }
}