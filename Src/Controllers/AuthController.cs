using IdentityApi.Authorization;
using IdentityApi.Models;
using IdentityApi.Services;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApi.Controllers
{
    [Authorize]
	[Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
		private readonly IAuthService _authService;

		public AuthController(IAuthService authService)
		{
			_authService = authService;
		}

		[HttpGet]
		public List<string> Get()
		{
			var users = new List<string>
		{
			"Satinder Singh",
			"Amit Sarna",
			"Davin Jon"
		};

			return users;
		}

        [AllowAnonymous]
        [HttpPost("register")]
		public async Task<IActionResult> Register(RegisterRequest registerRequest)
        {
			await _authService.Register(registerRequest);
			return Ok();
        }

		[AllowAnonymous]
		[HttpPost("authenticate")]
		public async Task<IActionResult> Authenticate(AuthenticateRequest authenticateRequest)
		{
			var response = await _authService.Authenticate(authenticateRequest, ipAddress());
			setTokenCookie(response.RefreshToken);
			return Ok(response);
		}

        [AllowAnonymous]
        [HttpPost("refresh-token")]
		public async Task<IActionResult> RefreshToken()
        {
			var refreshToken = Request.Cookies["refreshToken"];
			var response = await _authService.RefreshToken(refreshToken, ipAddress());
			setTokenCookie(response.RefreshToken);
			return Ok(response);
        }
		private void setTokenCookie(string token)
		{
			// append cookie with refresh token to the http response
			var cookieOptions = new CookieOptions
			{
				HttpOnly = true,
				Expires = DateTime.UtcNow.AddDays(7)
			};
			Response.Cookies.Append("refreshToken", token, cookieOptions);
		}

		private string ipAddress()
		{
			// get source ip address for the current request
			if (Request.Headers.ContainsKey("X-Forwarded-For"))
				return Request.Headers["X-Forwarded-For"];
			else
				return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
		}
	}
}
