using IdentityApi.Authorization;
using IdentityApi.Entities;
using IdentityApi.Helpers;
using IdentityApi.Models;
using Microsoft.Extensions.Options;

namespace IdentityApi.Services
{
	public interface IAuthService
	{
		Task Register(RegisterRequest registerRequest);
		Task<AuthenticateResponse> Authenticate(AuthenticateRequest authenticateRequest, string ipAddress);
		Task<AuthenticateResponse> RefreshToken(string token, string ipAddress);

	}

	public class AuthService : IAuthService
    {
		private static readonly int TokenTTL = 10; // in minutes

		private IIdentitiesService _identitiesService;
		private IJwtUtils _jwtUtils;
		private AppSettings _appSettings;
		public AuthService(IIdentitiesService identitiesService, IJwtUtils jwtUtils, IOptions<AppSettings> appSettings)
		{
			_identitiesService = identitiesService;
			_jwtUtils = jwtUtils;
			_appSettings = appSettings.Value;
		}

		public async Task Register (RegisterRequest registerRequest)
        {
			var usernameOrEmailExists = await _identitiesService.DoesUsernameOrEmailExistsAsync(registerRequest.Username, registerRequest.Email);
			if (usernameOrEmailExists)
				throw new AppException("Username or email is arleady in usage");

			if (!checkIfPasswordIsSafe(registerRequest.Password))
				throw new AppException("Password is to weak");

			await _identitiesService.CreateAsync(new Identity()
			{
				Username = registerRequest.Username,
				Email = registerRequest.Email,
				PasswordHash = registerRequest.Password,
				IdentityClaims = new List<IdentityClaim>(),
				RefreshTokens = new List<RefreshToken>()
			});
        }

		public async Task<AuthenticateResponse> Authenticate(AuthenticateRequest authenticateRequest, string ipAddress)
		{
			var identity = await _identitiesService.GetByUsernameAsync(authenticateRequest.Username);

			if (identity == null || authenticateRequest.Password != identity.PasswordHash)
				throw new AppException("Username or password is incorrect");

			var jwtToken = _jwtUtils.GenerateJwtToken(identity);
			var refreshToken = await _jwtUtils.GenerateRefreshToken(ipAddress);

			identity.RefreshTokens.Add(refreshToken);

			await _identitiesService.UpdateAsync(identity.IdentityId, identity);

			return new AuthenticateResponse(identity, jwtToken, refreshToken.Token);
		}

		public async Task<AuthenticateResponse> RefreshToken(string? token, string ipAddress)
        {
			var identity = token != null ? await _identitiesService.GetByRefreshTokenAsync(token) : null;
			if (identity == null)
				throw new AppException("Invalid token");
			var refreshToken = identity.RefreshTokens.Single(x => x.Token == token);

			if (refreshToken.IsRevoked)
            {
				// revoke all descendant tokens in case this token has been compromised
				revokeDescendantRefreshTokens(refreshToken, identity, ipAddress, $"Attempted reuse of revoked ancestor token: {token}");
				await _identitiesService.UpdateAsync(identity.IdentityId, identity);
			}

			if (!refreshToken.IsActive)
				throw new AppException("Invalid token");

			// replace old refresh token with a new one (rotate token)
			var newRefreshToken = await rotateRefreshToken(refreshToken, ipAddress);
			identity.RefreshTokens.Add(newRefreshToken);

			// remove old refresh tokens from user
			removeOldRefreshTokens(identity);

			await _identitiesService.UpdateAsync(identity.IdentityId, identity);

			var jwtToken = _jwtUtils.GenerateJwtToken(identity);

			return new AuthenticateResponse(identity, jwtToken, newRefreshToken.Token);
		}
		public async void RevokeToken(string token, string ipAddress)
		{
			var identity = await _identitiesService.GetByRefreshTokenAsync(token);
			var refreshToken = identity.RefreshTokens.Single(x => x.Token == token);

			if (!refreshToken.IsActive)
				throw new AppException("Invalid token");

			// revoke token and save
			revokeRefreshToken(refreshToken, ipAddress, "Revoked without replacement");
			await _identitiesService.UpdateAsync(identity.IdentityId, identity);
		}

		private bool checkIfPasswordIsSafe(string password)
        {
			return true;
        }

		private async Task<RefreshToken> rotateRefreshToken(RefreshToken refreshToken, string ipAddress)
		{
			var newRefreshToken = await _jwtUtils.GenerateRefreshToken(ipAddress);
			revokeRefreshToken(refreshToken, ipAddress, "Replaced by new token", newRefreshToken.Token);
			return newRefreshToken;
		}
		private void removeOldRefreshTokens(Identity identity)
		{
			// remove old inactive refresh tokens from user based on TTL in app settings
			identity.RefreshTokens.RemoveAll(x =>
				!x.IsActive &&
				x.Created.AddDays(_appSettings.RefreshTokenTTL) <= DateTime.UtcNow);
		}

		private void revokeDescendantRefreshTokens(RefreshToken refreshToken, Identity identity, string ipAddress, string reason)
		{
			// recursively traverse the refresh token chain and ensure all descendants are revoked
			if (!string.IsNullOrEmpty(refreshToken.ReplacedByToken))
			{
				var childToken = identity.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken.ReplacedByToken);
				if (childToken.IsActive)
					revokeRefreshToken(childToken, ipAddress, reason);
				else
					revokeDescendantRefreshTokens(childToken, identity, ipAddress, reason);
			}
		}

		private void revokeRefreshToken(RefreshToken token, string ipAddress, string? reason = null, string? replacedByToken = null)
		{
			token.Revoked = DateTime.UtcNow;
			token.RevokedByIp = ipAddress;
			token.ReasonRevoked = reason;
			token.ReplacedByToken = replacedByToken;
		}
	}
}
