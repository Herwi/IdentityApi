using IdentityApi.Authorization;
using IdentityApi.Controllers;
using IdentityApi.Entities;
using IdentityApi.Helpers;
using IdentityApi.Models;
using IdentityApi.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace IdentityApi.UnitTests.ControllerTests
{
    public class AuthControllerTests
    {
        private static readonly int _refreshTokenTTL = 7;

        private readonly Mock<HttpContext> _httpContext;
        private readonly Mock<IIdentitiesService> _identitiesService;
        private readonly JwtUtils _jwtUtils;
        private readonly IOptions<AppSettings> _appSettings;
        private readonly Mock<AuthService> _authService;
        private readonly AuthController _authController;

        public AuthControllerTests()
        {
            _httpContext = new Mock<HttpContext>();
            _httpContext.Setup(c => c.Request.Headers.ContainsKey("X-Forwarded-For")).Returns(true);
            _httpContext.Setup(c => c.Request.Headers["X-Forwarded-For"]).Returns("0.0.0.0");
            _httpContext.Setup(c => c.Response.Cookies.Append(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CookieOptions>())).Verifiable();
            _identitiesService = new Mock<IIdentitiesService>();

            _appSettings = Options.Create(new AppSettings
            {
                Secret = "ofjB9FoliOo0LcRw",
                RefreshTokenTTL = _refreshTokenTTL
            });

            _jwtUtils = new JwtUtils(_identitiesService.Object, _appSettings);

            _authService = new Mock<AuthService>(_identitiesService.Object, _jwtUtils, _appSettings);
            _authController = new AuthController(_authService.Object)
            {
                ControllerContext = new ControllerContext { HttpContext = _httpContext.Object},
            };
        }

        [Theory]
        [InlineData("Test", "some2@email.com")]
        [InlineData("Test2", "some@email.com")]
        [InlineData("Test", "some@email.com")]
        public async Task Register_WhenUsernameOrEmailAlreadyUsed_ShouldThrowException(string username, string email)
        {
            // Arrange
            var identity = PrepareIdentity();

            // Act & Assert
            await Assert.ThrowsAsync<AppException>(async () =>
            {
                var actionResult = await _authController.Register(new RegisterRequest
                {
                    Username = username,
                    Email = email,
                    Password = "pass"
                });
            });
        }

        [Fact]
        public async Task Authenticate_WhenCredentialsAreCorrect_ShouldAuthenticateUser()
        {
            // Arrange
            var identity = PrepareIdentity();

            // Act
            var actionResult = await _authController.Authenticate(new AuthenticateRequest
            {
                Username = "Test",
                Password = "pass"
            });

            // Assert
            Assert.IsType<OkObjectResult>(actionResult);
            Assert.Single(identity.RefreshTokens);
            _httpContext.Verify(c => c.Response.Cookies.Append(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CookieOptions>()));
        }

        [Theory]
        [InlineData("Test", "pass2")]
        [InlineData("Test2", "pass")]
        public async Task Authenticate_WhenCredentialsAreInvalid_ShouldThrowException(string username, string password)
        {
            // Arrange
            PrepareIdentity();

            // Act & Assert
            await Assert.ThrowsAsync<AppException>(async () => {
                var actionResult = await _authController.Authenticate(new AuthenticateRequest
                {
                    Username = username,
                    Password = password
                });
            });
        }

        private Identity PrepareIdentity()
        {
            var identity = new Identity
            {
                IdentityId = "6282273c2fee24a4562800db",
                Username = "Test",
                PasswordHash = "pass",
                Email = "some@email.com",
                IdentityClaims = new List<IdentityClaim>(),
                RefreshTokens = new List<RefreshToken>()
            };

            _identitiesService
                .Setup(i => i.GetByUsernameAsync(identity.Username))
                .Returns(Task.FromResult(identity));

            _identitiesService
                .Setup(i => i.DoesTokenExistsAsync(It.IsAny<string>()))
                .Returns(Task.FromResult(false));

            _identitiesService
                .Setup(x => x.DoesUsernameOrEmailExistsAsync(It.Is<string>(a => a == identity.Username), It.IsAny<string>()))
                .Returns(Task.FromResult(true));
            _identitiesService
                .Setup(x => x.DoesUsernameOrEmailExistsAsync(It.IsAny<string>(), It.Is<string>(a => a == identity.Email)))
                .Returns(Task.FromResult(true));

            return identity;
        }
    }
}