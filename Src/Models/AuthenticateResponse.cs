using IdentityApi.Entities;
using System.Text.Json.Serialization;

namespace IdentityApi.Models
{
    public class AuthenticateResponse
    {
        public string IdentityId { get; set; }
        public string Username { get; set; }
        public string JwtToken { get; set; }

        [JsonIgnore]
        public string RefreshToken { get; set; }

        public AuthenticateResponse(Identity identity, string jwtToken, string refreshToken)
        {
            IdentityId = identity.IdentityId;
            Username = identity.Username;
            JwtToken = jwtToken;
            RefreshToken = refreshToken;
        }
    }
}
