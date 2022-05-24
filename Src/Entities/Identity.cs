using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System.Text.Json.Serialization;

namespace IdentityApi.Entities
{
    public class Identity
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? IdentityId { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public List<IdentityClaim> IdentityClaims { get; set; }

        [JsonIgnore]
        public string PasswordHash { get; set; }

        [JsonIgnore]
        public List<RefreshToken> RefreshTokens { get; set; }
    }
}