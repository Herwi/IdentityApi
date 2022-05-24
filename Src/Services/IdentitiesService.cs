using IdentityApi.Entities;
using IdentityApi.Models;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace IdentityApi.Services
{
    public interface IIdentitiesService
    {
        public Task<bool> DoesTokenExistsAsync(string token);
        public Task<bool> DoesUsernameExistsAsync(string username);
        public Task<bool> DoesUsernameOrEmailExistsAsync(string username, string email);
        public Task<List<Identity>> GetAsync();
        public Task<Identity?> GetByIdAsync(string id);
        public Task<Identity?> GetByUsernameAsync(string username);
        public Task<Identity?> GetByRefreshTokenAsync(string token);
        public Task CreateAsync(Identity newIdentity);
        public Task UpdateAsync(string id, Identity updatedIdentity);
        public Task RemoveAsync(string id);
    }
    public class IdentitiesService : IIdentitiesService
    {
        private IMongoCollection<Identity> _identitiesCollection;

        public IdentitiesService(
            IOptions<IdentityServiceDatabaseSettings> identityServiceDatabaseSettings)
        {
            var mongoClient = new MongoClient(
                identityServiceDatabaseSettings.Value.ConnectionString);

            var mongoDatabase = mongoClient.GetDatabase(
                identityServiceDatabaseSettings.Value.DatabaseName);

            _identitiesCollection = mongoDatabase.GetCollection<Identity>(
                identityServiceDatabaseSettings.Value.IdentitiesCollectionName);
        }

        public async Task<bool> DoesTokenExistsAsync(string token) =>
            await _identitiesCollection.Find(x => x.RefreshTokens.Any(t => t.Token == token)).FirstOrDefaultAsync() == null ? false : true;

        public async Task<bool> DoesUsernameExistsAsync(string username) =>
            await _identitiesCollection.Find(x => x.Username == username).FirstOrDefaultAsync() == null ? false : true;

        public async Task<bool> DoesUsernameOrEmailExistsAsync(string username, string email) =>
            await _identitiesCollection.Find(x => x.Username == username || x.Email == email).FirstOrDefaultAsync() == null ? false : true;

        public async Task<List<Identity>> GetAsync() =>
            await _identitiesCollection.Find(_ => true).ToListAsync();

        public async Task<Identity?> GetByIdAsync(string id) =>
            await _identitiesCollection.Find(x => x.IdentityId == id).FirstOrDefaultAsync();

        public async Task<Identity?> GetByUsernameAsync(string username) =>
            await _identitiesCollection.Find(x => x.Username == username).FirstOrDefaultAsync();

        public async Task<Identity?> GetByRefreshTokenAsync(string token) =>
            await _identitiesCollection.Find(x => x.RefreshTokens.Any(t => t.Token == token)).FirstOrDefaultAsync();

        public async Task CreateAsync(Identity newIdentity) =>
            await _identitiesCollection.InsertOneAsync(newIdentity);

        public async Task UpdateAsync(string id, Identity updatedIdentity) =>
            await _identitiesCollection.ReplaceOneAsync(x => x.IdentityId == id, updatedIdentity);

        public async Task RemoveAsync(string id) =>
            await _identitiesCollection.DeleteOneAsync(x => x.IdentityId == id);
    }
}
