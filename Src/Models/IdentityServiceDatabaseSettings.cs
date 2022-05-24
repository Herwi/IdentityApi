namespace IdentityApi.Models
{
    public class IdentityServiceDatabaseSettings
    {
        public string ConnectionString { get; set; } = null!;
        public string DatabaseName { get; set; } = null!;
        public string IdentitiesCollectionName { get; set; } = null!;
    }
}
