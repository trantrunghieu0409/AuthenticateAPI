using AuthenticationAPI.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationAPI.Helpers
{
    public class DataContext: DbContext
    {
        private readonly IConfiguration _configuration;

        public DataContext(IConfiguration configuration) : base()
        {
            _configuration = configuration;
        }

        DbSet<Account> accounts;

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseInMemoryDatabase("TestDB"); // change this later to use sql server
        }
    }
}
