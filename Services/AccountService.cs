using AuthenticationAPI.Entities;

namespace AuthenticationAPI.Services
{
    public interface IAccountService
    {
        public Account GetAccountById(int? accountId);
    }

    public class AccountService : IAccountService
    {
        public Account GetAccountById(int? accountId)
        {
            throw new NotImplementedException();
        }
    }
}
