using AuthenticationAPI.Authorization;
using AuthenticationAPI.Entities;
using AuthenticationAPI.Helpers;
using AuthenticationAPI.Models;
using Microsoft.Extensions.Options;

namespace AuthenticationAPI.Services
{
    public interface IAccountService
    {
        public AuthenticateResponse Authenticate(AuthenticateRequest request, string ipAddress);

        public Account GetAccountById(int accountId);
        public IEnumerable<Account> GetAllAccounts();
    }

    public class AccountService : IAccountService
    {
        private readonly DataContext _context;
        private readonly JwtUtils _jwtUtils;
        private readonly AppSettings _appSettings;

        public AccountService(DataContext context, JwtUtils jwtUtils, IOptions<AppSettings> appSettings)
        {
            _context = context;
            _jwtUtils = jwtUtils;
            _appSettings = appSettings.Value;
        }

        public AuthenticateResponse Authenticate(AuthenticateRequest request, string ipAddress)
        {
            var account = _context.Accounts.SingleOrDefault(x => x.Email == request.Email);

            if (account == null || !BCrypt.Verify(account.PasswordHarsh, request.Password))
                throw new ApplicationException()
        }

        public Account GetAccountById(int accountId)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<Account> GetAllAccounts()
        {
            throw new NotImplementedException();
        }
    }
}
