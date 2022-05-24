using AuthenticationAPI.Authorization;
using AuthenticationAPI.Entities;
using AuthenticationAPI.Helpers;
using AuthenticationAPI.Models;
using Microsoft.Extensions.Options;
using AutoMapper;

namespace AuthenticationAPI.Services
{
    public interface IAccountService
    {
        public AuthenticateResponse Authenticate(AuthenticateRequest request, string ipAddress);

        public Account GetAccountById(int accountId);
        public IEnumerable<AccountResponse> GetAllAccounts();
    }

    public class AccountService : IAccountService
    {
        private readonly DataContext _context;
        private readonly JwtUtils _jwtUtils;
        private readonly AppSettings _appSettings;
        private readonly IMapper _mapper;

        public AccountService(DataContext context, JwtUtils jwtUtils, IMapper mapper, IOptions<AppSettings> appSettings)
        {
            _context = context;
            _jwtUtils = jwtUtils;
            _mapper = mapper;
            _appSettings = appSettings.Value;
        }

        public AuthenticateResponse Authenticate(AuthenticateRequest request, string ipAddress)
        {
            var account = _context.Accounts.SingleOrDefault(x => x.Email == request.Email);

            if (account == null || !BCrypt.Net.BCrypt.Verify(request.Password, account.PasswordHash))
                throw new AppException("Username or Password is Incorrect");

            var jwtToken = _jwtUtils.GenerateToken(account);
            var refreshToken = _jwtUtils.generateRefreshToken(ipAddress);
            account.RefreshTokens.Add(refreshToken);

            RemoveOldRefreshTokens(account);

            _context.Accounts.Update(account);
            _context.SaveChanges();

            var response = _mapper.Map<AuthenticateResponse>(account);
            response.RefreshToken = refreshToken.Token;
            response.JwtToken = jwtToken;
            return response;
        }

        private void RemoveOldRefreshTokens(Account account)
        {
            account.RefreshTokens.RemoveAll(x => x.IsActive == false
                                                 && x.CreatedDate.AddDays(_appSettings.RefreshTokenTTL) <= DateTime.UtcNow);
        }

        public Account GetAccountById(int accountId)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<AccountResponse> GetAllAccounts()
        {
            var accounts = _context.Accounts;
            return _mapper.Map<IList<AccountResponse>>(accounts);
        }
    }
}
