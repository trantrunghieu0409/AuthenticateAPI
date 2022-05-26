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
        // authenticate
        public AuthenticateResponse Authenticate(AuthenticateRequest request, string ipAddress);
        public AuthenticateResponse RefreshToken(string token, string ipAddress);

        // CRUD
        public AccountResponse GetAccountById(int accountId);
        public IEnumerable<AccountResponse> GetAllAccounts();
        public AccountResponse Create(CreateRequest request);
        public AccountResponse Update(UpdateRequest request);
        public void Delete(int Id);

        public Account GetAccountId(int accountId);
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

        // authenticate methods
        public AuthenticateResponse Authenticate(AuthenticateRequest request, string ipAddress)
        {
            var account = _context.Accounts.SingleOrDefault(x => x.Email == request.Email);

            if (account == null || !BCrypt.Net.BCrypt.Verify(request.Password, account.PasswordHash))
                throw new AppException("Username or Password is Incorrect");

            var jwtToken = _jwtUtils.GenerateToken(account);
            var refreshToken = _jwtUtils.generateRefreshToken(ipAddress);
            account.RefreshTokens.Add(refreshToken);

            removeOldRefreshTokens(account);

            _context.Accounts.Update(account);
            _context.SaveChanges();

            var response = _mapper.Map<AuthenticateResponse>(account);
            response.RefreshToken = refreshToken.Token;
            response.JwtToken = jwtToken;
            return response;
        }

        public AuthenticateResponse RefreshToken(string token, string ipAddress)
        {
            var account = getAccountByRefreshToken(token);
            var refreshToken = account.RefreshTokens.Single(x => x.Token == token);

            if (refreshToken.IsRevoked)
            {
                // revoke all descendant tokens in case this token has been compromised
                revokeDescendantRefreshTokens(refreshToken, account, ipAddress);
                _context.Update(account);
                _context.SaveChanges();
            }

            if (!refreshToken.IsActive)
                throw new AppException("Invalid refresh token");

            // replace old refresh token with a new one (rotate token)
            var newRefreshToken = rotateRefreshToken(refreshToken, ipAddress);
            account.RefreshTokens.Add(newRefreshToken);


            // remove old refresh tokens from account
            removeOldRefreshTokens(account);

            // save changes to db
            _context.Update(account);
            _context.SaveChanges();

            // generate new jwt
            var jwtToken = _jwtUtils.GenerateToken(account);

            // return data in authenticate response object
            var response = _mapper.Map<AuthenticateResponse>(account);
            response.JwtToken = jwtToken;
            response.RefreshToken = newRefreshToken.Token;
            return response;
        }

        public void RevokeToken(string token, string ipAddress)
        {
            var account = getAccountByRefreshToken(token);
            var refreshToken = account.RefreshTokens.Single(x => x.Token == token);

            if (!refreshToken.IsActive)
                throw new AppException("Invalid token");

            // revoke token and save
            revokeRefreshToken(refreshToken, ipAddress);
            _context.Update(account);
            _context.SaveChanges();
        }

        // CRUD methods
        public AccountResponse GetAccountById(int accountId)
        {
            var account = _context.Accounts.FirstOrDefault(x => x.Id == accountId);
            if (account == null) throw new KeyNotFoundException("Account not found");
            return _mapper.Map<AccountResponse>(account);
        }

        public IEnumerable<AccountResponse> GetAllAccounts()
        {
            var accounts = _context.Accounts;
            return _mapper.Map<IList<AccountResponse>>(accounts);
        }


        public Account GetAccountId(int accountId)
        {
            return _context.Accounts.FirstOrDefault(x => x.Id == accountId);
        }

        public AccountResponse Create(CreateRequest request)
        {
            var account = _mapper.Map<Account>(request);

            account.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);
            account.Role = account.Id == 1 ? Role.Admin : Role.User; // admin is the first created/registered account

            _context.Accounts.Add(account);
            _context.SaveChanges();

            return _mapper.Map<AccountResponse>(account);
        }

        public AccountResponse Update(UpdateRequest request)
        {

        }

        public void Delete(int Id)
        {
            _context.Remove(Id);
            _context.SaveChanges();
        }




        // private methods
        private RefreshToken rotateRefreshToken(RefreshToken refreshToken, string ipAddress)
        {
            var newRefreshToken = _jwtUtils.generateRefreshToken(ipAddress);

            revokeRefreshToken(refreshToken, ipAddress);
            return newRefreshToken;
        }

        private void revokeRefreshToken(RefreshToken token, string ipAddress, string newToken = null)
        {
            token.RevokedDate = DateTime.UtcNow;
            token.RevokedByIp = ipAddress;
            token.ReplacedByToken = newToken;
        }

        private void revokeDescendantRefreshTokens(RefreshToken refreshToken, Account account, string ipAddress)
        {
            if (!string.IsNullOrEmpty(refreshToken.ReplacedByToken))
            {
                var childToken = account.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken.ReplacedByToken);
                if (childToken != null)
                    revokeRefreshToken(childToken, ipAddress);
            }
        }

        private Account getAccountByRefreshToken(string token)
        {
            var account = _context.Accounts.SingleOrDefault(x => x.RefreshTokens.Any(t => t.Token == token));
            if (account == null) throw new AppException("Invalid token");
            return account;
        }

        private void removeOldRefreshTokens(Account account)
        {
            account.RefreshTokens.RemoveAll(x => x.IsActive == false
                                                 && x.CreatedDate.AddDays(_appSettings.RefreshTokenTTL) <= DateTime.UtcNow);
        }

    }
}
