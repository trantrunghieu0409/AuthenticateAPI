using AuthenticationAPI.Helpers;
using AuthenticationAPI.Services;
using Microsoft.Extensions.Options;

namespace AuthenticationAPI.Authorization
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly AppSettings _appSettings;

        public JwtMiddleware(RequestDelegate next, IOptions<AppSettings> appSettings)
        {
            _next = next;
            _appSettings = appSettings.Value;
        }

        public async Task Invoke(HttpContext context, IAccountService accountService, JwtUtils jwtUtils)
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            var accountId = jwtUtils.ValidateToken(token);
            if (accountId != null)
            {
                context.Items["Account"] = accountService.GetAccountId((int)accountId);
            }

            await _next(context);
        }
    }
}
