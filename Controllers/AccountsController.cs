using AuthenticationAPI.Authorization;
using AuthenticationAPI.Entities;
using AuthenticationAPI.Models;
using AuthenticationAPI.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationAPI.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class AccountsController: BaseController
    {
        private readonly IAccountService _accountService;

        public AccountsController(IAccountService accountService)
        {
            _accountService = accountService;
        }

        [AllowAnonymous]
        [HttpPost("authenticate")]
        public ActionResult<AuthenticateResponse> Authenticate(AuthenticateRequest request)
        {
            var response = _accountService.Authenticate(request, ipAddress());
            if (response.RefreshToken != null) setTokenCookie(response.RefreshToken);
            return Ok(response);
        }

        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public ActionResult<AuthenticateResponse> RefreshToken()
        {
            var token = Request.Cookies["refreshToken"];
            var response = _accountService.RefreshToken(token, ipAddress());
            setTokenCookie(response.RefreshToken);
            return response;
        }

        [Authorize(Role.Admin)]
        [HttpGet]
        public IEnumerable<AccountResponse> GetAllAccounts()
        {
            return _accountService.GetAllAccounts();
        }

        [Authorize(Role.Admin)]
        [HttpGet("{id:int}")]
        public ActionResult<AccountResponse> GetAccountById(int id)
        {
            return Ok(_accountService.GetAccountById(id));
        }

        [Authorize(Role.Admin)]
        [HttpPost]
        public ActionResult<AccountResponse> CreateAccount(CreateRequest createRequest)
        {
            return Ok(_accountService.Create(createRequest));
        }

        [HttpPut("{id:int}")]
        public ActionResult<AccountResponse> UpdateAccount(int id, UpdateRequest updateRequest)
        {
            if (Account.Role != Role.Admin || Account.Id != id)
                return Unauthorized(new { message = "Unauthorized" });

            return Ok(_accountService.Update(id, updateRequest));
        }

        [Authorize(Role.Admin)]
        [HttpDelete("{id:int}")]
        public ActionResult DeleteAccount(int id)
        {
            _accountService.Delete(id);
            return Ok(new { message = "Delete account successfully" });
        }

        // helper methods
        private string ipAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }

        private void setTokenCookie(string refreshToken)
        {
            var cookie = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTimeOffset.UtcNow.AddDays(7),
            };

            Response.Cookies.Append("refreshToken", refreshToken, cookie);
        }
    }
}
