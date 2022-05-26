using AuthenticationAPI.Authorization;
using AuthenticationAPI.Entities;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationAPI.Controllers
{
    [Authorize]
    public abstract class BaseController: ControllerBase
    {
        public Account Account => (Account)HttpContext.Items["Account"];
    }
}
