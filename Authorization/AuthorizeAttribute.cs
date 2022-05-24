﻿using AuthenticationAPI.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace AuthenticationAPI.Authorization
{
    [AttributeUsage(AttributeTargets.Class |AttributeTargets.Method)]
    public class AuthorizeAttribute: Attribute, IAuthorizationFilter
    {
        private readonly IList<Role> _roles;

        public AuthorizeAttribute(params Role[] roles)
        {
            _roles = roles ?? new Role[] { };
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var allowAnonymous = context.ActionDescriptor.EndpointMetadata.OfType<AllowAnonymousAttribute>().Any();
            if (allowAnonymous)
                return;

            var account = context.HttpContext.Items["Account"] as Account;
            if (account == null)
            {
                context.Result = new JsonResult(new { message = "Unauthorized" }) { StatusCode = StatusCodes.Status401Unauthorized }; 
            }
        }
    }
}
