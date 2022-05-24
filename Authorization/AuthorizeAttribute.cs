namespace AuthenticationAPI.Authorization
{
    [AttributeUsage(AttributeTargets.Property |AttributeTargets.Method)]
    public class AuthorizeAttribute: Attribute
    {
    }
}
