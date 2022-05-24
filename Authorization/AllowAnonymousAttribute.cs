namespace AuthenticationAPI.Authorization
{
    [AttributeUsage(AttributeTargets.Method)]
    public class AllowAnonymousAttribute: Attribute
    {
    }
}
