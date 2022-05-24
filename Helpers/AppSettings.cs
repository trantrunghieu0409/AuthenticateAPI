namespace AuthenticationAPI.Helpers
{
    public class AppSettings
    {
        public string Secret { get; set; }

        public DateTime? RefreshTokenTTL { get; set; }
    }
}
