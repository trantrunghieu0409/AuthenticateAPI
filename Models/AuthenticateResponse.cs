using System.Text.Json.Serialization;

namespace AuthenticationAPI.Models
{
    public class AuthenticateResponse
    {
        public int Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string JwtToken { get; set; }

        [JsonIgnore]
        public string RefreshToken { get; set; }
    }
}
