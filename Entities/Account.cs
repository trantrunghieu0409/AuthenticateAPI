using Microsoft.EntityFrameworkCore;
using System.Text.Json.Serialization;

namespace AuthenticationAPI.Entities
{
    [Owned]
    public class Account
    {
        int Id { get; set; }
        string? FirstName { get; set; }
        string? LastName { get; set; }
        public string? Email { get; set; }
        public Role Role { get; set; }

        public string? Username { get; set; }
        
        [JsonIgnore]
        public string? PasswordHarsh { get; set; }


        public DateTime CreatedDate => DateTime.UtcNow;
        public DateTime? ExpiredDate { get; set; }


        public bool IsExpired => DateTime.UtcNow >= ExpiredDate;
        public bool IsActive => !IsExpired;

        List<RefreshToken>? refreshTokens { get; set; }
    }
}
