﻿using Microsoft.EntityFrameworkCore;
using System.Text.Json.Serialization;

namespace AuthenticationAPI.Entities
{
    public class Account
    {
        public int Id { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
        public Role Role { get; set; }

        public string? Token { get; set; }
        
        [JsonIgnore]
        public string? PasswordHash { get; set; }


        public DateTime CreatedDate => DateTime.UtcNow;
        public DateTime? LastUpdatedDate { get; set; }
        public DateTime? ExpiredDate { get; set; }


        public bool IsExpired => DateTime.UtcNow >= ExpiredDate;
        public bool IsActive => !IsExpired;

        [JsonIgnore]
        public List<RefreshToken>? RefreshTokens { get; set; }
    }
}
