using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Models
{
    public class AuthenticateRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }   
    }
}
