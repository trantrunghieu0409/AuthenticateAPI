using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Models
{
    public class ForgotPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
