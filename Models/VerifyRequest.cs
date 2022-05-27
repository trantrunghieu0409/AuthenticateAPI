using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Models
{
    public class VerifyRequest
    {
        [Required]
        public string Token { get; set; }
    }
}
