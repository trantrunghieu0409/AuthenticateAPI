using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Models
{
    public class NewLoginRequest
    {
        [Required]
        public string IpAddress { get; set; }

        [Required]
        public string Token { get; set; }
    }
}
