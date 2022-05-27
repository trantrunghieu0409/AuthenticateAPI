using System.ComponentModel.DataAnnotations;

namespace AuthenticationAPI.Models
{
    public class ChangeTimeAliveRequest
    {
        [Required]
        public int time { get; set; }
    }
}
