using System.ComponentModel.DataAnnotations;

namespace JWTInAspNetCore.Models
{
    public class LoginModel
    {
        [Required,EmailAddress]
        public string Email { get; set; }
        [DataType(DataType.Password),Required]
        public string Password { get; set; }
    }
}