using System.ComponentModel.DataAnnotations;

namespace JWTInAspNetCore.Models
{
    public class RegisterModel
    {
        [Required(ErrorMessage = "Please enter your name")]
        public string Username { get; set; }
        [Required(ErrorMessage = "Please enter your email address"), EmailAddress]
        public string Email { get; set; }
        [Required(ErrorMessage = "Please enter password"), DataType(DataType.Password)]
        public string Password { get; set; }
        [DataType(DataType.Password), Compare("Password", ErrorMessage = "Password not matched"), Required(ErrorMessage ="Fill this field")]
        public string ConfirmPassword { get; set; }
    }
}