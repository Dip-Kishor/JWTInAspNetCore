using Microsoft.AspNetCore.Identity;

namespace JWTInAspNetCore.Models
{
    public class AppUser : IdentityUser
    {
        public string? RefreshToken { get; set; }
    }
}