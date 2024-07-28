namespace JWTInAspNetCore.Models
{
    public record UserSession(string Id, string Username, string Email,string Role);
}