namespace JWTInAspNetCore.Models
{
    public class ServiceResponse
    {
        public record GeneralResponse(bool Flag,string Message);
        public record LoginResponse(bool Flag, string? AccessToken, string? RefreshToken, string? Message);
    }
}