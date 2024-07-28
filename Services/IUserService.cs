using JWTInAspNetCore.Models;
using static JWTInAspNetCore.Models.ServiceResponse;

namespace JWTInAspNetCore.Services
{
    public interface IUserService
    {
        Task<GeneralResponse> CreateAccount(RegisterModel register);
        Task<LoginResponse> Login(LoginModel login);
        public void Logout();
    }
}