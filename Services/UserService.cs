using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWTInAspNetCore.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using static JWTInAspNetCore.Models.ServiceResponse;

namespace JWTInAspNetCore.Services
{
    public class UserService : IUserService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly ILogger<UserService> _logger;
        public UserService(
            IHttpContextAccessor httpContextAccessor,
            UserManager<AppUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            ILogger<UserService> logger
        )
        {
            _httpContextAccessor = httpContextAccessor;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _logger = logger;
        }

        public async Task<GeneralResponse> CreateAccount(RegisterModel register)
        {
            //checking if the requiredd information is provided or not
            if (register == null)
            {
                return new GeneralResponse(false, "Model is empty");
            }
            //creating new user instance
            var newUser = new AppUser
            {
                UserName = register.Username,
                Email = register.Email
            };
            var user = await _userManager.FindByEmailAsync(newUser.Email);
            //checking if user is already registered or not
            if (user != null)
            {
                return new GeneralResponse(false, "User already exist");
            }
            //creating a newUser of app
            var createUser = await _userManager.CreateAsync(newUser, register.Password);
            if (!createUser.Succeeded)
            {
                foreach (var error in createUser.Errors)
                {
                    _logger.LogError($"Error creating user :{error.Description}");
                }
                return new GeneralResponse(false, "Error occurred, please try again");
            }
            //retrieving the Roles from Role table
            var checkAdmin = await _roleManager.FindByNameAsync("Admin");
            var checkManager = await _roleManager.FindByNameAsync("Manager");

            if (checkAdmin == null)
            {
                await _roleManager.CreateAsync(new IdentityRole { Name = "Admin" });
                await _userManager.AddToRoleAsync(newUser, "Admin");
                return new GeneralResponse(true, "Admin account is created successfully");
            }
            else if (checkManager == null)
            {
                await _roleManager.CreateAsync(new IdentityRole { Name = "Manager" });
                await _userManager.AddToRoleAsync(newUser, "Manager");
                return new GeneralResponse(true, "Manager account is created successfully");
            }
            else
            {
                var checkUser = await _roleManager.FindByNameAsync("User");
                if (checkUser == null)
                {
                    await _roleManager.CreateAsync(new IdentityRole { Name = "User" });
                }
                await _userManager.AddToRoleAsync(newUser, "User");
                return new GeneralResponse(true, "Account created successfully");
            }
        }

        public async Task<LoginResponse> Login(LoginModel login)
        {
            if (login == null)
            {
                return new LoginResponse(false, null!, null!, "Information not provided or model is empty");
            }
            var getUser = await _userManager.FindByEmailAsync(login.Email);
            if (getUser == null)
            {
                return new LoginResponse(false, null!, null!, "User not found");
            }
            bool checkPassword = await _userManager.CheckPasswordAsync(getUser, login.Password);
            if (!checkPassword)
            {
                return new LoginResponse(false, null!, null!, "Invalid Username/Password");
            }
            if (getUser.Email == null)
            {
                return new LoginResponse(false, null!, null!, "Email is empty");
            }
            var getUserRole = await _userManager.GetRolesAsync(getUser);
            var userSession = new UserSession(getUser.Id, getUser.UserName, getUser.Email, getUserRole.First());

            string accessToken = GenerateAccessToken(userSession);
            string refreshToken = GenerateRefreshToken(getUser);

            getUser.RefreshToken = refreshToken;
            await _userManager.UpdateAsync(getUser);

            SetTokenCookie("accessToken", accessToken!);
            SetTokenCookie("refreshToken", refreshToken!);
            return new LoginResponse(true, accessToken, refreshToken, "Logged in succesfully");
        }


        public void Logout( )
        {
            var cookies = _httpContextAccessor.HttpContext.Request.Cookies.Keys;
            foreach (var cookie in cookies)
            {
                _httpContextAccessor.HttpContext.Response.Cookies.Delete(cookie);
            }
        }
        

        private string GenerateAccessToken(UserSession user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["AccessToken:Key"]!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier,user.Id),
                new Claim(ClaimTypes.Name,user.Username),
                new Claim(ClaimTypes.Email,user.Email),
                new Claim(ClaimTypes.Role,user.Role)
            };
            var accessToken = new JwtSecurityToken
            (
                issuer: _configuration["AccessToken:Issuer"],
                audience: _configuration["AccessToken:Audience"],
                claims: userClaims,
                expires: DateTime.UtcNow.AddMinutes(1.5),
                signingCredentials: credentials
            );
            return new JwtSecurityTokenHandler().WriteToken(accessToken);
        }
        private string GenerateRefreshToken(AppUser user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["RefreshToken:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email)

            };

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(3),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        private void SetTokenCookie(string key, string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                // Expires = DateTime.UtcNow.Add(timeSpan)
            };
            _httpContextAccessor.HttpContext.Response.Cookies.Append(key, token, cookieOptions);
        }
    }
}