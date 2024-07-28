using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWTInAspNetCore.Data;
using JWTInAspNetCore.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace JWTInAspNetCore.Middleware
{
    public class TokenRenewalMiddleWare
    {
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<TokenRenewalMiddleWare> _logger;
        private readonly RequestDelegate _next;
        public TokenRenewalMiddleWare(
         IConfiguration configuration,
         IHttpContextAccessor httpContextAccessor,
         ILogger<TokenRenewalMiddleWare> logger,
         RequestDelegate next
        )
        {
            _configuration = configuration;
            _httpContextAccessor = httpContextAccessor;
            _logger = logger;
            _logger = logger;
            _next = next;
        }
        public async Task InvokeAsync(HttpContext context,IServiceProvider serviceProvider)
        {
            if(context.Request.Cookies.TryGetValue("accessToken",out var token))
            {
                var accessTokenHandler = new JwtSecurityTokenHandler();
                try
                {
                    var accessToken = accessTokenHandler.ReadJwtToken(token);
                    //if token is expired try to get new token
                    if(accessToken.ValidTo< DateTime.UtcNow)
                    {
                        _logger.LogInformation("Access Token expired, trying to get new one");
                        if(context.Request.Cookies.TryGetValue("refreshToken", out var refreshToken))
                        {
                            var refreshTokenHandler = new JwtSecurityTokenHandler();
                            var refToken =refreshTokenHandler.ReadJwtToken(refreshToken);
                            if(refToken.ValidTo > DateTime.UtcNow)
                            {
                                // _logger.LogInformation("Refreshtoken is not expired");
                                var emailClaim = refToken?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
                                if(!string.IsNullOrEmpty(emailClaim))
                                {
                                    _logger.LogInformation("Refresh token is valid. Generating new tokens.");
                                    using(var scope = serviceProvider.CreateScope())
                                    {
                                        var dbContext = scope.ServiceProvider.GetRequiredService<JWTContext>();

                                        //query to the database
                                        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
                                        var getUser = await userManager.FindByEmailAsync(emailClaim);
                                        if(getUser != null)
                                        {
                                            var getRoles = await userManager.GetRolesAsync(getUser);
                                            var userSession = new UserSession(getUser.Id,getUser.UserName,getUser.Email!,getRoles.First());

                                            var newAccessToken = GenerateAccessToken(userSession);
                                            SetTokenCookie("accessToken",newAccessToken,TimeSpan.FromMinutes(1.5));
                                        }
                                        else
                                        {
                                            _logger.LogInformation("User not found");
                                        }
                                    }
                                }
                            }
                            else
                            {
                                _logger.LogInformation("Refresh Token expired");
                            }
                        }
                        else
                        {
                            _logger.LogInformation("Could not found refresh token cookie");
                        }
                    }
                }
                catch(Exception ex)
                {
                    _logger.LogError($"Token renewal failed: {ex.Message}");
                }
            }
            await _next(context);
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
        private void SetTokenCookie(string key, string token, TimeSpan timeSpan)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.Add(timeSpan)
            };
            _httpContextAccessor.HttpContext.Response.Cookies.Append(key, token, cookieOptions);
        }
    }
}