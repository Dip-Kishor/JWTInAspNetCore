using JWTInAspNetCore.Services;
using JWTInAspNetCore.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotnetApi.Controllers
{
    [AllowAnonymous]
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        public UserController(IUserService userService)
        {
            _userService = userService;
        }
        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterModel register)
        {
            var response = await _userService.CreateAccount(register);
            return Ok(response);
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginModel login)
        {
            var response = await _userService.Login(login);
            return Ok(response);
        }
        [HttpPost("logout")]
        [Authorize]
        public IActionResult Logout()
        {
            _userService.Logout();
            return Ok(new { message = "Logged out successfully" });
            
        }
        // [AllowAnonymous]
        // [HttpPost("refreshtoken")]
        // public async Task<IActionResult> RefreshToken(RefreshModel model)
        // {
        //     var response = await _userService.RefreshToken(model);

        //     if (response.Flag)
        //     {
        //         return Ok(response);
        //     }
        //     else
        //     {
        //         return BadRequest(response.Message);
        //     }
        // }


    }
}