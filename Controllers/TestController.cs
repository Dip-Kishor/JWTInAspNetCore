using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotnetApi.Controllers
{
    [ApiController]
    [Route("api/[Controller]")]
    public class TestController: ControllerBase
    {
        [AllowAnonymous]
        [HttpGet("test")]
        public IActionResult Test()
        {
            return Content("Unauthorized");
        }
        [Authorize(Roles ="Admin")]
        [HttpGet("TestAdmin")]
        public IActionResult TestAdmin()
        {
            return Content("Authorized Admin");
        }
        [Authorize(Roles ="Manager")]
        [HttpGet("TestManager")]
        public IActionResult TestManager()
        {
            return Content("Authorized Manager");
        }
        [Authorize(Roles ="User")]
        [HttpGet("TestUser")]
        public IActionResult TestUser()
        {
            return Content("Authorized User");
        }
         [Authorize(Roles ="Manager, Admin")]
        [HttpGet("TestBoth")]
        public IActionResult TestBoth()
        {
            return Content("Authorized Admin and Manager");
        }
    }
}