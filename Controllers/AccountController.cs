using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authorization;
using SafeVaultSecurity.Models;

namespace SafeVaultSecurity.Controllers
{
 [ApiController]
 [Route("[controller]")]
 public class AccountController : ControllerBase
 {
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
private readonly IConfiguration _configuration;

   public AccountController(
    UserManager<IdentityUser> userManager,
    SignInManager<IdentityUser> signInManager,
    IConfiguration configuration)
{
    _userManager = userManager;
    _signInManager = signInManager;
    _configuration = configuration;
}

[Authorize(Roles = "Admin")]
[HttpGet("admin-panel")]
public IActionResult AdminPanel()
{
    return Ok("Sadece Admin rolündeki kullanıcılar burayı görebilir.");
}

[HttpPost("register")]
public async Task<IActionResult> Register(UserRegisterModel model)
{
    if (!ModelState.IsValid) return BadRequest(ModelState);

    var user = new IdentityUser { UserName = model.Email, Email = model.Email };
    var result = await _userManager.CreateAsync(user, model.Password);

    if (result.Succeeded)
    {
        await _userManager.AddToRoleAsync(user, "User");
        return Ok(new { message = "Kayıt başarılı" });
    }

    foreach (var error in result.Errors)
        ModelState.AddModelError(string.Empty, error.Description);

    return BadRequest(ModelState);
}

[HttpPost("login")]
public async Task<IActionResult> Login(UserLoginModel model)
{
    if (!ModelState.IsValid) return BadRequest(ModelState);

    var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);

    if (result.Succeeded)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        var token = GenerateJwtToken(user);
        return Ok(new { token });
    }

    return Unauthorized(new { message = "Geçersiz giriş bilgisi" });
}

private string GenerateJwtToken(IdentityUser user)
{
    var jwtSettings = _configuration.GetSection("Jwt");
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: jwtSettings["Issuer"],
        audience: jwtSettings["Audience"],
        claims: new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.NameIdentifier, user.Id)
        },
        expires: DateTime.UtcNow.AddMinutes(double.Parse(jwtSettings["ExpireMinutes"])),
        signingCredentials: creds
    );

    return new JwtSecurityTokenHandler().WriteToken(token);
}

[Authorize]
[HttpGet("me")]
public IActionResult Me()
{
    return Ok(new
    {
        message = "Yetkilendirilmiş kullanıcı bilgisi",
        username = User.Identity?.Name
    });
}
}

   
}
