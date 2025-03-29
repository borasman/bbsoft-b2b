using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using bbSoft_B2B.Domain.Entities;
using bbSoft_B2B.Shared.Authorization;

namespace bbSoft_B2B.WebUI.Server.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password))
            {
                return Unauthorized(new AuthResult { Successful = false, Errors = new List<string> { "Invalid credentials." } });
            }

            if (!user.IsActive)
            {
                return Unauthorized(new AuthResult { Successful = false, Errors = new List<string> { "User account is inactive." } });
            }

            // --- 2FA Kontrolü ---
            if (user.TwoFactorEnabled)
            {
                // Şifre doğru ama 2FA gerekli. Henüz token oluşturma.
                // Client'a 2FA gerektiğini ve doğrulamak için UserId'yi bildir.
                return Ok(new AuthResult
                {
                    Successful = true, // Şifre kısmı başarılı
                    RequiresTwoFactor = true,
                    UserId = user.Id
                });
            }
            // --- 2FA Gerekmiyorsa veya Kapalıysa ---

            // JWT Token Oluşturma
            var authResponse = await GenerateJwtToken(user);

            // Başarılı login ve token döndür
            return Ok(new AuthResult
            {
                Successful = true,
                RequiresTwoFactor = false, // 2FA gerekmedi
                AuthResponse = authResponse
            });
        }

        [HttpPost("verify-2fa")]
        public async Task<IActionResult> VerifyTwoFactorToken([FromBody] Verify2faRequest request)
        {
            if (!ModelState.IsValid)
            {
                // ModelState hatalarını içeren bir AuthResult döndürebiliriz
                var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage);
                return BadRequest(new AuthResult { Successful = false, Errors = errors });
            }

            var user = await _userManager.FindByIdAsync(request.UserId);
            if (user == null)
            {
                // UserId geçerli değilse veya kullanıcı bulunamazsa
                return BadRequest(new AuthResult { Successful = false, Errors = new List<string> { "Invalid user identifier." }});
            }

            // Identity kütüphanesindeki token sağlayıcısının adını kullanıyoruz
            var provider = TokenOptions.DefaultAuthenticatorProvider; // Veya direkt "Authenticator" string'i

            // Gönderilen kodu doğrula
            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, provider, request.Code);

            if (isValid)
            {
                // Kod doğru! JWT Token oluştur ve döndür.
                var authResponse = await GenerateJwtToken(user);
                return Ok(new AuthResult
                {
                    Successful = true,
                    RequiresTwoFactor = false, // 2FA adımı tamamlandı
                    AuthResponse = authResponse
                });
            }
            else
            {
                // Kod yanlış
                return BadRequest(new AuthResult { Successful = false, Errors = new List<string> { "Invalid authenticator code." }});
            }
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationUser
            {
                UserName = request.Email,
                Email = request.Email,
                FirstName = request.FirstName,
                LastName = request.LastName,
                PhoneNumber = request.PhoneNumber,
                IsActive = true, // Default olarak aktif yapıyoruz
                CreatedOn = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user, request.Password);

            if (!result.Succeeded)
            {
                return BadRequest(new AuthResult
                {
                    Successful = false,
                    Errors = result.Errors.Select(e => e.Description)
                });
            }

            // Kullanıcıya default "Customer" rolünü ata
            await _userManager.AddToRoleAsync(user, "Customer");

            // Kayıt başarılı, login olmadan önce kaydın onaylanması gerekiyorsa burada ekstra adımlar eklenebilir
            return Ok(new AuthResult
            {
                Successful = true
            });
        }

        [Authorize]
        [HttpGet("profile")]
        public async Task<IActionResult> GetProfile()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            var userRoles = await _userManager.GetRolesAsync(user);

            var userProfile = new UserProfileResponse
            {
                UserId = user.Id,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                PhoneNumber = user.PhoneNumber,
                Roles = userRoles.ToList()
            };

            return Ok(userProfile);
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return Ok();
        }

        private async Task<AuthResponse> GenerateJwtToken(ApplicationUser user)
        {
            var userRoles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.Email),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("FirstName", user.FirstName ?? string.Empty),
                new Claim("LastName", user.LastName ?? string.Empty),
            };

            foreach (var role in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSecurityKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expiry = DateTime.Now.AddDays(Convert.ToInt32(_configuration["JwtExpiryInDays"]));

            var token = new JwtSecurityToken(
                _configuration["JwtIssuer"],
                _configuration["JwtAudience"],
                claims,
                expires: expiry,
                signingCredentials: creds
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            return new AuthResponse
            {
                Token = tokenString,
                ExpiryDate = expiry
            };
        }
    }

    public class LoginRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string Password { get; set; } = string.Empty;
    }

    public class RegisterRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [StringLength(100, MinimumLength = 6)]
        public string Password { get; set; } = string.Empty;

        [Required]
        [Compare("Password")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        public string LastName { get; set; } = string.Empty;

        public string PhoneNumber { get; set; } = string.Empty;
    }

    public class UserProfileResponse
    {
        public string UserId { get; set; } = string.Empty;
        public string? Email { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? PhoneNumber { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
    }

    public class Verify2faRequest
    {
        [Required]
        public string UserId { get; set; } = string.Empty;

        [Required]
        [StringLength(7, MinimumLength = 6)] // TOTP kodları genellikle 6 hanelidir
        public string Code { get; set; } = string.Empty;
    }
}