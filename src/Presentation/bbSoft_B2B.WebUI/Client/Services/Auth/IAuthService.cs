using bbSoft_B2B.Shared.Authorization;

namespace bbSoft_B2B.WebUI.Client.Services.Auth;

public interface IAuthService
{
    Task<AuthResult> Login(LoginRequest loginModel);
    Task<AuthResult> Register(RegisterRequest registerModel);
    Task<bool> Logout();
    Task<UserProfileResponse?> GetUserProfile();
    Task<bool> CheckAuthStatus();
    Task<AuthResult> Verify2faCode(string userId, string code);
}

// Bu class'lar Shared projeye taşınabilir
public class LoginRequest
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class RegisterRequest
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string ConfirmPassword { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
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
    public string UserId { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
}