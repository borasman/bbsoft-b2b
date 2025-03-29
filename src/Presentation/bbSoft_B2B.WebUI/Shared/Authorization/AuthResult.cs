using System.Collections.Generic;

namespace bbSoft_B2B.Shared.Authorization;

public class AuthResult
{
    public bool Successful { get; set; }
    public IEnumerable<string>? Errors { get; set; }

    // Login başarılı ama 2FA bekleniyorsa true olacak
    public bool RequiresTwoFactor { get; set; } = false;

    // 2FA gerekiyorsa, 2FA kodunu doğrulamak için UserId'ye ihtiyacımız olacak
    public string? UserId { get; set; }

    // 2FA da başarılıysa veya gerekmiyorsa token burada olacak
    public AuthResponse? AuthResponse { get; set; }
}