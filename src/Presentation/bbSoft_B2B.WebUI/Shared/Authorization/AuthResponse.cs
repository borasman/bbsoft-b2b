using System;

namespace bbSoft_B2B.Shared.Authorization;

public class AuthResponse
{
    public string Token { get; set; } = string.Empty;
    public DateTime ExpiryDate { get; set; }
}