using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using bbSoft_B2B.Shared.Authorization;

namespace bbSoft_B2B.WebUI.Client.Services.Auth;

public class AuthService : IAuthService
{
    private readonly HttpClient _httpClient;
    private readonly AuthenticationStateProvider _authStateProvider;
    private readonly ILocalStorageService _localStorage;

    public AuthService(
        HttpClient httpClient,
        AuthenticationStateProvider authStateProvider,
        ILocalStorageService localStorage)
    {
        _httpClient = httpClient;
        _authStateProvider = authStateProvider;
        _localStorage = localStorage;
    }

    public async Task<AuthResult> Login(LoginRequest loginModel)
    {
        var response = await _httpClient.PostAsJsonAsync("api/auth/login", loginModel);
        var result = await response.Content.ReadFromJsonAsync<AuthResult>();

        if (result == null)
        {
            return new AuthResult { Successful = false, Errors = new[] { "Unknown error occurred" } };
        }

        if (result.Successful && !result.RequiresTwoFactor)
        {
            // Normal başarılı giriş (2FA gerekmez)
            if (result.AuthResponse != null)
            {
                await _localStorage.SetItemAsync("authToken", result.AuthResponse.Token);
                await _localStorage.SetItemAsync("authTokenExpiry", result.AuthResponse.ExpiryDate);
                ((CustomAuthStateProvider)_authStateProvider).NotifyAuthenticationStateChanged();
            }
        }

        // Sonucu olduğu gibi döndür (2FA gerekirse, RequiresTwoFactor=true olacak)
        return result;
    }

    public async Task<AuthResult> Verify2faCode(string userId, string code)
    {
        var request = new Verify2faRequest
        {
            UserId = userId,
            Code = code
        };

        var response = await _httpClient.PostAsJsonAsync("api/auth/verify-2fa", request);
        var result = await response.Content.ReadFromJsonAsync<AuthResult>();

        if (result == null)
        {
            return new AuthResult { Successful = false, Errors = new[] { "Unknown error occurred" } };
        }

        if (result.Successful && result.AuthResponse != null)
        {
            // 2FA doğrulama başarılı, token'ı kaydet
            await _localStorage.SetItemAsync("authToken", result.AuthResponse.Token);
            await _localStorage.SetItemAsync("authTokenExpiry", result.AuthResponse.ExpiryDate);
            ((CustomAuthStateProvider)_authStateProvider).NotifyAuthenticationStateChanged();
        }

        return result;
    }

    public async Task<AuthResult> Register(RegisterRequest registerModel)
    {
        var response = await _httpClient.PostAsJsonAsync("api/auth/register", registerModel);
        var result = await response.Content.ReadFromJsonAsync<AuthResult>();

        return result ?? new AuthResult { Successful = false, Errors = new[] { "Unknown error occurred" } };
    }

    public async Task<bool> Logout()
    {
        try
        {
            // API'ye logout isteği gönder (token blacklisting, audit log vb. için)
            await _httpClient.PostAsync("api/auth/logout", null);
        }
        catch
        {
            // API'ye bağlanılamazsa bile local storage'ı temizle
        }

        await _localStorage.RemoveItemAsync("authToken");
        await _localStorage.RemoveItemAsync("authTokenExpiry");
        ((CustomAuthStateProvider)_authStateProvider).NotifyAuthenticationStateChanged();

        return true;
    }

    public async Task<UserProfileResponse?> GetUserProfile()
    {
        try
        {
            var response = await _httpClient.GetAsync("api/auth/profile");
            
            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadFromJsonAsync<UserProfileResponse>();
            }
            
            return null;
        }
        catch
        {
            return null;
        }
    }

    public async Task<bool> CheckAuthStatus()
    {
        var authState = await _authStateProvider.GetAuthenticationStateAsync();
        return authState.User.Identity?.IsAuthenticated ?? false;
    }
}