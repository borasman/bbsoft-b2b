# bbSoft B2B

B2B e-commerce application built with Blazor WebAssembly and .NET 8

## Authentication Implementation with Two-Factor Authentication (2FA)

This repository demonstrates a complete implementation of JWT-based authentication with Two-Factor Authentication (TOTP) support using ASP.NET Core Identity and Blazor WebAssembly.

### Key Features

1. JWT-based authentication
2. Role-based authorization
3. Two-Factor Authentication using Authenticator Apps (TOTP)
4. Secure token storage with expiration management

### Server-Side Implementation

- **AuthController**: Provides endpoints for login, registration, and 2FA verification
- **Token Generation**: Uses JWT tokens for secure authentication 
- **2FA Verification**: Verifies codes from authenticator apps

### Client-Side Implementation

- **AuthService**: Manages authentication state and communicates with server
- **CustomAuthStateProvider**: Handles JWT parsing and authentication state
- **Login.razor**: Supports both standard login and redirects to 2FA when needed
- **TwoFactorAuth.razor**: Dedicated page for 2FA code verification

### Usage Flow

1. User enters credentials
2. If 2FA is enabled for the account, user is redirected to the 2FA page
3. After successful 2FA code verification, a JWT token is issued
4. The token is stored in local storage and used for authorization

### Setup Instructions

1. Configure server-side Identity with JWT token support
2. Set up client-side authentication state providers
3. Implement login, register, and 2FA UI components
4. Connect components using the auth service

## License

MIT