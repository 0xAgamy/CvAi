using System.Security.Claims;
using CvAi.Application.Abstractions.Authentication;
using CvAi.Application.Common.Models;
using CvAi.Application.DTOs.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CvAi.API.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthenticationController : ControllerBase
{
    private readonly IAuthenticationService _authenticationService;

    public AuthenticationController(
        IAuthenticationService authenticationService)
    {
        _authenticationService = authenticationService;
    }


    [HttpPost("register")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register(
        [FromBody] RegisterRequestDto request,
        CancellationToken cancellationToken)
    {
        var result = await _authenticationService.RegisterAsync(
            request,
            cancellationToken);

        return result.Success
            ? Ok(result)
            : BadRequest(result);
    }


    [HttpPost("login")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login(
        [FromBody] LoginRequestDto request,
        CancellationToken cancellationToken)
    {
        var result = await _authenticationService.LoginAsync(
            request,
            cancellationToken);

        return result.Success
            ? Ok(result)
            : Unauthorized(result);
    }


    [HttpPost("refresh-token")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> RefreshToken(
        [FromBody] RefreshTokenRequestDto request,
        CancellationToken cancellationToken)
    {
        var result = await _authenticationService.RefreshAccessTokenAsync(
            request,
            cancellationToken);

        return result.Success
            ? Ok(result)
            : Unauthorized(result);
    }

  
    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Logout(
        [FromBody] LogoutRequestDto request,
        CancellationToken cancellationToken)
    {
        var result = await _authenticationService.LogoutAsync(
            request,
            cancellationToken);

        return result.Success
            ? Ok(result)
            : BadRequest(result);
    }


    [HttpPost("logout-all")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> LogoutAll(
        CancellationToken cancellationToken)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (string.IsNullOrWhiteSpace(userId))
        {
            return Unauthorized(ApiResponse.Fail(
                "Authenticated user ID is required."));
        }

        var result = await _authenticationService.RevokeAllSessionsAsync(
            userId,
            cancellationToken);

        return result.Success
            ? Ok(result)
            : Unauthorized(result);
    }


    [HttpPost("send-otp")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> SendOtp(
        [FromBody] SendOtpRequestDto request,
        CancellationToken cancellationToken)
    {
        var result = await _authenticationService.SendOtpAsync(
            request,
            cancellationToken);

        return result.Success
            ? Ok(result)
            : BadRequest(result);
    }


    [HttpPost("resend-otp")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ResendOtp(
        [FromBody] ResendEmailOtpRequestDto request,
        CancellationToken cancellationToken)
    {
        var result = await _authenticationService.ResendOtpAsync(
            request,
            cancellationToken);

        return result.Success
            ? Ok(result)
            : BadRequest(result);
    }

  
    [HttpPost("verify-email")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> VerifyEmail(
        [FromBody] VerifyEmailOtpRequestDto request,
        CancellationToken cancellationToken)
    {
        var result = await _authenticationService.VerifyEmailAsync(
            request,
            cancellationToken);

        return result.Success
            ? Ok(result)
            : BadRequest(result);
    }
}