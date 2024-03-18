using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CustomAuthenticationHandler.Controllers;

[ApiController]
[Authorize]
[Route("api/customers")]
public class CustomerController: ControllerBase
{
    [HttpGet]
    public IActionResult GetCustomer()
    {
        return Ok(new { CustomerId = 1, CustomerName = "Tst" });
    }
}