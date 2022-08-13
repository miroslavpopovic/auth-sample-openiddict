using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Samples.WeatherApi.JavaScriptBffClient.Controllers
{
    public class LocalApiController : ControllerBase
    {
        [Route("local/identity")]
        [Authorize]
        public IActionResult Get()
        {
            var name = User.FindFirst("name")?.Value ?? User.FindFirst("sub")?.Value;
            return new JsonResult(new { message = "Local API Success!", user = name });
        }
    }
}
