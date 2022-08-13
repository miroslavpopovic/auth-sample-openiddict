namespace Auth.Models;

public class DeviceAuthorizationInputModel : ConsentInputModel
{
    public string? UserCode { get; set; }
}
