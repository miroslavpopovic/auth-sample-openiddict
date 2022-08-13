namespace Auth.Email;

public class EmailOptions
{
    public string FromEmail { get; set; } = string.Empty;
    public string FromName { get; set; } = string.Empty;
    public SmtpOptions Smtp { get; set; } = new();
}

