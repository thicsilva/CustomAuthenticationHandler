namespace CustomAuthenticationHandler;

public static class StringHelpers
{
    public static T ParseValueOrDefault<T>(string? value, Func<string, T> parser, T defaultValue)
    {
        try
        {
            return parser.Invoke(value!);
        }
        catch
        {
            return defaultValue;
        }
    }
}