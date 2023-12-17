using System;

public static class DebugUtility
{
    public static bool IsDebugEnabled { get; set; } = false;

    public static void DebugPrint(string message)
    {
        if (IsDebugEnabled)
        {
            Console.WriteLine($" [DEBUG] {message}");
        }
    }
}
