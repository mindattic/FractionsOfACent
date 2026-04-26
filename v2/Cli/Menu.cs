namespace FractionsOfACent;

/// <summary>
/// Interactive single-key TUI for the CLI. Background scan loop is owned
/// by Program; this just reads keys and translates to ScannerControl
/// writes (or local cancellation for quit). Mirrors the Blazor Settings
/// tab buttons — both surfaces converge on the same DB row.
/// </summary>
public static class Menu
{
    public static async Task RunAsync(Db db, CancellationTokenSource cts)
    {
        Console.Error.WriteLine();
        Console.Error.WriteLine("  Commands:  [p]ause   [r]esume   [s]tatus   [q]uit");
        Console.Error.WriteLine();

        while (!cts.IsCancellationRequested)
        {
            ConsoleKeyInfo key;
            try
            {
                if (!Console.KeyAvailable)
                {
                    await Task.Delay(150, cts.Token);
                    continue;
                }
                key = Console.ReadKey(intercept: true);
            }
            catch (OperationCanceledException) { break; }
            catch (InvalidOperationException)
            {
                // stdin redirected — no menu possible. Just idle until cts fires.
                try { await Task.Delay(Timeout.Infinite, cts.Token); }
                catch (OperationCanceledException) { }
                break;
            }

            switch (char.ToLowerInvariant(key.KeyChar))
            {
                case 'p':
                    db.SetScannerRequestedState("paused");
                    Console.Error.WriteLine("[menu] requested: paused");
                    break;
                case 'r':
                    db.SetScannerRequestedState("running");
                    Console.Error.WriteLine("[menu] requested: running");
                    break;
                case 's':
                    PrintStatus(db);
                    break;
                case 'q':
                    Console.Error.WriteLine("[menu] quitting — finishing current step then exiting");
                    cts.Cancel();
                    return;
            }
        }
    }

    public static void PrintStatus(Db db)
    {
        var ctrl = db.GetScannerControl();
        var (findings, scanned) = db.Stats();
        var age = ctrl.LastHeartbeatUtc is null
            ? "never"
            : $"{(DateTime.UtcNow - ctrl.LastHeartbeatUtc.Value).TotalSeconds:F0}s ago";
        Console.Error.WriteLine(
            $"[status] state={ctrl.RequestedState} label='{ctrl.CurrentLabel ?? "—"}' " +
            $"heartbeat={age} findings={findings} scanned={scanned}");
    }
}
