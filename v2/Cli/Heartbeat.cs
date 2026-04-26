namespace FractionsOfACent;

/// <summary>
/// Transient stderr spinner — draws "[label]." → ".." → "..." on the
/// current line via \r so the user can see the scanner is alive between
/// the structured log lines (which can be tens of seconds apart while
/// fetching files). WriteLine takes the same lock, clears the spinner,
/// emits the line, and the next tick redraws.
///
/// Disabled automatically when stderr is redirected (file/pipe) so
/// captured logs don't fill with carriage returns.
/// </summary>
public sealed class Heartbeat : IDisposable
{
    private static readonly object _lock = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _task;
    private readonly bool _enabled;
    private string _label;
    private int _phase;
    private int _drawnWidth;

    public Heartbeat(string label)
    {
        _label = label;
        _enabled = !Console.IsErrorRedirected;
        _task = _enabled ? Task.Run(LoopAsync) : Task.CompletedTask;
    }

    public string Label
    {
        get => _label;
        set
        {
            lock (_lock)
            {
                ClearLineLocked();
                _label = value;
            }
        }
    }

    public void WriteLine(string line)
    {
        lock (_lock)
        {
            ClearLineLocked();
            Console.Error.WriteLine(line);
        }
    }

    private void ClearLineLocked()
    {
        if (!_enabled || _drawnWidth == 0) return;
        Console.Error.Write('\r');
        Console.Error.Write(new string(' ', _drawnWidth));
        Console.Error.Write('\r');
        _drawnWidth = 0;
    }

    private async Task LoopAsync()
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                lock (_lock)
                {
                    var dots = new string('.', _phase + 1);
                    var pad = new string(' ', 3 - _phase);
                    var s = $"[{_label}]{dots}{pad}";
                    Console.Error.Write('\r');
                    Console.Error.Write(s);
                    _drawnWidth = s.Length;
                    _phase = (_phase + 1) % 3;
                }
                await Task.Delay(400, _cts.Token);
            }
        }
        catch (OperationCanceledException) { }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _task.Wait(); } catch { }
        lock (_lock) { ClearLineLocked(); }
        _cts.Dispose();
    }
}
