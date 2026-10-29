using System.Reflection;

namespace SessionContractExperiment;

// IMsTscAdvancedSettings::allowBackgroundInput is LONG, not VARIANT_BOOL.
// Keep the getter for the same AdvancedSettings9 object configured before
// Connect. This borrowed managed reference does not acquire a new COM pointer.
internal sealed class BackgroundInputConfiguration
{
    private readonly Func<object?> read;
    private readonly Action<string, object?> record;
    private BackgroundInputConfiguration(Func<object?> read, Action<string, object?> record)
    { this.read = read; this.record = record; }

    internal static BackgroundInputConfiguration? Prepare(bool requested, Func<object?> read,
        Action<int> write, Action<string, object?> record)
    {
        // Ordinary modes do not read or write the optional property.
        if (!requested) return null;
        BackgroundInputConfiguration result = new(read, record);
        int initial = result.ReadLong("sendkeys_background_input_initial");
        try { write(1); }
        catch (Exception error) { throw Failure("sendkeys_background_input_set_failed", error); }
        int actual = result.ReadLong("sendkeys_background_input_readback");
        record("sendkeys_background_input_configuration", new { initial, requested = 1, readback = actual,
            before_connect = true, accepted = actual == 1 });
        if (actual != 1) throw new ExperimentFailure("sendkeys_background_input_not_enabled");
        return result;
    }

    internal void RequireEnabled()
    {
        int actual = ReadLong("sendkeys_background_input_presend");
        record("sendkeys_background_input_presend", new { requested = 1, readback = actual, accepted = actual == 1 });
        if (actual != 1) throw new ExperimentFailure("sendkeys_background_input_changed");
    }

    private int ReadLong(string stage)
    {
        object? value;
        try { value = read(); }
        catch (Exception error) { throw Failure(stage + "_failed", error); }
        // Convert.ToInt32 would accept BOOL, other widths and strings. Those
        // are different Automation contracts and must not pass this gate.
        if (value is not int actual) throw new ExperimentFailure(stage + "_type_mismatch", unchecked((int)0x80020005));
        return actual;
    }

    private static ExperimentFailure Failure(string stage, Exception error)
    {
        Exception original = error is TargetInvocationException { InnerException: Exception inner } ? inner : error;
        return new ExperimentFailure(stage, original.HResult);
    }
}
