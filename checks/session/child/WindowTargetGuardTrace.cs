namespace SessionContractExperiment;

// IDs match the existing basic guard's short-circuit evaluation order. The
// trace adds no window query and allocates nothing on the successful path.
internal enum WindowTargetPredicate
{
    None = 0, OwnerThread = 1, ParentAlive, HostAlive, ParentHandleCreated,
    HostHandleCreated, ParentHandleMatches, HostHandleMatches, InvokeNotRequired,
    HostInsideParent, ControlIsNotParent, ControlInsideHost, ParentVisible,
    ControlVisible, ControlEnabled, ParentNotIconic, ParentForeground
}

internal struct WindowTargetGuardTrace
{
    internal uint CheckedMask { get; private set; }
    internal WindowTargetPredicate FirstFailed { get; private set; }

    internal bool Failed(bool condition, WindowTargetPredicate predicate)
    {
        CheckedMask |= 1U << ((int)predicate - 1);
        if (condition) FirstFailed = predicate;
        return condition;
    }

    private readonly bool? Passed(WindowTargetPredicate predicate) =>
        (CheckedMask & (1U << ((int)predicate - 1))) != 0 ? FirstFailed != predicate : null;

    internal readonly void Record(Action<string, object?> record, int phase)
    {
        if (FirstFailed == WindowTargetPredicate.None) return;
        try
        {
            record("window_input_target_guard_failure", new
            {
                validation_phase_id = phase,
                first_failed_predicate = FirstFailed.ToString(),
                first_failed_predicate_id = (int)FirstFailed,
                checked_mask = CheckedMask,
                original_guard_code = 0,
                native_error_code_captured = false,
                observation_scope = "actual_short_circuit_basic_guard_no_additional_queries",
                operands = new
                {
                    owner_thread_matches = Passed(WindowTargetPredicate.OwnerThread),
                    parent_alive = Passed(WindowTargetPredicate.ParentAlive),
                    host_alive = Passed(WindowTargetPredicate.HostAlive),
                    parent_handle_created = Passed(WindowTargetPredicate.ParentHandleCreated),
                    host_handle_created = Passed(WindowTargetPredicate.HostHandleCreated),
                    parent_handle_matches = Passed(WindowTargetPredicate.ParentHandleMatches),
                    host_handle_matches = Passed(WindowTargetPredicate.HostHandleMatches),
                    invoke_not_required = Passed(WindowTargetPredicate.InvokeNotRequired),
                    host_inside_parent = Passed(WindowTargetPredicate.HostInsideParent),
                    control_is_not_parent = Passed(WindowTargetPredicate.ControlIsNotParent),
                    control_inside_host = Passed(WindowTargetPredicate.ControlInsideHost),
                    parent_visible = Passed(WindowTargetPredicate.ParentVisible),
                    control_visible = Passed(WindowTargetPredicate.ControlVisible),
                    control_enabled = Passed(WindowTargetPredicate.ControlEnabled),
                    parent_not_iconic = Passed(WindowTargetPredicate.ParentNotIconic),
                    parent_foreground_matches = Passed(WindowTargetPredicate.ParentForeground)
                },
                focus_observation = "not_reached",
                geometry_observation = "not_reached"
            });
        }
        catch { /* Preserve the original rejection even if diagnostics fail. */ }
    }
}
