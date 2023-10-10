using System;

namespace Fido2NetLib;

internal static class DateTimeUtilities
{
    /// <summary>
    /// Finds the nearest future point in time that aligns with the increment provided
    /// e.g. 12:58:23 -> 13:00 if the increment provided is 2 minutes
    /// </summary>
    /// <param name="startTime">The time from which to calculated the next increment</param>
    /// <param name="increment">The increment used to calculate the new time</param>
    /// <returns></returns>
    public static DateTimeOffset GetNextIncrement(this DateTimeOffset startTime, TimeSpan increment)
    {
        // Find next increment
        var nextIncrementTicks = (long)(Math.Ceiling((decimal)startTime.Ticks / (decimal)increment.Ticks) * (decimal)increment.Ticks);

        // Find the difference between the start time and the target time
        var timeSpanDiff = TimeSpan.FromTicks(nextIncrementTicks).Subtract(TimeSpan.FromTicks(startTime.Ticks));

        // If the calculated difference is 0 then make it the increment value
        if (timeSpanDiff.Ticks == 0)
            timeSpanDiff = TimeSpan.FromTicks(increment.Ticks);

        // Add the difference to the normalized time
        return startTime.Add(timeSpanDiff);
    }
}
