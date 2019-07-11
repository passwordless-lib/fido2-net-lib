/*
Written by Peter O. in 2014-2018.
Any copyright is dedicated to the Public Domain.
http://creativecommons.org/publicdomain/zero/1.0/
If you like this, you should donate to Peter O.
at: http://peteroupc.github.io/
 */
 #if DEBUG
using System;
using System.Reflection;

namespace PeterO {
  internal static class DebugUtility {
    private static MethodInfo GetTypeMethod(
      Type t,
      string name,
      Type[] parameters) {
#if NET40 || NET20
      return t.GetMethod(name, parameters);
#else
{
        return t?.GetRuntimeMethod(name, parameters);
}
#endif
    }

    public static void Log(string str) {
      Type type = Type.GetType("System.Console");
      var types = new[] { typeof(string) };
      var typeMethod = GetTypeMethod(type, "WriteLine", types);
      if (typeMethod != null)typeMethod.Invoke(
        type,
        new object[] { str });
    }

    public static void Log(string format, params object[] args) {
      Log(String.Format(format, args));
    }
  }
}
#endif
