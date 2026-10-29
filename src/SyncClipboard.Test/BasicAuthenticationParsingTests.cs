using System.Text;
using SyncClipboard.Server.Core;

namespace SyncClipboard.Test;

[TestClass]
public class BasicAuthenticationParsingTests
{
    [TestMethod]
    [DataRow("user", "pass:segment", "Basic")]
    [DataRow("用戶", "密码:段", "bAsIc")]
    [DataRow("user", "", "BASIC")]
    public void TryParseCredentials_ParsesValidBasicCredentials(string username, string password, string scheme)
    {
        var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));

        var parsed = BasicAuthenticationHandler.TryParseCredentials($"{scheme} {token}", out var actualUsername, out var actualPassword);

        Assert.IsTrue(parsed);
        Assert.AreEqual(username, actualUsername);
        Assert.AreEqual(password, actualPassword);
    }

    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("Basic")]
    [DataRow("Basic ")]
    [DataRow("Basic !!!")]
    [DataRow("Basic dXNlcnBhc3M=")]
    [DataRow("Bearer dXNlcjpwYXNz")]
    [DataRow("Basic /w==")]
    public void TryParseCredentials_RejectsMalformedOrNonBasicHeaders(string? header)
    {
        var parsed = BasicAuthenticationHandler.TryParseCredentials(header, out _, out _);

        Assert.IsFalse(parsed);
    }
}
