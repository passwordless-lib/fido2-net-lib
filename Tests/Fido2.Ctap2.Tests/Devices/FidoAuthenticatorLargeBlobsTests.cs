using System.Security.Cryptography;

using Fido2NetLib.Cbor;

namespace Fido2NetLib.Ctap2.Tests;

public class FidoAuthenticatorLargeBlobsTests
{
    private sealed class ReadOnlyAuthenticator(byte[] storedData) : FidoAuthenticator
    {
        public List<AuthenticatorLargeBlobsCommand> Commands { get; } = [];

        protected override ValueTask<FidoAuthenticatorResponse> ExecuteCommandAsync(CtapCommand command)
        {
            var getCommand = Assert.IsType<AuthenticatorLargeBlobsCommand>(command);
            Commands.Add(getCommand);

            int offset = (int)getCommand.Offset;
            int available = Math.Max(0, storedData.Length - offset);
            int take = Math.Min(available, getCommand.Get!.Value);

            var config = storedData.AsSpan(offset, take).ToArray();

            var payload = new CborMap { { 0x01, config } }.Encode();

            var message = new byte[1 + payload.Length];
            message[0] = (byte)CtapStatusCode.OK;
            payload.CopyTo(message.AsSpan(1));

            return ValueTask.FromResult(new FidoAuthenticatorResponse(message));
        }
    }

    private sealed class WriteRecordingAuthenticator : FidoAuthenticator
    {
        public List<AuthenticatorLargeBlobsCommand> Commands { get; } = [];

        protected override ValueTask<FidoAuthenticatorResponse> ExecuteCommandAsync(CtapCommand command)
        {
            Commands.Add(Assert.IsType<AuthenticatorLargeBlobsCommand>(command));

            return ValueTask.FromResult(new FidoAuthenticatorResponse(CtapStatusCode.OK));
        }
    }

    [Fact]
    public async Task ReadLargeBlobArrayAsync_ReassemblesMultipleFragments()
    {
        var storedData = RandomNumberGenerator.GetBytes(25);
        var authenticator = new ReadOnlyAuthenticator(storedData);

        var result = await authenticator.ReadLargeBlobArrayAsync(maxFragmentLength: 10);

        Assert.Equal(storedData, result);
        // 10 + 10 + 5 (last fragment shorter than maxFragmentLength ends the loop)
        Assert.Equal(3, authenticator.Commands.Count);
        Assert.Equal(0u, authenticator.Commands[0].Offset);
        Assert.Equal(10u, authenticator.Commands[1].Offset);
        Assert.Equal(20u, authenticator.Commands[2].Offset);
    }

    [Fact]
    public async Task ReadLargeBlobArrayAsync_ExactMultipleOfFragmentLength_IssuesTrailingEmptyRead()
    {
        var storedData = RandomNumberGenerator.GetBytes(20);
        var authenticator = new ReadOnlyAuthenticator(storedData);

        var result = await authenticator.ReadLargeBlobArrayAsync(maxFragmentLength: 10);

        Assert.Equal(storedData, result);
        Assert.Equal(3, authenticator.Commands.Count); // 10, 10, then a 0-length fragment to confirm completion
    }

    [Fact]
    public async Task ReadLargeBlobArrayAsync_DataExactlyOneFragmentLong_StopsAfterSingleRead()
    {
        var storedData = RandomNumberGenerator.GetBytes(10);
        var authenticator = new ReadOnlyAuthenticator(storedData);

        var result = await authenticator.ReadLargeBlobArrayAsync(maxFragmentLength: 10);

        Assert.Equal(storedData, result);
        // A full-length fragment that happens to be the entirety of the data still can't be
        // distinguished from "there might be more" without one further (empty) read.
        Assert.Equal(2, authenticator.Commands.Count);
    }

    private sealed class StatefulAuthenticator : FidoAuthenticator
    {
        private byte[] _stored = [];

        protected override ValueTask<FidoAuthenticatorResponse> ExecuteCommandAsync(CtapCommand command)
        {
            var largeBlobsCommand = Assert.IsType<AuthenticatorLargeBlobsCommand>(command);

            if (largeBlobsCommand.Set is { } set)
            {
                int offset = (int)largeBlobsCommand.Offset;

                if (offset == 0)
                {
                    _stored = new byte[largeBlobsCommand.Length!.Value];
                }

                set.CopyTo(_stored, offset);

                return ValueTask.FromResult(new FidoAuthenticatorResponse(CtapStatusCode.OK));
            }
            else
            {
                int offset = (int)largeBlobsCommand.Offset;
                int available = Math.Max(0, _stored.Length - offset);
                int take = Math.Min(available, largeBlobsCommand.Get!.Value);

                var config = _stored.AsSpan(offset, take).ToArray();
                var payload = new CborMap { { 0x01, config } }.Encode();

                var message = new byte[1 + payload.Length];
                message[0] = (byte)CtapStatusCode.OK;
                payload.CopyTo(message.AsSpan(1));

                return ValueTask.FromResult(new FidoAuthenticatorResponse(message));
            }
        }
    }

    [Fact]
    public async Task WriteThenReadLargeBlobArrayAsync_RoundTripsAcrossFragmentBoundaries()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var entries = new[]
        {
            LargeBlobArray.Encrypt(key, "first entry payload"u8),
            LargeBlobArray.Encrypt(key, "a second, somewhat longer entry payload to force multiple fragments"u8),
        };
        var serialized = LargeBlobArray.Encode(entries);

        var authenticator = new StatefulAuthenticator();

        // A fragment size much smaller than the serialized array forces several fragments in both
        // the write (split) and read (reassembly) directions, including a boundary that doesn't
        // align with either entry.
        await authenticator.WriteLargeBlobArrayAsync(serialized, maxFragmentLength: 24);
        var roundTripped = await authenticator.ReadLargeBlobArrayAsync(maxFragmentLength: 24);

        Assert.Equal(serialized, roundTripped);

        var success = LargeBlobArray.TryDecode(roundTripped, out var decodedEntries);
        Assert.True(success);
        Assert.Equal(2, decodedEntries.Count);
        Assert.Equal(entries[0].Ciphertext, decodedEntries[0].Ciphertext);
        Assert.Equal(entries[1].Ciphertext, decodedEntries[1].Ciphertext);
    }

    [Fact]
    public async Task WriteLargeBlobArrayAsync_DataExactlyOneFragmentLong_SendsSingleFragment()
    {
        var data = RandomNumberGenerator.GetBytes(10);
        var authenticator = new WriteRecordingAuthenticator();

        await authenticator.WriteLargeBlobArrayAsync(data, maxFragmentLength: 10);

        var command = Assert.Single(authenticator.Commands);
        Assert.Equal(0u, command.Offset);
        Assert.Equal(10, command.Length);
        Assert.Equal(data, command.Set);
    }

    [Fact]
    public async Task WriteLargeBlobArrayAsync_SplitsIntoFragmentsWithCorrectOffsetsAndLength()
    {
        var data = RandomNumberGenerator.GetBytes(25);
        var authenticator = new WriteRecordingAuthenticator();

        await authenticator.WriteLargeBlobArrayAsync(data, maxFragmentLength: 10);

        Assert.Equal(3, authenticator.Commands.Count);

        Assert.Equal(0u, authenticator.Commands[0].Offset);
        Assert.Equal(25, authenticator.Commands[0].Length);
        Assert.Equal(data[..10], authenticator.Commands[0].Set);

        Assert.Equal(10u, authenticator.Commands[1].Offset);
        Assert.Null(authenticator.Commands[1].Length);
        Assert.Equal(data[10..20], authenticator.Commands[1].Set);

        Assert.Equal(20u, authenticator.Commands[2].Offset);
        Assert.Equal(data[20..25], authenticator.Commands[2].Set);
    }

    [Fact]
    public async Task WriteLargeBlobArrayAsync_WithPinUvAuthToken_ComputesExpectedAuthParamPerFragment()
    {
        var data = RandomNumberGenerator.GetBytes(15);
        var authenticator = new WriteRecordingAuthenticator();
        var pinUvAuthToken = Convert.FromHexString("00112233445566778899aabbccddeeff");

        await authenticator.WriteLargeBlobArrayAsync(data, pinUvAuthToken, maxFragmentLength: 10);

        Assert.Equal(2, authenticator.Commands.Count);

        foreach (var command in authenticator.Commands)
        {
            var expected = ExpectedPinUvAuthParam(pinUvAuthToken, command.Offset, command.Set!);

            Assert.Equal(expected, command.PinUvAuthParam);
            Assert.Equal(1u, command.PinUvAuthProtocol);
        }
    }

    private static byte[] ExpectedPinUvAuthParam(byte[] pinUvAuthToken, uint offset, byte[] set)
    {
        Span<byte> message = stackalloc byte[32 + 2 + 4 + 32];
        message[..32].Fill(0xff);
        message[32] = 0x0c;
        message[33] = 0x00;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(message.Slice(34, 4), offset);
        SHA256.HashData(set, message.Slice(38, 32));

        return HMACSHA256.HashData(pinUvAuthToken, message).AsSpan(0, 16).ToArray();
    }
}
